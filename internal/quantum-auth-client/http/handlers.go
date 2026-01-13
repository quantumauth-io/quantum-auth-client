package http

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/constants"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/contracts/bindings/go/entrypoint"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/contracts/bindings/go/quantumauthaccount"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/shared"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/utils"

	"github.com/quantumauth-io/quantum-go-utils/log"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{JSONKeyOK: true})
}

func (s *Server) handleAgentSessionValidate(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK:    true,
		JSONKeyValid: true,
	})
}

func (s *Server) handleAgentExtensionStatus(w http.ResponseWriter, r *http.Request) {
	paired := false
	if _, err := loadPairingToken(s.pairingTokenPath); err == nil {
		paired = true
	}
	writeJSON(w, http.StatusOK, map[string]any{JSONKeyPaired: paired})
}

func (s *Server) handleAgentExtensionPair(w http.ResponseWriter, r *http.Request) {
	token, err := newSessionToken()
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	if s.pairingTokenPath == "" {
		p, err := pairingTokenFilePath()
		if err != nil {
			http.Error(w, "failed to resolve pairing token path", http.StatusInternalServerError)
			return
		}
		s.pairingTokenPath = p
	}

	if err := writePairingTokenFile(s.pairingTokenPath, token); err != nil {
		http.Error(w, "failed to write pairing token", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, pairResp{
		OK:               true,
		PairingToken:     token,
		PairingTokenPath: s.pairingTokenPath,
	})
}

func (s *Server) handleAgentStatus(w http.ResponseWriter, r *http.Request) {
	out := agentStatusResponse{OK: true}
	if s.authClient != nil && s.authClient.State != nil {
		out.LoggedIn = true
		out.UserID = s.authClient.State.UserID
		out.DeviceID = s.authClient.State.DeviceID
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAgentSignRegister(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, signResp{Signature: AgentSignaturePlaceholderHex})
}

func (s *Server) handleAgentSignWithdraw(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, signResp{Signature: AgentSignaturePlaceholderHex})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleExtensionAuth(w http.ResponseWriter, r *http.Request) {
	var extReq extensionRequest
	if !decodeJSONBody(w, r, &extReq) {
		return
	}

	switch extReq.Action {
	case ExtensionActionPing:
		writeJSON(w, http.StatusOK, extensionResponse{
			OK: true,
			Data: map[string]string{
				ExtensionPingResponseMessageKey: ExtensionPingResponseMessageValue,
			},
		})

	case ExtensionActionRequestChallenge:
		s.handleRequestChallenge(w, r.Context(), extReq)

	default:
		writeJSON(w, http.StatusBadRequest, extensionResponse{
			OK:    false,
			Error: ExtensionUnknownActionError,
		})
	}
}

func (s *Server) handleRequestChallenge(w http.ResponseWriter, ctx context.Context, extReq extensionRequest) {
	if !requireAuthState(w, s) {
		return
	}

	var req qaChallengeRequest
	if len(extReq.Data) == 0 {
		writeJSON(w, http.StatusBadRequest, extensionResponse{OK: false, Error: "missing data"})
		return
	}
	if err := json.Unmarshal(extReq.Data, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	origin := normalizeOrigin(req.Origin)
	if origin == "" {
		writeJSON(w, http.StatusBadRequest, extensionResponse{OK: false, Error: "missing/invalid origin"})
		return
	}

	if s.perms == nil || !s.perms.IsAllowed(origin) {
		writeJSON(w, http.StatusOK, extensionResponse{
			OK:    false,
			Error: ExtensionApprovalRequiredError,
			Data: map[string]any{
				JSONKeyOrigin:  origin,
				JSONKeyAllowed: false,
			},
		})
		return
	}

	chID, err := s.qaClient.RequestChallenge(ctx, s.authClient.State.DeviceID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	signedHeaders, err := s.qaClient.SignRequest(
		req.Method,
		req.Path,
		req.BackendHost,
		s.authClient.State.UserID,
		s.authClient.State.DeviceID,
		chID,
		nil,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, extensionResponse{
		OK: true,
		Data: map[string]any{
			"qaProof":      signedHeaders,
			JSONKeyOrigin:  origin,
			JSONKeyAllowed: true,
		},
	})
}

func (s *Server) handleGetPermissions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, extensionResponse{
		OK: true,
		Data: map[string]any{
			JSONKeyAllowed: s.perms.List(),
		},
	})
}

func (s *Server) handleGetPermissionStatus(w http.ResponseWriter, r *http.Request) {
	origin := normalizeOrigin(r.URL.Query().Get(JSONKeyOrigin))
	if origin == "" {
		writeJSON(w, http.StatusBadRequest, extensionResponse{OK: false, Error: "missing/invalid origin"})
		return
	}

	writeJSON(w, http.StatusOK, extensionResponse{
		OK: true,
		Data: map[string]any{
			JSONKeyOrigin:  origin,
			JSONKeyAllowed: s.perms.IsAllowed(origin),
		},
	})
}

func (s *Server) handleSetPermission(w http.ResponseWriter, r *http.Request) {
	var req setPermissionRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}

	origin := normalizeOrigin(req.Origin)
	if origin == "" {
		writeJSON(w, http.StatusBadRequest, extensionResponse{OK: false, Error: "missing/invalid origin"})
		return
	}

	if err := s.perms.Set(origin, req.Allowed); err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, extensionResponse{
		OK: true,
		Data: map[string]any{
			JSONKeyOrigin:  origin,
			JSONKeyAllowed: req.Allowed,
		},
	})
}

func (s *Server) handleTokenPair(w http.ResponseWriter, r *http.Request) {
	var req pairExchangeReq
	if !decodeJSONBody(w, r, &req) {
		return
	}

	req.PairID = strings.TrimSpace(req.PairID)
	req.Code = strings.TrimSpace(req.Code)
	if req.PairID == "" || req.Code == "" {
		http.Error(w, PairingErrorMissingPairIDOrCodeText, http.StatusBadRequest)
		return
	}

	now := time.Now()

	s.pairingsMu.Lock()
	for id, p := range s.pairings {
		if p == nil || now.After(p.ExpiresAt) {
			delete(s.pairings, id)
		}
	}

	p, ok := s.pairings[req.PairID]
	if !ok || p == nil || p.Used || now.After(p.ExpiresAt) {
		s.pairingsMu.Unlock()
		http.Error(w, PairingErrorPairExpiredText, http.StatusGone)
		return
	}

	got := sha256.Sum256([]byte(req.Code))
	want := p.CodeHash
	if len(want) != PairingCodeSHA256SizeBytes || subtle.ConstantTimeCompare(want, got[:]) != 1 {
		s.pairingsMu.Unlock()
		http.Error(w, PairingErrorInvalidCodeText, http.StatusUnauthorized)
		return
	}

	p.Used = true
	token := p.Token
	s.pairingsMu.Unlock()

	writeJSON(w, http.StatusOK, pairExchangeResp{
		OK:     true,
		Token:  token,
		Header: agentSessionHeader,
	})
}

func (s *Server) handleWalletChainId(w http.ResponseWriter, r *http.Request) {
	if !requireEthClient(w, s) {
		return
	}

	activeChainClient, err := s.activeHTTP(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	chainId, err := activeChainClient.ChainID(s.ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	if chainId == nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: fmt.Sprintf("missing chain id")})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyChainIDHex: bigIntToHexQuantity(chainId),
	})
}

func (s *Server) handleTransactionReceipt(w http.ResponseWriter, r *http.Request) {
	if !requireEthClient(w, s) {
		return
	}

	activeChainClient, err := s.activeHTTP(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	var req txReceiptRequest
	if !decodeJSONBody(w, r, &req) {
		writeJSON(w, http.StatusBadRequest, txReceiptResponse{OK: false, Error: HTTPErrorInvalidJSONText})
		return
	}

	var hashes []string
	if req.TxHash != "" {
		hashes = append(hashes, req.TxHash)
	}
	if len(req.TxHashes) > 0 {
		hashes = append(hashes, req.TxHashes...)
	}

	hashes = uniqueStrings(hashes)
	if len(hashes) == 0 {
		writeJSON(w, http.StatusBadRequest, txReceiptResponse{OK: false, Error: TxReceiptErrorMissingTxHashText})
		return
	}
	if len(hashes) > TxReceiptRequestMaxTxHashes {
		writeJSON(w, http.StatusBadRequest, txReceiptResponse{OK: false, Error: TxReceiptErrorTooManyTxHashesText})
		return
	}

	out := make(map[string]txReceiptResult, len(hashes))

	for _, h := range hashes {
		hh := strings.TrimSpace(h)
		if !isTxHash(hh) {
			out[hh] = txReceiptResult{
				TxHash: hh,
				Found:  false,
				Status: TxReceiptStatusPendingText,
				Error:  TxReceiptErrorInvalidTxHashFieldText,
			}
			continue
		}

		txHash := common.HexToHash(hh)
		receipt, err := activeChainClient.TransactionReceipt(r.Context(), txHash)
		if err != nil {
			if errors.Is(err, ethereum.NotFound) {
				out[hh] = txReceiptResult{TxHash: hh, Found: false, Status: TxReceiptStatusPendingText}
				continue
			}
			out[hh] = txReceiptResult{TxHash: hh, Found: false, Status: TxReceiptStatusPendingText, Error: err.Error()}
			continue
		}

		statusStr := TxReceiptStatusConfirmedText
		if receipt.Status == TxReceiptResponseMinedFailureStatus64 {
			statusStr = TxReceiptStatusFailedText
		}

		var blockHex string
		if receipt.BlockNumber != nil {
			blockHex = TxReceiptResponseBlockHexPrefix + receipt.BlockNumber.Text(16)
		}

		out[hh] = txReceiptResult{
			TxHash:         hh,
			Found:          true,
			Status:         statusStr,
			ReceiptStatus:  receipt.Status,
			BlockNumberHex: blockHex,
		}
	}

	writeJSON(w, http.StatusOK, txReceiptResponse{OK: true, Data: out})
}

func (s *Server) handleWalletAccounts(w http.ResponseWriter, r *http.Request) {
	if !requireEthClient(w, s) {
		return
	}
	if !requireWalletRuntime(w, s) {
		return
	}

	accounts := make([]string, 0, 3)

	// EOAs always exist
	accounts = append(accounts, s.onChain.User.Address().Hex())
	accounts = append(accounts, s.onChain.Device.Address().Hex())

	// AA account: always return *something* (zero address when not deployed)
	contractAddr := common.Address{}

	if s.onChain.Contract != nil {
		if ca, err := s.onChain.ContractAddress(); err == nil && ca != (common.Address{}) {
			contractAddr = ca
		} else if addr := strings.TrimSpace(s.onChain.Contract.Address); addr != "" {
			contractAddr = common.HexToAddress(addr)
		}
	}

	accounts = append(accounts, contractAddr.Hex())

	accounts = uniqueStrings(accounts)

	writeJSON(w, http.StatusOK, map[string]any{
		"accounts": accounts,
	})
}

func (s *Server) handleWalletSwitchChain(w http.ResponseWriter, r *http.Request) {
	if !requireEthClient(w, s) {
		return
	}

	activeChainClient, err := s.activeHTTP(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	var req walletSwitchChainReq
	if !decodeJSONBodyRPC(w, r, &req) {
		return
	}

	want := strings.TrimSpace(req.ChainIDHex)
	if want == "" {
		writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidRequest, WalletMissingChainIDHexText, nil)
		return
	}

	currentChainID, err := activeChainClient.ChainID(r.Context())
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidRequest, WalletMissingChainIDHexText, nil)
		return
	}
	requestedChainID, err := parseHexChainID(want)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidRequest, WalletMissingChainIDHexText, nil)
		return
	}

	if currentChainID.Cmp(requestedChainID) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}

	network, err := s.chainService.ResolveNetworkByChainIDHex(want)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{JSONKeyNotAdded: true})
		return
	}

	if err := s.chainService.SwitchChain(s.ctx, network.NetworkName); err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletSwitchNetworkFailedText, err.Error())
		return
	}

	if s.onChain != nil {
		_ = s.onChain.ValidateChain(r.Context())
		if err := s.onChain.LoadContractForCurrentChain(r.Context(), s.cwStore); err != nil {
			log.Error("failed to load contract wallet store after switch", "err", err)
		}
	}

	if s.assetsManager != nil {
		defaultAssets := s.cfg.DefaultAssets.Network[network.NetworkName]

		if err := s.assetsManager.EnsureStoreForNetwork(r.Context(), network.NetworkName, defaultAssets); err != nil {
			log.Error("failed to ensure store for network", "network", network.NetworkName, "err", err)
			writeRPCError(w, http.StatusOK, JSONRPCErrorCodeInternalError, WalletFailedToLoadAssetsText, err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{JSONKeyOK: true})
}

func (s *Server) handleWalletSendTransaction(w http.ResponseWriter, r *http.Request) {
	var req SendTxRequest
	if !decodeJSONBodyRPC(w, r, &req) {
		return
	}

	if strings.TrimSpace(req.Tx.From) == "" {
		writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidParams, "missing tx.from", nil)
		return
	}

	from := common.HexToAddress(req.Tx.From)

	// AA path
	if s.isAAAccount(from) {
		s.handleSendViaAA(w, r, req)
		return
	}

	// EOA path
	s.handleSendViaEOA(w, r, req, from)
}

func (s *Server) handleSendViaAA(w http.ResponseWriter, r *http.Request, req SendTxRequest) {
	activeChainClient, err := s.activeHTTP(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}
	chainId, err := activeChainClient.ChainID(s.ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}
	network, err := s.chainService.ResolveNetworkByChainID(chainId.Uint64())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	if strings.TrimSpace(network.EntryPoint) == "" {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletEntryPointNotConfiguredText, nil)
		return
	}

	entryPointAddr := common.HexToAddress(network.EntryPoint)
	entryPoint, err := entrypoint.NewEntryPoint(entryPointAddr, activeChainClient)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletBindEntryPointFailedText, err.Error())
		return
	}

	sender := common.HexToAddress(req.Tx.From)
	to := common.HexToAddress(req.Tx.To)

	value := new(big.Int)
	if req.Tx.Value != "" && req.Tx.Value != HexPrefix0x {
		value.SetString(strings.TrimPrefix(req.Tx.Value, HexPrefix0x), 16)
	}
	data := common.FromHex(req.Tx.Data)

	accABI, err := quantumauthaccount.QuantumAuthAccountMetaData.GetAbi()
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "account abi failed", err.Error())
		return
	}

	callData, err := accABI.Pack("execute", to, value, data)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletPackExecuteFailedText, err.Error())
		return
	}

	nonce, err := entryPoint.GetNonce(&bind.CallOpts{Context: r.Context()}, sender, big.NewInt(UserOpDefaultNonceKeyInt64))
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletGetNonceFailedText, err.Error())
		return
	}

	callGas := new(big.Int).SetUint64(UserOpDefaultCallGasLimitUint64)
	verificationGas := new(big.Int).SetUint64(UserOpDefaultVerificationGasLimitUint64)
	maxPriorityFee := big.NewInt(EIP1559DefaultMaxPriorityFeeWeiInt64)
	maxFee := big.NewInt(EIP1559DefaultMaxFeeWeiInt64)
	preVerificationGas := new(big.Int).SetUint64(UserOpDefaultPreVerificationGasUint64)

	userOp := entrypoint.PackedUserOperation{
		Sender:             sender,
		Nonce:              nonce,
		InitCode:           []byte{},
		CallData:           callData,
		AccountGasLimits:   packU128Pair(callGas, verificationGas),
		PreVerificationGas: preVerificationGas,
		GasFees:            packU128Pair(maxPriorityFee, maxFee),
		PaymasterAndData:   []byte{},
		Signature:          []byte{},
	}

	userOpHash, err := entryPoint.GetUserOpHash(&bind.CallOpts{Context: r.Context()}, userOp)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletGetUserOpHashFailedText, err.Error())
		return
	}

	sig, err := s.signUserOpHash(r.Context(), userOpHash[:])
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletUserOpSigningFailedText, err.Error())
		return
	}
	userOp.Signature = sig

	auth, beneficiary, err := s.relayerAuth(r.Context())
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletTxAuthFailedText, err.Error())
		return
	}

	tx, err := entryPoint.HandleOps(auth, []entrypoint.PackedUserOperation{userOp}, beneficiary)
	if err != nil {
		log.Error(WalletHandleOpsFailedText, "tx", tx, "err", err)
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletHandleOpsFailedText, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"txHash": tx.Hash().Hex()})
}

func (s *Server) handleSendViaEOA(w http.ResponseWriter, r *http.Request, req SendTxRequest, from common.Address) {
	activeChainClient, err := s.activeHTTP(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}
	// Ensure we control this EOA
	wlt, err := s.pickWallet(from)
	if err != nil {
		writeRPCError(w, http.StatusForbidden, JSONRPCErrorCodeInvalidRequest, "from address not controlled by this wallet", nil)
		return
	}

	// "to" can be empty for contract creation
	var to *common.Address
	if strings.TrimSpace(req.Tx.To) != "" && req.Tx.To != HexPrefix0x {
		t := common.HexToAddress(req.Tx.To)
		to = &t
	}

	value := new(big.Int)
	if req.Tx.Value != "" && req.Tx.Value != HexPrefix0x {
		// assume hex string
		v, ok := new(big.Int).SetString(strings.TrimPrefix(req.Tx.Value, HexPrefix0x), 16)
		if !ok {
			writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidParams, "invalid tx.value", req.Tx.Value)
			return
		}
		value = v
	}

	data := common.FromHex(req.Tx.Data)

	// Chain ID
	chainID, err := activeChainClient.ChainID(r.Context())
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "failed to get chainId", err.Error())
		return
	}

	// Nonce
	nonce, err := activeChainClient.PendingNonceAt(r.Context(), from)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "failed to get nonce", err.Error())
		return
	}

	var TxFormatError error

	from = common.HexToAddress(req.Tx.From)

	to, err = parseAddressPtr(req.Tx.To)
	if err != nil {
		TxFormatError = err
	}

	value, err = parseHexBigInt(req.Tx.Value)
	if err != nil {
		TxFormatError = err
	}

	data, err = parseHexData(req.Tx.Data)
	if err != nil {
		TxFormatError = err
	}

	if TxFormatError != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "failed to format transaction", TxFormatError)
		return
	}

	msg := ethereum.CallMsg{
		From:  from,
		To:    to,
		Value: value,
		Data:  data,
	}

	estimatedGas, err := activeChainClient.EstimateGas(r.Context(), msg)
	if err != nil {
		writeRPCError(
			w,
			http.StatusInternalServerError,
			JSONRPCErrorCodeInternalError,
			"estimateGas failed",
			err.Error(),
		)
		return
	}

	// Fees (EIP-1559). Use request values if present, else suggest.
	maxFeePerGas, maxPriorityFeePerGas, err := s.resolveEIP1559Fees(r.Context(), req)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "fee resolution failed", err.Error())
		return
	}

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		Gas:       estimatedGas,
		To:        to,
		Value:     value,
		Data:      data,
		GasTipCap: maxPriorityFeePerGas,
		GasFeeCap: maxFeePerGas,
	})

	signedTx, err := signEOATransaction(r.Context(), wlt, tx, chainID)
	if err != nil {
		writeRPCError(
			w,
			http.StatusInternalServerError,
			JSONRPCErrorCodeInternalError,
			"EOA signing failed",
			err.Error(),
		)
		return
	}

	err = activeChainClient.SendTransaction(r.Context(), signedTx)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "SendTransaction failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"txHash": signedTx.Hash().Hex()})
}

func (s *Server) handleWalletEstimateSendTransaction(w http.ResponseWriter, r *http.Request) {
	activeChainClient, err := s.activeHTTP(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}
	chainId, err := activeChainClient.ChainID(s.ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}
	network, err := s.chainService.ResolveNetworkByChainID(chainId.Uint64())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	if strings.TrimSpace(network.EntryPoint) == "" {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletEntryPointNotConfiguredText, nil)
		return
	}

	entryPointAddr := common.HexToAddress(network.EntryPoint)

	entryPoint, err := entrypoint.NewEntryPoint(entryPointAddr, activeChainClient)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletBindEntryPointFailedText, err.Error())
		return
	}

	var req SendTxRequest
	if !decodeJSONBodyRPC(w, r, &req) {
		return
	}

	sender := common.HexToAddress(req.Tx.From)
	to := common.HexToAddress(req.Tx.To)

	value := new(big.Int)
	if req.Tx.Value != "" && req.Tx.Value != HexPrefix0x {
		if _, ok := value.SetString(strings.TrimPrefix(req.Tx.Value, HexPrefix0x), 16); !ok {
			writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidParams, "bad value hex", req.Tx.Value)
			return
		}
	}
	data := common.FromHex(req.Tx.Data)

	accABI, err := quantumauthaccount.QuantumAuthAccountMetaData.GetAbi()
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "account abi failed", err.Error())
		return
	}

	callData, err := accABI.Pack("execute", to, value, data)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletPackExecuteFailedText, err.Error())
		return
	}

	nonce, err := entryPoint.GetNonce(&bind.CallOpts{Context: r.Context()}, sender, big.NewInt(UserOpDefaultNonceKeyInt64))
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletGetNonceFailedText, err.Error())
		return
	}

	head, err := activeChainClient.HeaderByNumber(r.Context(), nil)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "get latest header failed", err.Error())
		return
	}
	baseFee := head.BaseFee
	if baseFee == nil {
		baseFee = big.NewInt(0)
	}

	tipCap, err := s.httpChainClient.SuggestGasTipCap(r.Context())
	if err != nil {
		tipCap = big.NewInt(EIP1559DefaultMaxPriorityFeeWeiInt64)
	}

	maxFee := new(big.Int).Mul(baseFee, big.NewInt(EIP1559MaxFeeBaseFeeMultiplierInt64))
	maxFee.Add(maxFee, tipCap)

	preVerificationGas := new(big.Int).SetUint64(UserOpDefaultPreVerificationGasUint64)
	callGasTmp := new(big.Int).SetUint64(UserOpEstimateTmpCallGasLimitUint64)
	verificationGasTmp := new(big.Int).SetUint64(UserOpEstimateTmpVerificationGasLimitUint64)

	userOp := entrypoint.PackedUserOperation{
		Sender:             sender,
		Nonce:              nonce,
		InitCode:           []byte{},
		CallData:           callData,
		AccountGasLimits:   packU128Pair(callGasTmp, verificationGasTmp),
		PreVerificationGas: preVerificationGas,
		GasFees:            packU128Pair(tipCap, maxFee),
		PaymasterAndData:   []byte{},
		Signature:          []byte{},
	}

	userOpHash, err := entryPoint.GetUserOpHash(&bind.CallOpts{Context: r.Context()}, userOp)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletGetUserOpHashFailedText, err.Error())
		return
	}

	sig, err := s.signUserOpHash(r.Context(), userOpHash[:])
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletUserOpSigningFailedText, err.Error())
		return
	}
	userOp.Signature = sig

	callGasU64, err := activeChainClient.EstimateGas(r.Context(), ethereum.CallMsg{
		From: entryPointAddr,
		To:   &sender,
		Data: callData,
	})
	if err != nil {
		log.Error("estimate execute callGas failed; falling back", "err", err)
		callGasU64 = GasEstimateCallGasFallbackUint64
	}
	callGasLimit := new(big.Int).SetUint64(applyBpsBuffer(callGasU64, GasBufferBpsCallGasLimit))

	missingFunds := big.NewInt(UserOpDefaultMissingFundsWeiInt64)

	validateCalldata, err := accABI.Pack("validateUserOp", userOp, userOpHash, missingFunds)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "pack validateUserOp failed", err.Error())
		return
	}

	verificationGasU64, err := activeChainClient.EstimateGas(r.Context(), ethereum.CallMsg{
		From: entryPointAddr,
		To:   &sender,
		Data: validateCalldata,
	})
	if err != nil {
		log.Error("estimate validateUserOp verificationGas failed; falling back", "err", err)
		verificationGasU64 = GasEstimateVerificationGasFallbackUint64
	}
	verificationGasLimit := new(big.Int).SetUint64(applyBpsBuffer(verificationGasU64, GasBufferBpsVerificationGasLimit))

	agl := packU128Pair(callGasLimit, verificationGasLimit)
	gf := packU128Pair(tipCap, maxFee)

	resp := map[string]any{
		"baseFeeWei":               baseFee.String(),
		"baseFeeGwei":              weiToGweiString(baseFee),
		"maxPriorityFeePerGasWei":  tipCap.String(),
		"maxPriorityFeePerGasGwei": weiToGweiString(tipCap),
		"maxFeePerGasWei":          maxFee.String(),
		"maxFeePerGasGwei":         weiToGweiString(maxFee),

		"callGasLimit":         callGasLimit.String(),
		"verificationGasLimit": verificationGasLimit.String(),
		"preVerificationGas":   preVerificationGas.String(),

		"accountGasLimitsHex":     HexPrefix0x + hex.EncodeToString(agl[:]),
		"gasFeesHex":              HexPrefix0x + hex.EncodeToString(gf[:]),
		"callGasLimitHex":         HexPrefix0x + callGasLimit.Text(16),
		"verificationGasLimitHex": HexPrefix0x + verificationGasLimit.Text(16),
		"preVerificationGasHex":   HexPrefix0x + preVerificationGas.Text(16),
		"maxFeePerGasHex":         HexPrefix0x + maxFee.Text(16),
		"maxPriorityFeePerGasHex": HexPrefix0x + tipCap.Text(16),
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleWalletPersonalSign(w http.ResponseWriter, r *http.Request) {
	// NOTE: requireWalletRuntime checks onChain.User/Device; this endpoint only needs onChain != nil.
	// If you want to keep original semantics, add a separate helper requireOnChain(w,s).
	if s.onChain == nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletRuntimeNotInitializedText, nil)
		return
	}

	var req walletPersonalSignReq
	if !decodeJSONBodyRPC(w, r, &req) {
		return
	}

	addr, err := parseAddr(req.Address)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidParams, WalletInvalidAddressText, err.Error())
		return
	}

	wallet, err := s.pickWallet(addr)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{JSONKeyUnauthorized: true})
		return
	}

	msgBytes, err := parsePersonalSignMessage(req.Message)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidParams, WalletInvalidMessageText, err.Error())
		return
	}

	digest := eip191HashPersonalMessage(msgBytes)
	sig, err := wallet.SignHash(r.Context(), digest)
	if err != nil {
		writeRPCError(w, http.StatusOK, JSONRPCErrorCodeInternalError, WalletSignFailedText, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"signature": sigToHex(sig)})
}

func (s *Server) handleWalletSignTypedDataV4(w http.ResponseWriter, r *http.Request) {
	if s.onChain == nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletRuntimeNotInitializedText, nil)
		return
	}

	var req walletSignTypedDataReq
	if !decodeJSONBodyRPC(w, r, &req) {
		return
	}

	addr, err := parseAddr(req.Address)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidParams, WalletInvalidAddressText, err.Error())
		return
	}

	wallet, err := s.pickWallet(addr)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{JSONKeyUnauthorized: true})
		return
	}

	digest, err := eip712DigestV4(req.TypedDataJson)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidParams, WalletInvalidTypedDataText, err.Error())
		return
	}

	sig, err := wallet.SignHash(r.Context(), digest)
	if err != nil {
		writeRPCError(w, http.StatusOK, JSONRPCErrorCodeInternalError, WalletSignFailedText, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"signature": sigToHex(sig)})
}

func (s *Server) handleWalletRPC(w http.ResponseWriter, r *http.Request) {
	var req walletRPCReq
	if !decodeJSONBodyRPC(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Method) == "" {
		writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidRequest, WalletMissingMethodText, nil)
		return
	}

	switch req.Method {
	case "eth_getBalance":
		resultHex, err := s.handleEthGetBalance(r.Context(), req.Params)
		if err != nil {
			// Invalid params should be 400 + InvalidParams
			var rpcCode int
			var httpStatus int
			if errors.Is(err, errInvalidParams) {
				httpStatus = http.StatusBadRequest
				rpcCode = JSONRPCErrorCodeInvalidParams
			} else {
				httpStatus = http.StatusInternalServerError
				rpcCode = JSONRPCErrorCodeInternalError
			}
			writeRPCError(w, httpStatus, rpcCode, err.Error(), nil)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{JSONKeyResult: resultHex})
		return

	default:
		writeRPCError(
			w,
			http.StatusBadRequest,
			JSONRPCErrorCodeMethodNotFound,
			fmt.Sprintf("unsupported rpc method %q", req.Method),
			nil,
		)
		return
	}
}

func (s *Server) handleWalletAccountsSummary(w http.ResponseWriter, r *http.Request) {
	if !requireWalletRuntime(w, s) {
		return
	}
	if !requireEthClient(w, s) {
		return
	}

	activeChainClient, err := s.activeHTTP(r.Context())
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "no active chain", err.Error())
		return
	}

	chainID, err := activeChainClient.ChainID(r.Context())
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletChainIDFetchFailedText, err.Error())
		return
	}
	network, _ := s.chainService.ResolveNetworkByChainID(chainID.Uint64())

	cryptoAssets := []assetOut{}
	if s.assetsManager != nil && network.NetworkName != "" {
		contractAddr, _ := s.onChain.ContractAddress()

		list, err := s.assetsManager.ListForNetwork(r.Context(), network.NetworkName)
		if err != nil {
			writeRPCError(w, http.StatusOK, JSONRPCErrorCodeInternalError, WalletAssetsLoadFailedText, err.Error())
			return
		}

		for _, as := range list {
			if strings.EqualFold(as.Address, common.HexToAddress(constants.NativeAddr).Hex()) {
				weiDec, err := s.getBalanceWeiDecimal(r.Context(), contractAddr)
				if err != nil {
					writeRPCError(w, http.StatusOK, JSONRPCErrorCodeInternalError, WalletNativeBalanceFetchFailedText, err.Error())
					return
				}
				cryptoAssets = append(cryptoAssets, assetOut{
					Address:      common.HexToAddress(constants.NativeAddr).Hex(),
					Symbol:       NativeAssetSymbolETH,
					Decimals:     NativeAssetDecimalsETH,
					Name:         NativeAssetNameEther,
					BalanceWei:   weiDec,
					BalanceHuman: weiDecimalToEthString(weiDec, BalanceHumanMaxDecimalsDefault),
					LogoURI:      as.LogoURI,
				})
				continue
			}

			balWei, err := s.assetsManager.BalanceOf(r.Context(), network.NetworkName, common.HexToAddress(as.Address), contractAddr)
			if err != nil {
				log.Error("asset balance failed", "asset", as.Address, "err", err)
				continue
			}

			cryptoAssets = append(cryptoAssets, assetOut{
				Address:      common.HexToAddress(as.Address).Hex(),
				Symbol:       as.Symbol,
				Decimals:     as.Decimals,
				Name:         as.Name,
				BalanceWei:   balWei.String(),
				BalanceHuman: utils.FormatUnitsTrim(balWei, as.Decimals, BalanceHumanMaxDecimalsDefault),
				LogoURI:      as.LogoURI,
			})
		}
	}

	err = s.onChain.LoadContractForCurrentChain(s.ctx, s.cwStore)
	if err != nil {
		return
	}

	accts := []acctIn{
		{Addr: s.onChain.User.Address(), Role: "user (EOA)"},
		{Addr: s.onChain.Device.Address(), Role: "device (TPM)"},
	}

	// Always return the AA contract row (zero address when not deployed)
	contractAddr := common.Address{}

	if s.onChain.Contract != nil {
		if ca, err := s.onChain.ContractAddress(); err == nil && ca != (common.Address{}) {
			contractAddr = ca
		} else if addr := strings.TrimSpace(s.onChain.Contract.Address); addr != "" {
			contractAddr = common.HexToAddress(addr)
		}
	}

	accts = append(accts, acctIn{Addr: contractAddr, Role: "contract"})

	out := make([]acctOut, 0, len(accts))
	for _, a := range accts {
		weiDec, err := s.getBalanceWeiDecimal(r.Context(), a.Addr)
		if err != nil {
			writeRPCError(w, http.StatusOK, JSONRPCErrorCodeInternalError, WalletBalanceFetchFailedText, err.Error())
			return
		}

		ethStr := weiDecimalToEthString(weiDec, BalanceHumanMaxDecimalsDefault)
		if ethStr == "" {
			ethStr = "0.0"
		}

		out = append(out, acctOut{
			Address:    a.Addr.Hex(),
			Role:       a.Role,
			BalanceWei: weiDec,
			BalanceEth: ethStr,
			Symbol:     NativeAssetSymbolETH,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK: true,
		JSONKeyData: map[string]any{
			JSONKeyChainIDHex: bigIntToHexQuantity(chainID),
			"accounts":        out,
			"assets":          cryptoAssets,
		},
	})
}

func (s *Server) handleWalletNetworkMetadata(w http.ResponseWriter, r *http.Request) {
	if !requireEthClient(w, s) {
		return
	}
	if s.networksManager == nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: "networks manager not initialized"})
		return
	}

	var req shared.NetworkMetadataReq
	if !decodeJSONBody(w, r, &req) {
		return
	}

	ctx := r.Context()

	// 1) Probe the RPC
	meta, err := s.networksManager.ProbeRPC(ctx, req.RpcUrl)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: err.Error(),
		})
		return
	}

	// 2) Enrich from store + chainId defaults (+ entrypoint detection if you add it)
	meta = s.networksManager.EnrichByChain(ctx, meta)

	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK:   true,
		JSONKeyData: meta,
	})
}

func (s *Server) handleWalletNetworks(w http.ResponseWriter, r *http.Request) {
	if !requireEthClient(w, s) {
		return
	}
	if s.networksManager == nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: "networks manager not initialized"})
		return
	}

	activeChainClient, err := s.activeHTTP(r.Context())
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "no active chain", err.Error())
		return
	}

	currentChainID, err := activeChainClient.ChainID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	nets, err := s.networksManager.ListFromFile(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	// Return the same shape your extension expects: { ok:true, data:{ currentChainIdHex, networks:[...] } }
	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK: true,
		JSONKeyData: map[string]any{
			JSONKeyCurrentChainIDHex: bigIntToHexQuantity(currentChainID),
			JSONKeyNetworks:          nets,
		},
	})
}

func (s *Server) handleWalletSetNetwork(w http.ResponseWriter, r *http.Request) {
	if !requireEthClient(w, s) {
		return
	}

	if s.networksManager == nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: "networks manager not initialized"})
		return
	}

	var req walletSetNetworkReq
	if !decodeJSONBody(w, r, &req) {
		return
	}

	wantHex := strings.TrimSpace(req.ChainIDHex)
	if wantHex == "" {
		http.Error(w, WalletMissingChainIDHexText, http.StatusBadRequest)
		return
	}

	// 1) Find the network the user has added (by chainIdHex)
	netInfo, found, err := s.networksManager.FindByChainIdHex(r.Context(), wantHex)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}
	if !found {
		writeJSON(w, http.StatusOK, map[string]any{
			JSONKeyOK:       false,
			JSONKeyNotAdded: true,
			JSONKeyError:    "network not added",
		})
		return
	}

	// 2) Switch active chain (no-op if already active)
	if err := s.chainService.SwitchChain(r.Context(), netInfo.Name); err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	if s.onChain != nil {
		_ = s.onChain.ValidateChain(r.Context())
	}

	writeJSON(w, http.StatusOK, map[string]any{JSONKeyOK: true})
}

func (s *Server) handleDeployContractOnChain(w http.ResponseWriter, r *http.Request) {

	if s.deployer == nil {
		writeJSON(w, http.StatusInternalServerError, deployAAResponse{
			OK:  false,
			Err: "deployer not initialized",
		})
		return
	}

	var req deployAARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, HTTPErrorInvalidJSONText, http.StatusBadRequest)
		return
	}

	req.ChainIDHex = strings.TrimSpace(req.ChainIDHex)
	if req.ChainIDHex == "" {
		writeJSON(w, http.StatusBadRequest, deployAAResponse{
			OK:  false,
			Err: WalletMissingChainIDHexText,
		})
		return
	}

	res, err := s.deployer.DeployAAOnChainIDHex(r.Context(), req.ChainIDHex, req.RecoveryAddress)
	if err != nil {
		// Use 502 if this is typically upstream/rpc related; otherwise 500 is fine.
		writeJSON(w, http.StatusInternalServerError, deployAAResponse{
			OK:  false,
			Err: err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, deployAAResponse{
		OK:   true,
		Data: res,
	})
}

func (s *Server) handleWalletAddNetwork(w http.ResponseWriter, r *http.Request) {
	var req shared.AddNetworkReq
	if !decodeJSONBody(w, r, &req) {
		return
	}

	ctx := r.Context()

	networkConfig, err := toChainsNetworkConfig(req.Network)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	added, err := s.networksManager.AddNetwork(ctx, networkConfig)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "failed to add network",
			"details":    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK: true,
		JSONKeyData: map[string]any{
			"network": added,
		},
	})
}

func (s *Server) handleWalletRemoveNetwork(w http.ResponseWriter, r *http.Request) {
	var req removeNetworkReq
	if !decodeJSONBody(w, r, &req) {
		return
	}

	chainIdHex := strings.TrimSpace(req.ChainIdHex)
	if chainIdHex == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "chainIdHex is required",
		})
		return
	}

	ctx := r.Context()

	if err := s.networksManager.RemoveNetworkByChainIdHex(ctx, chainIdHex); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "failed to remove network",
			"details":    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK: true,
		JSONKeyData: map[string]any{
			"removed": true,
		},
	})
}

func (s *Server) handleWalletUpdateNetwork(w http.ResponseWriter, r *http.Request) {
	var req shared.UpdateNetworkReq
	if !decodeJSONBody(w, r, &req) {
		return
	}

	chainIdHex := strings.TrimSpace(req.ChainIdHex)
	if chainIdHex == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "chainIdHex is required",
		})
		return
	}

	ctx := r.Context()

	updated, err := s.networksManager.UpdateNetworkByChainIdHex(ctx, chainIdHex, req.Patch)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "failed to update network",
			"details":    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK: true,
		JSONKeyData: map[string]any{
			"network": updated,
		},
	})
}

func (s *Server) handleWalletListAssets(w http.ResponseWriter, r *http.Request) {
	var req listAssetsReq
	if !decodeJSONBody(w, r, &req) {
		return
	}

	network := strings.TrimSpace(req.NetworkName)
	if network == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "networkName is required",
		})
		return
	}

	ctx := r.Context()

	// OPTIONAL (recommended): bootstrap defaults for this network without overwriting user edits.
	// If you don’t have defaults yet, just use an empty slice.
	var defaultAddrs []string
	if err := s.assetsManager.EnsureStoreForNetwork(ctx, network, defaultAddrs); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "failed to load assets store",
			"details":    err.Error(),
		})
		return
	}

	list, err := s.assetsManager.ListForNetwork(ctx, network)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "failed to list assets",
			"details":    err.Error(),
		})
		return
	}

	// Map assets.Asset -> UI AssetRow
	rows := make([]map[string]any, 0, len(list))
	for _, a := range list {
		rows = append(rows, map[string]any{
			"address":  a.Address,
			"symbol":   a.Symbol,
			"name":     a.Name,
			"decimals": a.Decimals,
			"logoURI":  a.LogoURI,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK:   true,
		JSONKeyData: rows,
	})
}

func (s *Server) handleWalletAddAsset(w http.ResponseWriter, r *http.Request) {
	var req addAssetReq
	if !decodeJSONBody(w, r, &req) {
		return
	}

	network := strings.TrimSpace(req.NetworkName)
	address := strings.TrimSpace(req.Address)

	if network == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "networkName is required",
		})
		return
	}
	if address == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "address is required",
		})
		return
	}

	asset, err := s.assetsManager.AddAsset(s.ctx, network, address)
	if err != nil {
		// treat as user-input / chain lookup error by default
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "failed to add asset",
			"details":    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK: true,
		JSONKeyData: map[string]any{
			"address":  asset.Address,
			"symbol":   asset.Symbol,
			"name":     asset.Name,
			"decimals": asset.Decimals,
			"logoURI":  asset.LogoURI,
		},
	})
}

func (s *Server) handleWalletRemoveAsset(w http.ResponseWriter, r *http.Request) {
	var req removeAssetReq
	if !decodeJSONBody(w, r, &req) {
		return
	}

	network := strings.TrimSpace(req.NetworkName)
	address := strings.TrimSpace(req.Address)

	if network == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "networkName is required",
		})
		return
	}
	if address == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "address is required",
		})
		return
	}

	ctx := r.Context()

	if err := s.assetsManager.RemoveAsset(ctx, network, address); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "failed to remove asset",
			"details":    err.Error(),
		})
		return
	}

	// simple ack is enough; UI reloads list
	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK: true,
		JSONKeyData: map[string]any{
			"removed": true,
		},
	})
}

func (s *Server) handleWalletAssetMetadata(w http.ResponseWriter, r *http.Request) {
	var req assetMetadataReq
	if !decodeJSONBody(w, r, &req) {
		return
	}

	network := strings.TrimSpace(req.NetworkName)
	address := strings.TrimSpace(req.Address)

	if network == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "networkName is required",
		})
		return
	}
	if address == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "address is required",
		})
		return
	}

	// Important: use request context (cancels if popup closes / user types again)
	ctx := r.Context()

	asset, err := s.assetsManager.FetchAsset(ctx, network, address)
	if err != nil {
		// keep it user-friendly, but include details if you want for debugging
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "failed to fetch asset metadata",
			"details":    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK: true,
		JSONKeyData: map[string]any{
			"address":  asset.Address,
			"symbol":   asset.Symbol,
			"name":     asset.Name,
			"decimals": asset.Decimals,
			"logoURI":  asset.LogoURI,
		},
	})
}
