package http

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/quantumauth-io/quantum-auth-client/internal/constants"
	"github.com/quantumauth-io/quantum-auth-client/internal/contracts/bindings/go/entrypoint"
	"github.com/quantumauth-io/quantum-auth-client/internal/contracts/bindings/go/quantumauthaccount"
	"github.com/quantumauth-io/quantum-auth-client/internal/eth"
	"github.com/quantumauth-io/quantum-auth-client/internal/utils"
	utilsEth "github.com/quantumauth-io/quantum-go-utils/ethrpc"
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

	chainIDHex, err := s.ethClient.ChainIDHex(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyChainIDHex: chainIDHex,
	})
}

func (s *Server) handleTransactionReceipt(w http.ResponseWriter, r *http.Request) {
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
		receipt, err := s.ethClient.TransactionReceipt(r.Context(), txHash)
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
	if !requireWalletRuntime(w, s) {
		return
	}

	accounts := make([]string, 0, 3)

	// EOAs always exist
	accounts = append(accounts, s.onChain.User.Address().Hex())
	accounts = append(accounts, s.onChain.Device.Address().Hex())

	if s.onChain.Contract != nil {
		if ca, err := s.onChain.ContractAddress(); err == nil && ca != (common.Address{}) {
			accounts = append(accounts, ca.Hex())
		} else if addr := strings.TrimSpace(s.onChain.Contract.Address); addr != "" {
			accounts = append(accounts, common.HexToAddress(addr).Hex())
		}
	}

	accounts = uniqueStrings(accounts)

	writeJSON(w, http.StatusOK, map[string]any{
		"accounts": accounts,
	})
}

func (s *Server) handleWalletSwitchChain(w http.ResponseWriter, r *http.Request) {
	var req walletSwitchChainReq
	if !decodeJSONBodyRPC(w, r, &req) {
		return
	}

	want := strings.TrimSpace(req.ChainIDHex)
	if want == "" {
		writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidRequest, WalletMissingChainIDHexText, nil)
		return
	}

	got, err := s.ethClient.ChainIDHex(r.Context())
	if err == nil && strings.EqualFold(utilsEth.NormalizeHex0x(got), utilsEth.NormalizeHex0x(want)) {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}

	networkName, err := eth.NetworkNameForChainIDHex(s.cfg.EthNetworks, want)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{JSONKeyNotAdded: true})
		return
	}

	if err := s.ethClient.UseNetwork(networkName); err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletSwitchNetworkFailedText, err.Error())
		return
	}
	if err := s.ethClient.UseRPC(EthRPCProviderInfuraName); err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}
	if err := s.ethClient.EnsureBackend(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	if s.onChain != nil {
		_ = s.onChain.ValidateChain(r.Context())
		if err := s.onChain.LoadContractForCurrentChain(r.Context(), s.cwStore); err != nil {
			log.Error("failed to load contract wallet store after switch", "err", err)
		}
	}

	if s.assetsManager != nil {
		defaultAssets := s.cfg.DefaultAssets.Network[networkName]
		if err := s.assetsManager.EnsureStoreForNetwork(r.Context(), networkName, defaultAssets); err != nil {
			log.Error("failed to ensure store for network", "network", networkName, "err", err)
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
	netCfg, ok := s.cfg.EthNetworks.Networks[s.cfg.EthNetworks.ActiveNetwork]
	if !ok {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletActiveNetworkNotFoundText, nil)
		return
	}
	if strings.TrimSpace(netCfg.EntryPoint) == "" {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletEntryPointNotConfiguredText, nil)
		return
	}

	entryPointAddr := common.HexToAddress(netCfg.EntryPoint)
	ep, err := entrypoint.NewEntryPoint(entryPointAddr, s.ethClient.Backend())
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletBindEntryPointFailedText, err.Error())
		return
	}

	if !decodeJSONBodyRPC(w, r, &req) {
		// decodeJSONBodyRPC already wrote error
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

	nonce, err := ep.GetNonce(&bind.CallOpts{Context: r.Context()}, sender, big.NewInt(UserOpDefaultNonceKeyInt64))
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

	userOpHash, err := ep.GetUserOpHash(&bind.CallOpts{Context: r.Context()}, userOp)
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

	tx, err := ep.HandleOps(auth, []entrypoint.PackedUserOperation{userOp}, beneficiary)
	if err != nil {
		log.Error(WalletHandleOpsFailedText, "tx", tx, "err", err)
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletHandleOpsFailedText, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"txHash": tx.Hash().Hex()})
}

func (s *Server) handleSendViaEOA(w http.ResponseWriter, r *http.Request, req SendTxRequest, from common.Address) {
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
	chainID, err := s.ethClient.ChainID(r.Context())
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "failed to get chainId", err.Error())
		return
	}

	// Nonce
	nonce, err := s.ethClient.PendingNonceAt(r.Context(), from)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "failed to get nonce", err.Error())
		return
	}

	msg := utilsEth.CallMsg{
		From:  req.Tx.From,
		To:    req.Tx.To,
		Value: req.Tx.Value,
		Data:  req.Tx.Data,
	}

	estimatedGas, err := s.ethClient.EstimateGas(r.Context(), msg)
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
		Gas:       estimatedGas.Uint64(),
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

	rawBytes, err := signedTx.MarshalBinary()
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "marshal tx failed", err.Error())
		return
	}

	rawHex := hexutil.Encode(rawBytes)

	txHash, err := s.ethClient.SendRawTransaction(r.Context(), rawHex)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "SendTransaction failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"txHash": txHash.Hex()})
}

func (s *Server) handleWalletEstimateSendTransaction(w http.ResponseWriter, r *http.Request) {
	netCfg, ok := s.cfg.EthNetworks.Networks[s.cfg.EthNetworks.ActiveNetwork]
	if !ok {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletActiveNetworkNotFoundText, nil)
		return
	}
	if strings.TrimSpace(netCfg.EntryPoint) == "" {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletEntryPointNotConfiguredText, nil)
		return
	}

	entryPointAddr := common.HexToAddress(netCfg.EntryPoint)
	backend := s.ethClient.Backend()

	ep, err := entrypoint.NewEntryPoint(entryPointAddr, backend)
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

	nonce, err := ep.GetNonce(&bind.CallOpts{Context: r.Context()}, sender, big.NewInt(UserOpDefaultNonceKeyInt64))
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletGetNonceFailedText, err.Error())
		return
	}

	head, err := backend.HeaderByNumber(r.Context(), nil)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "get latest header failed", err.Error())
		return
	}
	baseFee := head.BaseFee
	if baseFee == nil {
		baseFee = big.NewInt(0)
	}

	tipCap, err := backend.SuggestGasTipCap(r.Context())
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

	userOpHash, err := ep.GetUserOpHash(&bind.CallOpts{Context: r.Context()}, userOp)
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

	callGasU64, err := backend.EstimateGas(r.Context(), ethereum.CallMsg{
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

	verificationGasU64, err := backend.EstimateGas(r.Context(), ethereum.CallMsg{
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

	log.Info("wallet personal sign", "addr", addr)

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

	log.Info("typesDataSigning", "addr", addr)

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
	if req.Method == "" {
		writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidRequest, WalletMissingMethodText, nil)
		return
	}

	var out json.RawMessage
	if err := s.ethClient.Call(r.Context(), req.Method, req.Params, &out); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			JSONKeyError: rpcErr{Code: JSONRPCErrorCodeInternalError, Message: err.Error()},
		})
		return
	}

	var result any
	_ = json.Unmarshal(out, &result)

	writeJSON(w, http.StatusOK, map[string]any{JSONKeyResult: result})
}

func (s *Server) handleWalletAccountsSummary(w http.ResponseWriter, r *http.Request) {
	if !requireWalletRuntime(w, s) {
		return
	}
	if s.ethClient == nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletRuntimeNotInitializedText, nil)
		return
	}

	chainIDHex, err := s.ethClient.ChainIDHex(r.Context())
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletChainIDFetchFailedText, err.Error())
		return
	}
	networkName, _ := eth.NetworkNameForChainIDHex(s.cfg.EthNetworks, chainIDHex)

	cryptoAssets := []assetOut{}
	if s.assetsManager != nil && networkName != "" {
		contractAddr, _ := s.onChain.ContractAddress()

		list, err := s.assetsManager.ListForNetwork(r.Context(), networkName)
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

			balWei, err := s.assetsManager.BalanceOf(r.Context(), networkName, common.HexToAddress(as.Address), contractAddr)
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

	accts := []acctIn{
		{Addr: s.onChain.User.Address(), Role: "user (EOA)"},
		{Addr: s.onChain.Device.Address(), Role: "device (TPM)"},
	}

	if s.onChain.Contract != nil {
		if ca, err := s.onChain.ContractAddress(); err == nil && (ca != common.Address{}) {
			accts = append(accts, acctIn{Addr: ca, Role: "contract"})
		}
	}

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
			JSONKeyChainIDHex: chainIDHex,
			"accounts":        out,
			"assets":          cryptoAssets,
		},
	})
}

func (s *Server) handleWalletNetworks(w http.ResponseWriter, r *http.Request) {
	if !requireEthClient(w, s) {
		return
	}

	currentChainIDHex, err := s.ethClient.ChainIDHex(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK: true,
		JSONKeyData: map[string]any{
			JSONKeyCurrentChainIDHex: currentChainIDHex,
			JSONKeyNetworks:          s.ethClient.SupportedNetworks(),
		},
	})
}

func (s *Server) handleWalletSetNetwork(w http.ResponseWriter, r *http.Request) {
	if !requireEthClient(w, s) {
		return
	}

	var req walletSetNetworkReq
	if !decodeJSONBody(w, r, &req) {
		return
	}

	want := strings.TrimSpace(req.ChainIDHex)
	if want == "" {
		http.Error(w, WalletMissingChainIDHexText, http.StatusBadRequest)
		return
	}

	networkName, err := eth.NetworkNameForChainIDHex(s.cfg.EthNetworks, want)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			JSONKeyOK:       false,
			JSONKeyNotAdded: true,
			JSONKeyError:    err.Error(),
		})
		return
	}

	if err := s.ethClient.UseNetwork(networkName); err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}
	if err := s.ethClient.UseRPC(EthRPCProviderInfuraName); err != nil {
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

	res, err := s.deployer.DeployAAOnChainIDHex(r.Context(), req.ChainIDHex)
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
