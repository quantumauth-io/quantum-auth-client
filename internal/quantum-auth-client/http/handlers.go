package http

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"

	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/constants"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/devkeys"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/txsender"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/walletsigner"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/shared"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/utils"
	"github.com/quantumauth-io/quantum-go-utils/log"
	"github.com/quantumauth-io/quantum-go-utils/qa/requests"
)

// WEB2 Handlers

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
		s.handleRequestChallenge(w, r, extReq)

	default:
		writeJSON(w, http.StatusBadRequest, extensionResponse{
			OK:    false,
			Error: ExtensionUnknownActionError,
		})
	}
}

func (s *Server) handleRequestChallenge(w http.ResponseWriter, r *http.Request, extReq extensionRequest) {
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
	
	validatedAppId, err := requests.ValidateUUIDv4(req.AppID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, extensionResponse{OK: false, Error: "missing/invalid appID"})
		return
	}

	if s.perms == nil || !s.perms.IsAllowed(validatedAppId) {
		writeJSON(w, http.StatusOK, extensionResponse{
			OK:    false,
			Error: ExtensionApprovalRequiredError,
			Data: map[string]any{
				JSONKeyOrigin:  validatedAppId,
				JSONKeyAllowed: false,
			},
		})
		return
	}

	chID, err := s.qaClient.RequestChallenge(s.ctx, s.identity.DeviceID, validatedAppId)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	normalizedMethod, err := requests.NormalizeAndValidateMethod(req.Method)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	normalizedHost := requests.NormalizeBackendHost(req.BackendHost)

	normalizedPath, err := requests.NormalizeAndValidatePath(req.Path, requests.PathNormalizeOptions{
		CollapseSlashes: false,
	})

	validatedChallangeId, err := requests.ValidateUUIDv4(chID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	var body []byte
	if strings.TrimSpace(req.BodyB64) != "" {
		var err error
		body, err = base64.RawStdEncoding.DecodeString(req.BodyB64)
		if err != nil {
			body, err = base64.StdEncoding.DecodeString(req.BodyB64)
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, extensionResponse{OK: false, Error: "invalid bodyB64"})
			return
		}
	}

	signedHeaders, err := s.qaClient.SignRequestAndReturnHeaders(
		s.ctx,
		normalizedMethod,
		normalizedPath,
		validatedAppId,
		normalizedHost,
		s.identity.UserID,
		s.identity.DeviceID,
		validatedChallangeId,
		body,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, extensionResponse{
		OK: true,
		Data: map[string]any{
			"qaProof": signedHeaders,
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
	raw := strings.TrimSpace(r.URL.Query().Get(JSONKeyAppId))
	appID, err := requests.ValidateUUIDv4(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, extensionResponse{OK: false, Error: "missing/invalid app id"})
		return
	}

	writeJSON(w, http.StatusOK, extensionResponse{
		OK: true,
		Data: map[string]any{
			JSONKeyAppId:   appID,
			JSONKeyAllowed: s.perms.IsAllowed(appID),
		},
	})
}

func (s *Server) handleSetPermission(w http.ResponseWriter, r *http.Request) {
	var req setPermissionRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}

	appID, err := requests.ValidateUUIDv4(req.AppId)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, extensionResponse{OK: false, Error: "missing/invalid appID"})
	}
	if appID == "" {
		writeJSON(w, http.StatusBadRequest, extensionResponse{OK: false, Error: "missing/invalid appID"})
		return
	}

	if err := s.perms.Set(appID, req.Allowed); err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, extensionResponse{
		OK: true,
		Data: map[string]any{
			JSONKeyAppId:   appID,
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

// Dev Keys Provider

func (s *Server) handleDevKeyList(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.requireDevKeys(w, r)
	if !ok {
		return
	}

	keys, err := snap.Manager.List(r.Context())
	if err != nil {
		writeJSON(w, devKeyHTTPStatus(err), map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "failed to list developer keys",
			"details":    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK: true,
		JSONKeyData: map[string]any{
			"keys": keys,
		},
	})
}

func (s *Server) handleDevKeyCreate(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.requireDevKeys(w, r)
	if !ok {
		return
	}

	var req devKeyCreateReq
	if !decodeJSONBody(w, r, &req) {
		return
	}

	appID := strings.TrimSpace(req.AppID)
	appName := strings.TrimSpace(req.AppName)

	if appID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "appId is required",
		})
		return
	}
	if appName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "appName is required",
		})
		return
	}

	ctx := r.Context()

	k, err := snap.Manager.Create(ctx, appID, appName)
	if err != nil {
		status := devKeyHTTPStatus(err)

		// friendlier message for expected conflicts
		msg := "failed to create developer key"
		if errors.Is(err, devkeys.ErrConflict) {
			msg = "developer key already exists for this appId"
		} else if errors.Is(err, devkeys.ErrInvalidInput) {
			msg = "invalid input"
		}

		writeJSON(w, status, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: msg,
			"details":    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK: true,
		JSONKeyData: map[string]any{
			"key": k,
		},
	})
}

func (s *Server) handleDevKeyUpdate(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.requireDevKeys(w, r)
	if !ok {
		return
	}

	var req devKeyUpdateReq
	if !decodeJSONBody(w, r, &req) {
		return
	}

	appID := strings.TrimSpace(req.AppID)
	if appID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "appId is required",
		})
		return
	}

	// normalize patch
	var patch devkeys.Patch

	if req.Patch.AppName != nil {
		v := strings.TrimSpace(*req.Patch.AppName)
		patch.AppName = &v
		if v == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				JSONKeyOK:    false,
				JSONKeyError: "appName cannot be empty",
			})
			return
		}
	}

	if patch.AppName == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "patch is empty (appName is required)",
		})
		return
	}

	ctx := r.Context()

	if err := snap.Manager.Update(ctx, appID, patch); err != nil {
		status := devKeyHTTPStatus(err)

		msg := "failed to update developer key"
		if errors.Is(err, devkeys.ErrNotFound) {
			msg = "developer key not found"
		} else if errors.Is(err, devkeys.ErrInvalidInput) {
			msg = "invalid input"
		}

		writeJSON(w, status, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: msg,
			"details":    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK: true,
	})
}

func (s *Server) handleDevKeyDelete(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.requireDevKeys(w, r)
	if !ok {
		return
	}

	var req devKeyDeleteReq
	if !decodeJSONBody(w, r, &req) {
		return
	}

	appID := strings.TrimSpace(req.AppID)
	if appID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "appId is required",
		})
		return
	}

	if err := snap.Manager.Delete(r.Context(), appID); err != nil {
		status := devKeyHTTPStatus(err)

		msg := "failed to delete developer key"
		if errors.Is(err, devkeys.ErrNotFound) {
			msg = "developer key not found"
		} else if errors.Is(err, devkeys.ErrInvalidInput) {
			msg = "invalid input"
		}

		writeJSON(w, status, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: msg,
			"details":    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK: true,
	})
}

func (s *Server) handleDeveloperKeyExport(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.requireDevKeys(w, r)
	if !ok {
		return
	}

	var req developerKeyExportReq
	if !decodeJSONBody(w, r, &req) {
		return
	}

	appID := strings.TrimSpace(req.AppID)
	if appID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "appId is required",
		})
		return
	}

	if !req.Confirm {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "confirm is required to export the private key",
		})
		return
	}

	privB64, err := snap.Manager.ExportPrivateKey(r.Context(), appID)
	if err != nil {
		switch {
		case errors.Is(err, devkeys.ErrInvalidInput):
			writeJSON(w, http.StatusBadRequest, map[string]any{
				JSONKeyOK:    false,
				JSONKeyError: "invalid appId",
			})
			return

		case errors.Is(err, devkeys.ErrNotFound):
			writeJSON(w, http.StatusNotFound, map[string]any{
				JSONKeyOK:    false,
				JSONKeyError: "key not found",
			})
			return

		default:
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				JSONKeyOK:    false,
				JSONKeyError: "failed to export private key",
				"details":    err.Error(),
			})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK: true,
		JSONKeyData: map[string]any{
			"privateKeyB64": privB64,
		},
	})
}

// WEB3 Provider

func (s *Server) handleWalletChainId(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}

	activeChainClient, err := snap.Chains.ActiveHTTP(r.Context())
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

	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}

	activeChainClient, err := snap.Chains.ActiveHTTP(r.Context())
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
	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}

	accounts := make([]string, 0, 3)

	// EOAs always exist
	accounts = append(accounts, snap.OnChain.User.Address().Hex())
	accounts = append(accounts, snap.OnChain.Device.Address().Hex())

	// AA account: always return *something* (zero address when not deployed)
	contractAddr := common.Address{}

	if snap.OnChain.Contract != nil {
		if ca, err := snap.OnChain.ContractAddress(); err == nil && ca != (common.Address{}) {
			contractAddr = ca
		} else if addr := strings.TrimSpace(snap.OnChain.Contract.Address); addr != "" {
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
	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}

	activeChainClient, err := snap.Chains.ActiveHTTP(r.Context())
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

	network, err := snap.Chains.ResolveNetworkByChainIDHex(want)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{JSONKeyNotAdded: true})
		return
	}

	if err := snap.Chains.SwitchChain(s.ctx, network.NetworkName); err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletSwitchNetworkFailedText, err.Error())
		return
	}

	if snap.Chains != nil {
		_ = snap.OnChain.ValidateChain(r.Context())
		if err := snap.OnChain.LoadContractForCurrentChain(r.Context(), snap.CWStore); err != nil {
			log.Error("failed to load contract wallet store after switch", "err", err)
		}
	}

	if snap.Assets != nil {
		defaultAssets := s.cfg.DefaultAssets.Network[network.NetworkName]

		if err := snap.Assets.EnsureStoreForNetwork(r.Context(), network.NetworkName, defaultAssets); err != nil {
			log.Error("failed to ensure store for network", "network", network.NetworkName, "err", err)
			writeRPCError(w, http.StatusOK, JSONRPCErrorCodeInternalError, WalletFailedToLoadAssetsText, err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{JSONKeyOK: true})
}

func (s *Server) handleWalletSendTransaction(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}

	var req SendTxRequest
	if !decodeJSONBodyRPC(w, r, &req) {
		return
	}

	txReq, err := toTxRequest(req)
	if err != nil {
		writeRPCError(
			w,
			http.StatusBadRequest,
			JSONRPCErrorCodeInvalidParams,
			"invalid transaction",
			err.Error(),
		)
		return
	}
	activeEthClient, err := snap.Chains.ActiveHTTP(r.Context())
	if err != nil {
		writeRPCError(
			w,
			http.StatusInternalServerError,
			JSONRPCErrorCodeInternalError,
			"no active eth client",
			err.Error(),
		)
		return

	}

	txSender := snap.TxSender.NewTxSender(activeEthClient)
	txHash, err := txSender.Send(r.Context(), txReq)
	if err != nil {
		writeRPCError(
			w,
			http.StatusInternalServerError,
			JSONRPCErrorCodeInternalError,
			"transaction failed",
			err.Error(),
		)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"txHash": txHash.Hex(),
	})
}

func (s *Server) handleWalletEstimateSendTransaction(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}

	var req SendTxRequest
	if !decodeJSONBodyRPC(w, r, &req) {
		return
	}

	// Parse/normalize inputs
	from := common.HexToAddress(req.Tx.From)

	toPtr, err := parseAddressPtr(req.Tx.To)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidParams, "invalid tx.to", err.Error())
		return
	}

	value, err := parseHexBigInt(req.Tx.Value)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidParams, "invalid tx.value", err.Error())
		return
	}

	data, err := parseHexData(req.Tx.Data)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidParams, "invalid tx.data", err.Error())
		return
	}

	// Parse optional EIP-1559 fee caps from request (hex string -> *big.Int)
	maxFee, err := parseHexBigInt(req.Tx.MaxFeePerGas)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidParams, "invalid tx.maxFeePerGas", err.Error())
		return
	}
	maxPrio, err := parseHexBigInt(req.Tx.MaxPriorityFeePerGas)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidParams, "invalid tx.maxPriorityFeePerGas", err.Error())
		return
	}
	// treat zero as “unset”
	if maxFee != nil && maxFee.Sign() == 0 {
		maxFee = nil
	}
	if maxPrio != nil && maxPrio.Sign() == 0 {
		maxPrio = nil
	}

	activeEthClient, err := snap.Chains.ActiveHTTP(r.Context())
	if err != nil {
		writeRPCError(
			w,
			http.StatusInternalServerError,
			JSONRPCErrorCodeInternalError,
			"no active eth client",
			err.Error(),
		)
		return

	}

	txSender := snap.TxSender.NewTxSender(activeEthClient)

	eoaEst, aaEst, err := txSender.Estimate(r.Context(), txsender.TxRequest{
		From:                 from,
		To:                   toPtr,
		Value:                value,
		Data:                 data,
		MaxFeePerGas:         maxFee,
		MaxPriorityFeePerGas: maxPrio,
	})
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "estimate failed", err.Error())
		return
	}

	// Decide response format (keep same JSON shape you already had)
	if aaEst != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"type": "aa",

			"maxPriorityFeePerGasWei": aaEst.MaxPriorityFeePerGasWei.String(),
			"maxFeePerGasWei":         aaEst.MaxFeePerGasWei.String(),

			"callGasLimit":         aaEst.CallGasLimit.String(),
			"verificationGasLimit": aaEst.VerificationGasLimit.String(),
			"preVerificationGas":   aaEst.PreVerificationGas.String(),

			"accountGasLimitsHex": aaEst.AccountGasLimitsHex,
			"gasFeesHex":          aaEst.GasFeesHex,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"type": "eoa",
		"gas":  eoaEst.GasLimit,

		"maxPriorityFeePerGasWei": eoaEst.MaxPriorityFeePerGasWei.String(),
		"maxFeePerGasWei":         eoaEst.MaxFeePerGasWei.String(),
	})
}

func (s *Server) handleWalletPersonalSign(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.requireWeb3(w, r)
	if !ok {
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

	res, err := snap.WalletSigner.PersonalSign(r.Context(), walletsigner.PersonalSignRequest{
		Address: addr,
		Message: req.Message,
	})

	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{JSONKeyUnauthorized: true})
		return
	}

	sigHex, err := walletsigner.SigToHex(res.Signature)
	if err != nil {
		writeRPCError(w, http.StatusOK, JSONRPCErrorCodeInternalError, WalletSignFailedText, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"signature": sigHex})
}

func (s *Server) handleWalletSignTypedDataV4(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.requireWeb3(w, r)
	if !ok {
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

	res, err := snap.WalletSigner.SignTypedDataV4(r.Context(), walletsigner.SignTypedDataV4Request{
		Address:       addr,
		TypedDataJSON: req.TypedDataJson,
	})
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{JSONKeyUnauthorized: true})
		return
	}

	sigHex, err := walletsigner.SigToHex(res.Signature)
	if err != nil {
		writeRPCError(w, http.StatusOK, JSONRPCErrorCodeInternalError, WalletSignFailedText, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"signature": sigHex})
}

func (s *Server) handleWalletRPC(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}
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
		resultHex, err := snap.RPC.EthGetBalance(r.Context(), req.Params)
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
	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}

	activeChainClient, err := snap.Chains.ActiveHTTP(r.Context())
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "no active chain", err.Error())
		return
	}

	chainID, err := activeChainClient.ChainID(r.Context())
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletChainIDFetchFailedText, err.Error())
		return
	}
	network, _ := snap.Chains.ResolveNetworkByChainID(chainID.Uint64())

	cryptoAssets := []assetOut{}
	if snap.Assets != nil && network.NetworkName != "" {
		contractAddr, _ := snap.OnChain.ContractAddress()

		list, err := snap.Assets.ListForNetwork(r.Context(), network.NetworkName)
		if err != nil {
			writeRPCError(w, http.StatusOK, JSONRPCErrorCodeInternalError, WalletAssetsLoadFailedText, err.Error())
			return
		}

		for _, as := range list {
			if strings.EqualFold(as.Address, common.HexToAddress(constants.NativeAddr).Hex()) {
				weiDec, err := snap.Auth.GetBalanceWeiDecimal(r.Context(), activeChainClient, contractAddr)
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

			balWei, err := snap.Assets.BalanceOf(r.Context(), network.NetworkName, common.HexToAddress(as.Address), contractAddr)
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

	err = snap.OnChain.LoadContractForCurrentChain(s.ctx, snap.CWStore)
	if err != nil {
		return
	}

	accts := []acctIn{
		{Addr: snap.OnChain.User.Address(), Role: "user (EOA)"},
		{Addr: snap.OnChain.Device.Address(), Role: "device (TPM)"},
	}

	// Always return the AA contract row (zero address when not deployed)
	contractAddr := common.Address{}

	if snap.OnChain.Contract != nil {
		if ca, err := snap.OnChain.ContractAddress(); err == nil && ca != (common.Address{}) {
			contractAddr = ca
		} else if addr := strings.TrimSpace(snap.OnChain.Contract.Address); addr != "" {
			contractAddr = common.HexToAddress(addr)
		}
	}

	accts = append(accts, acctIn{Addr: contractAddr, Role: "contract"})

	out := make([]acctOut, 0, len(accts))
	for _, a := range accts {
		weiDec, err := snap.Auth.GetBalanceWeiDecimal(r.Context(), activeChainClient, a.Addr)
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
	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}

	var req shared.NetworkMetadataReq
	if !decodeJSONBody(w, r, &req) {
		return
	}

	ctx := r.Context()

	meta, err := snap.Networks.ProbeRPC(ctx, req.RpcUrl)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: err.Error(),
		})
		return
	}

	meta = snap.Networks.EnrichByChain(ctx, meta)

	writeJSON(w, http.StatusOK, map[string]any{
		JSONKeyOK:   true,
		JSONKeyData: meta,
	})
}

func (s *Server) handleWalletNetworks(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}

	activeChainClient, err := snap.Chains.ActiveHTTP(r.Context())
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "no active chain", err.Error())
		return
	}

	currentChainID, err := activeChainClient.ChainID(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	nets, err := snap.Networks.ListFromFile(r.Context())
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
	snap, ok := s.requireWeb3(w, r)
	if !ok {
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

	netInfo, found, err := snap.Networks.FindByChainIdHex(r.Context(), wantHex)
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

	if err := snap.Chains.SwitchChain(r.Context(), netInfo.Name); err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	if snap.OnChain != nil {
		_ = snap.OnChain.ValidateChain(r.Context())
	}

	writeJSON(w, http.StatusOK, map[string]any{JSONKeyOK: true})
}

func (s *Server) handleDeployContractOnChain(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}

	if snap.Deployer == nil {
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

	res, err := snap.Deployer.DeployAAOnChainIDHex(r.Context(), req.ChainIDHex, req.RecoveryAddress)
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
	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}

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

	added, err := snap.Networks.AddNetwork(ctx, networkConfig)
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
	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}

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

	if err := snap.Networks.RemoveNetworkByChainIdHex(ctx, chainIdHex); err != nil {
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
	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}
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

	updated, err := snap.Networks.UpdateNetworkByChainIdHex(ctx, chainIdHex, req.Patch)
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
	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}

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
	if err := snap.Assets.EnsureStoreForNetwork(ctx, network, defaultAddrs); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			JSONKeyOK:    false,
			JSONKeyError: "failed to load assets store",
			"details":    err.Error(),
		})
		return
	}

	list, err := snap.Assets.ListForNetwork(ctx, network)
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
	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}

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

	asset, err := snap.Assets.AddAsset(s.ctx, network, address)
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
	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}
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

	if err := snap.Assets.RemoveAsset(ctx, network, address); err != nil {
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
	snap, ok := s.requireWeb3(w, r)
	if !ok {
		return
	}
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

	asset, err := snap.Assets.FetchAsset(ctx, network, address)
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

func toTxRequest(req SendTxRequest) (txsender.TxRequest, error) {
	if strings.TrimSpace(req.Tx.From) == "" {
		return txsender.TxRequest{}, fmt.Errorf("tx.from is required")
	}

	if !common.IsHexAddress(req.Tx.From) {
		return txsender.TxRequest{}, fmt.Errorf("invalid from address %q", req.Tx.From)
	}
	from := common.HexToAddress(req.Tx.From)

	to, err := parseAddressPtr(req.Tx.To)
	if err != nil {
		return txsender.TxRequest{}, err
	}

	value, err := parseHexBigInt(req.Tx.Value)
	if err != nil {
		return txsender.TxRequest{}, err
	}
	if value == nil {
		value = big.NewInt(0)
	}

	data := common.FromHex(strings.TrimSpace(req.Tx.Data))

	// Optional fee overrides (if you support them)
	var maxFee, maxPrio *big.Int
	if req.Tx.MaxFeePerGas != "" {
		maxFee, err = parseHexBigInt(req.Tx.MaxFeePerGas)
		if err != nil {
			return txsender.TxRequest{}, fmt.Errorf("invalid maxFeePerGas: %w", err)
		}
	}
	if req.Tx.MaxPriorityFeePerGas != "" {
		maxPrio, err = parseHexBigInt(req.Tx.MaxPriorityFeePerGas)
		if err != nil {
			return txsender.TxRequest{}, fmt.Errorf("invalid maxPriorityFeePerGas: %w", err)
		}
	}

	return txsender.TxRequest{
		From:                 from,
		To:                   to,
		Value:                value,
		Data:                 data,
		MaxFeePerGas:         maxFee,
		MaxPriorityFeePerGas: maxPrio,
	}, nil
}
