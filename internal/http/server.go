package http

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	entrypoint "github.com/quantumauth-io/quantum-auth-client/internal/contracts/bindings/go/entrypoint"
	"github.com/quantumauth-io/quantum-auth-client/internal/contracts/bindings/go/quantumauthaccount"
	"github.com/quantumauth-io/quantum-auth-client/internal/eth"
	"github.com/quantumauth-io/quantum-auth-client/internal/ethwallet/contractwallet"
	"github.com/quantumauth-io/quantum-auth-client/internal/login"
	"github.com/quantumauth-io/quantum-auth-client/internal/pairing"
	"github.com/quantumauth-io/quantum-auth-client/internal/qa"
	utilsEth "github.com/quantumauth-io/quantum-go-utils/ethrpc"
	"github.com/quantumauth-io/quantum-go-utils/log"
)

const extensionPairHeader = "X-QA-Extension"
const agentSessionHeader = "X-QA-Session"

const (
	ModeNormal   uint8 = 0
	ModeRecovery uint8 = 1
)

type Server struct {
	qaClient   *qa.Client
	authClient *login.QAClientLoginService
	mux        *http.ServeMux
	ethClient  *utilsEth.Client

	agentSessionToken string
	uiAllowedOrigins  map[string]struct{}

	perms            *PermissionStore
	pairingTokenPath string

	pairings   map[string]*Pairing
	pairingsMu sync.Mutex
	ctx        context.Context
	onChain    *contractwallet.Runtime
	ethCfg     *utilsEth.MultiConfig
}

func NewServer(ctx context.Context, qaClient *qa.Client, authState *login.QAClientLoginService, uiAllowedOrigins []string,
	ethClient *utilsEth.Client, onChain *contractwallet.Runtime, ethCfg *utilsEth.MultiConfig) (http.Handler, error) {
	s := &Server{
		ctx:        ctx,
		qaClient:   qaClient,
		authClient: authState,
		mux:        http.NewServeMux(),
		pairings:   make(map[string]*Pairing),
		ethClient:  ethClient,
		onChain:    onChain,
		ethCfg:     ethCfg,
	}

	// ---- init allowlist storage ----
	permPath, err := permissionsFilePath()
	if err != nil {
		return nil, err
	}
	s.perms = NewPermissionStore(permPath)
	if err := s.perms.Load(); err != nil {
		return nil, err
	}

	// ---- init pairing token path ----
	ptPath, err := pairingTokenFilePath()
	if err != nil {
		return nil, err
	}
	s.pairingTokenPath = ptPath

	// Agent Token and Allowed Origin
	token, err := newSessionToken()
	if err != nil {
		return nil, err
	}
	s.agentSessionToken = token
	s.uiAllowedOrigins = make(map[string]struct{}, len(uiAllowedOrigins))
	for _, o := range uiAllowedOrigins {
		o = normalizeOrigin(o)
		if o == "" {
			continue
		}
		s.uiAllowedOrigins[o] = struct{}{}
	}
	// CORS for local UI (Vite) but no token required
	localUICors := corsPolicy{
		allowedOrigins: s.uiAllowedOrigins,
		allowMethods:   "GET,OPTIONS",
		allowHeaders:   "", // echo requested
		maxAge:         600,
	}

	// Agent UI Endpoint
	s.mux.HandleFunc("/healthz", s.withCORS(localUICors, s.withLoopbackOnly(s.handleHealth)))
	s.mux.HandleFunc("/status", s.withCORS(localUICors, s.withLoopbackOnly(s.handleStatus)))

	pairCors := corsPolicy{
		allowedOrigins: s.uiAllowedOrigins,
		allowMethods:   "POST,OPTIONS",
		allowHeaders:   "", // echo
		maxAge:         600,
	}

	// initial load of agent UI
	s.mux.HandleFunc("/pair/exchange", s.withCORS(pairCors, s.withLoopbackOnly(s.handleTokenPair)))

	// agent pairing and status
	s.mux.HandleFunc("/agent/extension/pair", s.withAgentGuards(s.handleAgentExtensionPair))
	s.mux.HandleFunc("/agent/extension/status", s.withAgentGuards(s.handleAgentExtensionStatus))
	s.mux.HandleFunc("/agent/session/validate", s.withAgentGuards(s.handleAgentSessionValidate))

	// Challenge endpoint to authenticate on third party apps
	s.mux.HandleFunc("/extension/auth", s.withExtensionPairedGuards(s.handleExtensionAuth))

	// Extension management (paired extension only)
	s.mux.HandleFunc("/extension/permissions", s.withExtensionPairedGuards(s.handleGetPermissions))
	s.mux.HandleFunc("/extension/permissions/status", s.withExtensionPairedGuards(s.handleGetPermissionStatus))
	s.mux.HandleFunc("/extension/permissions/set", s.withExtensionPairedGuards(s.handleSetPermission))

	// extension ethwallet endpoint (paired extension only)
	s.mux.HandleFunc("/wallet/chainId", s.withExtensionPairedGuards(s.handleWalletChainId))
	s.mux.HandleFunc("/wallet/accounts", s.withExtensionPairedGuards(s.handleWalletAccounts))
	s.mux.HandleFunc("/wallet/switchChain", s.withExtensionPairedGuards(s.handleWalletSwitchChain))
	s.mux.HandleFunc("/wallet/sendTransaction", s.withExtensionPairedGuards(s.handleWalletSendTransaction))
	s.mux.HandleFunc("/wallet/personalSign", s.withExtensionPairedGuards(s.handleWalletPersonalSign))
	s.mux.HandleFunc("/wallet/signTypedDataV4", s.withExtensionPairedGuards(s.handleWalletSignTypedDataV4))
	s.mux.HandleFunc("/wallet/rpc", s.withExtensionPairedGuards(s.handleWalletRPC))

	s.mux.HandleFunc("/wallet/accounts/summary", s.withExtensionPairedGuards(s.handleWalletAccountsSummary))
	s.mux.HandleFunc("/wallet/networks", s.withExtensionPairedGuards(s.handleWalletNetworks))
	s.mux.HandleFunc("/wallet/network", s.withExtensionPairedGuards(s.handleWalletSetNetwork))

	// agent-only endpoints (UI)
	s.mux.HandleFunc("/agent/status", s.withAgentGuards(s.handleAgentStatus))
	s.mux.HandleFunc("/agent/guardian/sign-register", s.withAgentGuards(s.handleAgentSignRegister))
	s.mux.HandleFunc("/agent/guardian/sign-withdraw", s.withAgentGuards(s.handleAgentSignWithdraw))

	// generate a pair code for the extension
	pairID := uuid.NewString()
	pairCode, err := pairing.GeneratePairCode()
	if err != nil {
		return nil, err
	}

	s.pairingsMu.Lock()
	s.pairings[pairID] = &Pairing{
		CodeHash:  pairing.HashCode(pairCode),
		ExpiresAt: time.Now().Add(60 * time.Second),
		Token:     s.agentSessionToken,
	}
	s.pairingsMu.Unlock()

	pairURL := fmt.Sprintf(
		"http://127.0.0.1:6137/#/?server=%s&pair_id=%s&code=%s",
		url.QueryEscape("http://127.0.0.1:6137"),
		url.QueryEscape(pairID),
		url.QueryEscape(pairCode),
	)

	log.Info("pair with agent UI", "url", pairURL)
	// attach UI LAST
	if err = s.AttachUI(); err != nil {
		return nil, err
	}
	return s, nil
}

// ServeHTTP implements http.Handler
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// GUARDS (Middleware)
func (s *Server) withCORS(policy corsPolicy, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		originRaw := r.Header.Get("Origin")
		if originRaw != "" {
			origin := normalizeOrigin(originRaw)
			if origin == "" {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}

			// enforce allowlist if provided
			if policy.allowedOrigins != nil {
				if _, ok := policy.allowedOrigins[origin]; !ok {
					http.Error(w, "forbidden origin", http.StatusForbidden)
					return
				}
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			if policy.allowMethods != "" {
				w.Header().Set("Access-Control-Allow-Methods", policy.allowMethods)
			}

			// Echo browser-requested headers by default (most robust)
			if policy.allowHeaders != "" {
				w.Header().Set("Access-Control-Allow-Headers", policy.allowHeaders)
			} else if reqHdrs := r.Header.Get("Access-Control-Request-Headers"); reqHdrs != "" {
				w.Header().Set("Access-Control-Allow-Headers", reqHdrs)
			}

			if policy.maxAge > 0 {
				w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", policy.maxAge))
			}
		}

		// Preflight ends here
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next(w, r)
	}
}

func (s *Server) withAgentGuards(next http.HandlerFunc) http.HandlerFunc {
	// Agent UI is browser-based, so enforce allowed origins from config.
	cors := corsPolicy{
		allowedOrigins: s.uiAllowedOrigins,
		allowMethods:   "GET,POST,OPTIONS",
		// echo Access-Control-Request-Headers so X-QA-Session casing never breaks
		allowHeaders: "",
		maxAge:       600,
	}

	return s.withCORS(cors, func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackRequest(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		receivedToken := r.Header.Get(agentSessionHeader)

		// Auth required only for real requests (preflight is handled in withCORS)
		if receivedToken != s.agentSessionToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if !isSafeLocalHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}

		next(w, r)
	})
}

func (s *Server) withLoopbackOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackRequest(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *Server) withExtensionLocalGuards(next http.HandlerFunc) http.HandlerFunc {
	extCors := corsPolicy{
		allowedOrigins: nil, // allow any valid Origin (extension has unique origin)
		allowMethods:   "POST,OPTIONS",
		allowHeaders:   "", // echo requested headers
		maxAge:         600,
	}

	return s.withCORS(extCors, func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackRequest(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !isSafeLocalHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// For endpoints that *change or reveal* permissions: require paired extension token.
func (s *Server) withExtensionPairedGuards(next http.HandlerFunc) http.HandlerFunc {
	extCors := corsPolicy{
		allowedOrigins: nil,
		allowMethods:   "GET,POST,OPTIONS",
		allowHeaders:   "", // echo (covers X-QA-Extension)
		maxAge:         600,
	}

	return s.withCORS(extCors, func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackRequest(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !isSafeLocalHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}

		token, err := loadPairingToken(s.pairingTokenPath)
		if err != nil {
			http.Error(w, "extension not paired", http.StatusPreconditionRequired)
			return
		}

		if got := r.Header.Get(extensionPairHeader); got == "" || got != token {
			log.Info("extension paired guards", "token", token, "got", got)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	})
}

// HANDLERS
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAgentSessionValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"valid": true,
	})
}

func (s *Server) handleAgentExtensionStatus(w http.ResponseWriter, r *http.Request) {
	paired := false
	if _, err := loadPairingToken(s.pairingTokenPath); err == nil {
		paired = true
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"paired": paired,
	})
}

func (s *Server) handleAgentExtensionPair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// generate fresh token each time (you can change policy later)
	token, err := newSessionToken()
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	// ensure pairingTokenPath is set
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
		PairingTokenPath: s.pairingTokenPath, // optional, helpful for debugging
	})
}

func (s *Server) handleAgentStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type resp struct {
		OK       bool   `json:"ok"`
		LoggedIn bool   `json:"loggedIn"`
		UserID   string `json:"userId,omitempty"`
		DeviceID string `json:"deviceId,omitempty"`
	}

	out := resp{OK: true}
	if s.authClient != nil && s.authClient.State != nil {
		out.LoggedIn = true
		out.UserID = s.authClient.State.UserID
		out.DeviceID = s.authClient.State.DeviceID
	}

	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAgentSignRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, signResp{Signature: "0xTODO"})
}

func (s *Server) handleAgentSignWithdraw(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, signResp{Signature: "0xTODO"})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleExtensionAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var extReq extensionRequest

	if err := json.NewDecoder(r.Body).Decode(&extReq); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	switch extReq.Action {
	case "ping":
		writeJSON(w, http.StatusOK, extensionResponse{
			OK:   true,
			Data: map[string]string{"message": "pong"},
		})

	case "request_challenge":
		s.handleRequestChallenge(w, r.Context(), extReq)

	default:
		writeJSON(w, http.StatusBadRequest, extensionResponse{
			OK:    false,
			Error: "unknown action",
		})
	}
}

func (s *Server) handleRequestChallenge(w http.ResponseWriter, ctx context.Context, extReq extensionRequest) {
	if s.authClient == nil || s.authClient.State == nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{
			OK:    false,
			Error: "auth state not initialised",
		})
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

	// Enforce allowlist
	if s.perms == nil || !s.perms.IsAllowed(origin) {
		writeJSON(w, http.StatusOK, extensionResponse{
			OK:    false,
			Error: "approval_required",
			Data: map[string]any{
				"origin":  origin,
				"allowed": false,
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
			"qaProof": signedHeaders,
			"origin":  origin,
		},
	})
}

func (s *Server) handleGetPermissions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, extensionResponse{
		OK: true,
		Data: map[string]any{
			"allowed": s.perms.List(),
		},
	})
}

func (s *Server) handleGetPermissionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	origin := normalizeOrigin(r.URL.Query().Get("origin"))

	if origin == "" {
		writeJSON(w, http.StatusBadRequest, extensionResponse{OK: false, Error: "missing/invalid origin"})
		return
	}
	writeJSON(w, http.StatusOK, extensionResponse{
		OK: true,
		Data: map[string]any{
			"origin":  origin,
			"allowed": s.perms.IsAllowed(origin),
		},
	})
}

func (s *Server) handleSetPermission(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req setPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
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
			"origin":  origin,
			"allowed": req.Allowed,
		},
	})
}

func (s *Server) handleTokenPair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req pairExchangeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	req.PairID = strings.TrimSpace(req.PairID)
	req.Code = strings.TrimSpace(req.Code)
	if req.PairID == "" || req.Code == "" {
		http.Error(w, "missing pair_id or code", http.StatusBadRequest)
		return
	}

	now := time.Now()

	s.pairingsMu.Lock()
	// cleanup
	for id, p := range s.pairings {
		if p == nil || now.After(p.ExpiresAt) {
			delete(s.pairings, id)
		}
	}

	p, ok := s.pairings[req.PairID]
	if !ok || p == nil || p.Used || now.After(p.ExpiresAt) {
		s.pairingsMu.Unlock()
		http.Error(w, "pair expired", http.StatusGone)
		return
	}

	got := sha256.Sum256([]byte(req.Code))
	want := p.CodeHash
	if len(want) != sha256.Size || subtle.ConstantTimeCompare(want, got[:]) != 1 {
		s.pairingsMu.Unlock()
		http.Error(w, "invalid code", http.StatusUnauthorized)
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

// WALLET ENDPOINT

func (s *Server) handleWalletChainId(w http.ResponseWriter, r *http.Request) {
	chainIDHex, err := s.ethClient.ChainIDHex(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{
			OK:    false,
			Error: err.Error(),
		})
		return
	}

	// Match what your extension rpcRouter expects: r.chainIdHex
	writeJSON(w, http.StatusOK, map[string]any{
		"chainIdHex": chainIDHex,
	})
}

func (s *Server) handleWalletAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRPCError(w, http.StatusMethodNotAllowed, -32601, "method not allowed", nil)
		return
	}
	if s.onChain == nil || s.onChain.User == nil || s.onChain.Device == nil {
		writeRPCError(w, http.StatusInternalServerError, -32603, "wallet runtime not initialized", nil)
		return
	}

	// You can honor req.Silent/Prompt later. For now: return addresses we control.
	accounts := []string{
		//s.onChain.User.Address().Hex(),
		//s.onChain.Device.Address().Hex(),
		s.onChain.Contract.Address,
	}

	// Add contract account if configured (optional)
	if s.onChain.Contract != nil {
		if ca, err := s.onChain.ContractAddress(); err == nil {
			accounts = append(accounts, ca.Hex())
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"accounts": accounts})
}

func (s *Server) handleWalletSwitchChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRPCError(w, http.StatusMethodNotAllowed, -32601, "method not allowed", nil)
		return
	}

	var req walletSwitchChainReq
	log.Info("switching chain", "id", req.ChainIDHex)
	if err := readJSONBody(r, &req); err != nil {
		writeRPCError(w, http.StatusBadRequest, -32600, "invalid request", err.Error())
		return
	}

	want := strings.TrimSpace(req.ChainIDHex)
	if want == "" {
		writeRPCError(w, http.StatusBadRequest, -32600, "missing chainIdHex", nil)
		return
	}

	// Already on this chain? success.
	got, err := s.ethClient.ChainIDHex(r.Context())
	if err == nil && strings.EqualFold(utilsEth.NormalizeHex0x(got), utilsEth.NormalizeHex0x(want)) {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}

	networkName, err := eth.NetworkNameForChainIDHex(s.ethCfg, want)
	if err != nil {
		// Extension expects "notAdded" semantics
		writeJSON(w, http.StatusOK, map[string]any{
			"notAdded": true,
		})
		return
	}

	log.Info("switching chain", "chain", want, "network", networkName)
	if err := s.ethClient.UseNetwork(networkName); err != nil {
		writeRPCError(w, http.StatusOK, -32603, "failed to switch network", err.Error())
		return
	}

	// Keep onChain runtime on the same RPC client instance.
	// (This assumes onChain.Eth == s.ethClient; ensure you constructed it that way.)
	if s.onChain != nil {
		// If you have a contract configured, it might be for a different chain.
		// ValidateChain returns ErrContractNotConfigured if nil; ignore.
		_ = s.onChain.ValidateChain(r.Context())
	}

	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleWalletSendTransaction(w http.ResponseWriter, r *http.Request) {

	netCfg, ok := s.ethCfg.Networks[s.ethCfg.ActiveNetwork]
	if !ok {
		writeRPCError(w, http.StatusInternalServerError, -32603, "active network not found", nil)
		return
	}
	if strings.TrimSpace(netCfg.EntryPoint) == "" {
		writeRPCError(w, http.StatusInternalServerError, -32603, "entryPoint not configured", nil)
		return
	}
	entryPointAddr := common.HexToAddress(netCfg.EntryPoint)

	log.Info("entrypoint", "address", entryPointAddr)

	ep, err := entrypoint.NewEntryPoint(entryPointAddr, s.ethClient.Backend())
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, -32603, "bind entrypoint failed", err.Error())
		return
	}

	var req SendTxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeRPCError(w, http.StatusBadRequest, -32602, "bad request", err.Error())
		return
	}

	sender := common.HexToAddress(req.Tx.From)
	to := common.HexToAddress(req.Tx.To)

	value := new(big.Int)
	if req.Tx.Value != "" && req.Tx.Value != "0x" {
		value.SetString(strings.TrimPrefix(req.Tx.Value, "0x"), 16)
	}

	data := common.FromHex(req.Tx.Data)

	accABI, err := quantumauthaccount.QuantumAuthAccountMetaData.GetAbi()
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, -32603, "account abi failed", err.Error())
		return
	}

	callData, err := accABI.Pack("execute", to, value, data)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, -32603, "pack execute failed", err.Error())
		return
	}

	nonce, err := ep.GetNonce(&bind.CallOpts{Context: r.Context()}, sender, big.NewInt(0))
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, -32603, "getNonce failed", err.Error())
		return
	}

	callGas := big.NewInt(250_000)
	verificationGas := big.NewInt(700_000)
	maxPriorityFee := big.NewInt(1_500_000_000) // 1.5 gwei
	maxFee := big.NewInt(30_000_000_000)        // 30 gwei (temporary)

	userOp := entrypoint.PackedUserOperation{
		Sender:             sender,
		Nonce:              nonce,
		InitCode:           []byte{},
		CallData:           callData,
		AccountGasLimits:   packU128Pair(callGas, verificationGas),
		PreVerificationGas: big.NewInt(60_000),
		GasFees:            packU128Pair(maxPriorityFee, maxFee),
		PaymasterAndData:   []byte{},
		Signature:          []byte{},
	}

	deviceAddr := s.onChain.Device.Address() // or however you expose it
	log.Info("device address", "addr", deviceAddr.Hex())

	acct, err := quantumauthaccount.NewQuantumAuthAccount(sender, s.ethClient.Backend())
	if err != nil { /* handle */
	}

	keyId, err := acct.TpmKeyId(&bind.CallOpts{Context: r.Context()})
	if err != nil { /* handle */
	}

	// expected address = low 20 bytes
	expected := common.BytesToAddress(keyId[12:]) // bytes32 -> address
	log.Info("tpmKeyId expected signer", "addr", expected.Hex())

	epOnChain, _ := acct.EntryPoint(&bind.CallOpts{Context: r.Context()})
	log.Info("entrypoint compare", "cfg", entryPointAddr.Hex(), "account", epOnChain.Hex())

	userOpHash, err := ep.GetUserOpHash(&bind.CallOpts{Context: r.Context()}, userOp)
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, -32603, "getUserOpHash failed", err.Error())
		return
	}

	sig, err := s.signUserOpHash(r.Context(), userOpHash[:])
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, -32603, "signing failed", err.Error())
		return
	}

	userOp.Signature = sig

	auth, beneficiary, err := s.relayerAuth(r.Context())
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, -32603, "tx auth failed", err.Error())
		return
	}

	log.Info("userOp",
		"sender", userOp.Sender.Hex(),
		"nonce", userOp.Nonce.String(),
		"callDataLen", len(userOp.CallData),
		"sigLen", len(userOp.Signature),
	)

	mode, sig1, sig2, tpmSig, rec1, err := debugQuantumAuthSig(userOpHash, userOp.Signature)
	if err != nil {
		log.Error("sig debug failed", "err", err)
	} else {
		log.Info("sig debug",
			"mode", mode,
			"sig1Len", len(sig1),
			"sig2Len", len(sig2),
			"tpmSigLen", len(tpmSig),
			"recoveredSig1", rec1.Hex(),
		)
	}

	tx, err := ep.HandleOps(auth, []entrypoint.PackedUserOperation{userOp}, beneficiary)
	if err != nil {
		log.Error("handleOps failed", "tx", tx, "err", err)
		writeRPCError(w, http.StatusInternalServerError, -32603, "handleOps failed", err.Error())
		return
	}
	log.Info("handleOps sent", "txHash", tx.Hash().Hex())

	writeJSON(w, http.StatusOK, map[string]any{
		"txHash": tx.Hash().Hex(),
	})

}

func (s *Server) handleWalletPersonalSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRPCError(w, http.StatusMethodNotAllowed, -32601, "method not allowed", nil)
		return
	}
	if s.onChain == nil {
		writeRPCError(w, http.StatusInternalServerError, -32603, "wallet runtime not initialized", nil)
		return
	}

	var req walletPersonalSignReq
	if err := readJSONBody(r, &req); err != nil {
		writeRPCError(w, http.StatusBadRequest, -32600, "invalid request", err.Error())
		return
	}

	addr, err := parseAddr(req.Address)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, -32602, "invalid address", err.Error())
		return
	}

	wallet, err := s.pickWallet(addr)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"unauthorized": true})
		return
	}

	msgBytes, err := parsePersonalSignMessage(req.Message)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, -32602, "invalid message", err.Error())
		return
	}

	digest := eip191HashPersonalMessage(msgBytes)
	sig, err := wallet.SignHash(r.Context(), digest)
	if err != nil {
		writeRPCError(w, http.StatusOK, -32603, "sign failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"signature": sigToHex(sig), // V=0/1
	})
}

func (s *Server) handleWalletSignTypedDataV4(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRPCError(w, http.StatusMethodNotAllowed, -32601, "method not allowed", nil)
		return
	}
	if s.onChain == nil {
		writeRPCError(w, http.StatusInternalServerError, -32603, "wallet runtime not initialized", nil)
		return
	}

	var req walletSignTypedDataReq
	if err := readJSONBody(r, &req); err != nil {
		writeRPCError(w, http.StatusBadRequest, -32600, "invalid request", err.Error())
		return
	}

	addr, err := parseAddr(req.Address)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, -32602, "invalid address", err.Error())
		return
	}

	wallet, err := s.pickWallet(addr)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"unauthorized": true})
		return
	}

	digest, err := eip712DigestV4(req.TypedData)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, -32602, "invalid typed data", err.Error())
		return
	}

	sig, err := wallet.SignHash(r.Context(), digest)
	if err != nil {
		writeRPCError(w, http.StatusOK, -32603, "sign failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"signature": sigToHex(sig), // V=0/1
	})
}

func (s *Server) handleWalletRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRPCError(w, http.StatusMethodNotAllowed, -32601, "method not allowed", nil)
		return
	}

	var req walletRPCReq
	if err := readJSONBody(r, &req); err != nil {
		writeRPCError(w, http.StatusBadRequest, -32600, "invalid request", err.Error())
		return
	}
	if req.Method == "" {
		writeRPCError(w, http.StatusBadRequest, -32600, "missing method", nil)
		return
	}

	// This should call your external RPC client (Sepolia) using your eth module:
	var out json.RawMessage
	if err := s.ethClient.Call(r.Context(), req.Method, req.Params, &out); err != nil {
		// Ideally return a JSON-RPC style error object
		writeJSON(w, http.StatusOK, map[string]any{
			"error": rpcErr{Code: -32603, Message: err.Error()},
		})
		return
	}

	// Return raw JSON as "result"
	var result any
	_ = json.Unmarshal(out, &result)

	writeJSON(w, http.StatusOK, map[string]any{
		"result": result,
	})
}

func (s *Server) handleWalletAccountsSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeRPCError(w, http.StatusMethodNotAllowed, -32601, "method not allowed", nil)
		return
	}
	if s.onChain == nil || s.onChain.User == nil || s.onChain.Device == nil || s.ethClient == nil {
		writeRPCError(w, http.StatusInternalServerError, -32603, "wallet runtime not initialized", nil)
		return
	}

	chainIDHex, err := s.ethClient.ChainID(r.Context())
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, -32603, "failed to get chainId", err.Error())
		return
	}

	type acctOut struct {
		Address    string `json:"address"`
		Role       string `json:"role"`
		BalanceWei string `json:"balanceWei"`
		BalanceEth string `json:"balanceEth"`
		Symbol     string `json:"symbol"`
	}

	// Define which accounts you want to expose.
	// (Match your /wallet/accounts ordering so UI stays consistent.)
	type acctIn struct {
		Addr common.Address
		Role string
	}

	accts := []acctIn{
		{Addr: s.onChain.User.Address(), Role: "user"},
		{Addr: s.onChain.Device.Address(), Role: "device"},
	}

	// Optional: contract account
	if s.onChain.Contract != nil {
		if ca, err := s.onChain.ContractAddress(); err == nil && (ca != common.Address{}) {
			accts = append(accts, acctIn{Addr: ca, Role: "contract"})
		}
	}

	out := make([]acctOut, 0, len(accts))

	for _, a := range accts {
		weiDec, err := s.getBalanceWeiDecimal(r.Context(), a.Addr)
		if err != nil {
			// fail hard (simpler); alternatively return per-account error fields
			writeRPCError(w, http.StatusOK, -32603, "failed to fetch balance", err.Error())
			return
		}

		ethStr := weiDecimalToEthString(weiDec, 6) // trim to 6 decimals for UI
		if ethStr == "" {
			ethStr = "0.0"
		}

		out = append(out, acctOut{
			Address:    a.Addr.Hex(),
			Role:       a.Role,
			BalanceWei: weiDec,
			BalanceEth: ethStr,
			Symbol:     "ETH",
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"data": map[string]any{
			"chainIdHex": chainIDHex,
			"accounts":   out,
		},
	})
}

// GET /wallet/networks
func (s *Server) handleWalletNetworks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.ethClient == nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: "eth client not initialized"})
		return
	}

	// Live chainId from current active RPC connection (the truth of where we are)
	currentChainIDHex, err := s.ethClient.ChainIDHex(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	// Configured networks (what we can switch to)
	networks := s.ethClient.SupportedNetworks()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"data": map[string]any{
			"currentChainIdHex": currentChainIDHex,
			"networks":          networks,
		},
	})
}

// POST /wallet/network  { chainIdHex: "0x..." }
func (s *Server) handleWalletSetNetwork(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.ethClient == nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: "eth client not initialized"})
		return
	}

	var req walletSetNetworkReq
	if err := readJSONBody(r, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	want := strings.TrimSpace(req.ChainIDHex)
	if want == "" {
		http.Error(w, "missing chainIdHex", http.StatusBadRequest)
		return
	}

	// Resolve chainIdHex -> configured network name (you already have this helper)
	networkName, err := eth.NetworkNameForChainIDHex(s.ethCfg, want)
	if err != nil {
		// Keep extension-friendly semantics
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":       false,
			"notAdded": true,
			"error":    err.Error(),
		})
		return
	}

	// Switch the active network (updates ActiveNetwork and ActiveRPC)
	if err := s.ethClient.UseNetwork(networkName); err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: err.Error()})
		return
	}

	// Optional: keep onChain runtime aligned
	if s.onChain != nil {
		_ = s.onChain.ValidateChain(r.Context())
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Calls JSON-RPC eth_getBalance and returns WEI as a *decimal string* (not hex).
func (s *Server) getBalanceWeiDecimal(ctx context.Context, addr common.Address) (string, error) {
	// JSON-RPC returns hex quantity string like "0x0", "0xde0b6b3a7640000"
	var out json.RawMessage
	params := []any{addr.Hex(), "latest"}

	if err := s.ethClient.Call(ctx, "eth_getBalance", params, &out); err != nil {
		return "", err
	}

	// out is a JSON string, e.g. "0x1234..."
	var hexQty string
	if err := json.Unmarshal(out, &hexQty); err != nil {
		return "", fmt.Errorf("decode eth_getBalance: %w", err)
	}

	wei, err := parseHexQuantity(hexQty)
	if err != nil {
		return "", fmt.Errorf("parse balance hex quantity: %w", err)
	}
	if wei == nil {
		return "0", nil
	}
	return wei.String(), nil
}

func (s *Server) relayerAuth(ctx context.Context) (*bind.TransactOpts, common.Address, error) {
	privKey, err := s.onChain.User.ExportPrivateKey(ctx)
	if err != nil {
		return nil, common.Address{}, err
	}
	if privKey == nil {
		return nil, common.Address{}, fmt.Errorf("exported private key is nil")
	}

	from := crypto.PubkeyToAddress(privKey.PublicKey)

	chainID, err := s.ethClient.ChainID(ctx)
	if err != nil {
		return nil, common.Address{}, err
	}

	auth := &bind.TransactOpts{
		From:    from,
		Context: ctx,
		Signer: func(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if addr != from {
				return nil, fmt.Errorf("unauthorized signer: %s", addr.Hex())
			}
			return types.SignTx(tx, types.LatestSignerForChainID(chainID), privKey)
		},
	}

	return auth, from, nil
}

func (s *Server) signUserOpHash(ctx context.Context, userOpHash []byte) ([]byte, error) {
	if len(userOpHash) != 32 {
		return nil, fmt.Errorf("userOpHash must be 32 bytes")
	}

	// --- TPM signs RAW userOpHash ---
	sigTPM, err := s.onChain.Device.SignHash(ctx, userOpHash)
	if err != nil {
		return nil, fmt.Errorf("tpm sign failed: %w", err)
	}

	// --- EOAs sign ETH-SIGNED hash ---
	ethHash := ethSignedHash(userOpHash)

	var sigEOA1, sigEOA2 []byte

	// You decide which EOA is active; example uses EOA1
	sigEOA1, err = s.onChain.User.SignHash(ctx, ethHash)
	if err != nil {
		return nil, fmt.Errorf("eoa1 sign failed: %w", err)
	}

	// Not used in MODE_NORMAL
	sigEOA2 = []byte{}

	// Normalize V if needed (OpenZeppelin expects 27/28)
	if sigEOA1[64] < 27 {
		sigEOA1[64] += 27
	}

	return packQuantumAuthSignature(
		ModeNormal,
		sigEOA1,
		sigEOA2,
		sigTPM,
	)
}

func ethSignedHash(h []byte) []byte {
	prefix := []byte("\x19Ethereum Signed Message:\n32")
	return crypto.Keccak256(prefix, h)
}

func packQuantumAuthSignature(
	mode uint8,
	sigEOA1 []byte,
	sigEOA2 []byte,
	sigTPM []byte,
) ([]byte, error) {

	args := abi.Arguments{
		{Type: abi.Type{T: abi.UintTy, Size: 8}}, // uint8
		{Type: abi.Type{T: abi.BytesTy}},         // bytes
		{Type: abi.Type{T: abi.BytesTy}},         // bytes
		{Type: abi.Type{T: abi.BytesTy}},         // bytes
	}

	return args.Pack(
		mode,
		sigEOA1,
		sigEOA2,
		sigTPM,
	)
}

func debugQuantumAuthSig(userOpHash [32]byte, sigBlob []byte) (uint8, []byte, []byte, []byte, common.Address, error) {
	// Unpack abi.encode(uint8, bytes, bytes, bytes)
	args := abi.Arguments{
		{Type: abi.Type{T: abi.UintTy, Size: 8}}, // uint8
		{Type: abi.Type{T: abi.BytesTy}},         // bytes
		{Type: abi.Type{T: abi.BytesTy}},         // bytes
		{Type: abi.Type{T: abi.BytesTy}},         // bytes
	}

	out, err := args.Unpack(sigBlob)
	if err != nil {
		return 0, nil, nil, nil, common.Address{}, fmt.Errorf("unpack sigBlob: %w", err)
	}

	mode := out[0].(uint8)
	sig1 := out[1].([]byte)
	sig2 := out[2].([]byte)
	tpmSig := out[3].([]byte)

	// Contract uses ethHash = toEthSignedMessageHash(userOpHash)
	ethHash := ethSignedHash(userOpHash[:]) // 32 bytes

	// Recover signer of sig1 (go-ethereum expects v=0/1 for SigToPub)
	recovered := common.Address{}
	if len(sig1) == 65 {
		s := make([]byte, 65)
		copy(s, sig1)
		if s[64] >= 27 { // convert 27/28 -> 0/1 for SigToPub
			s[64] -= 27
		}
		pub, err := crypto.SigToPub(ethHash, s)
		if err != nil {
			return mode, sig1, sig2, tpmSig, common.Address{}, fmt.Errorf("SigToPub(sig1): %w", err)
		}
		recovered = crypto.PubkeyToAddress(*pub)
	}

	return mode, sig1, sig2, tpmSig, recovered, nil
}

// Converts a decimal-string wei amount into an ETH string, trimming to maxDecimals.
// Example: wei="1230000000000000000" => "1.23"
func weiDecimalToEthString(weiDec string, maxDecimals int) string {
	weiDec = strings.TrimSpace(weiDec)
	if weiDec == "" {
		return ""
	}

	// Remove leading zeros (keep one if all zeros)
	weiDec = strings.TrimLeft(weiDec, "0")
	if weiDec == "" {
		return "0.0"
	}

	const ethDecimals = 18

	// If <= 18 digits, it's < 1 ETH
	if len(weiDec) <= ethDecimals {
		pad := strings.Repeat("0", ethDecimals-len(weiDec))
		frac := pad + weiDec
		frac = trimFrac(frac, maxDecimals)
		if frac == "" {
			return "0.0"
		}
		return "0." + frac
	}

	// Otherwise split integer / fractional
	intPart := weiDec[:len(weiDec)-ethDecimals]
	frac := weiDec[len(weiDec)-ethDecimals:]
	frac = trimFrac(frac, maxDecimals)
	if frac == "" {
		return intPart
	}
	return intPart + "." + frac
}

func trimFrac(frac string, maxDecimals int) string {
	if maxDecimals < 0 {
		maxDecimals = 0
	}
	if maxDecimals == 0 {
		return ""
	}
	if len(frac) > maxDecimals {
		frac = frac[:maxDecimals]
	}
	frac = strings.TrimRight(frac, "0")
	return frac
}

// TODO move the helpers out of here
func isLoopbackRequest(r *http.Request) bool {
	ra := r.RemoteAddr

	h, _, err := net.SplitHostPort(ra)
	if err != nil {
		ip := net.ParseIP(ra)
		return ip != nil && ip.IsLoopback()
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func isSafeLocalHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func normalizeOrigin(in string) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return ""
	}
	u, err := url.Parse(in)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return fmt.Sprintf("%s://%s", strings.ToLower(u.Scheme), strings.ToLower(u.Host))
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writePairingTokenFile(path string, token string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	// token stored as plain text, newline-terminated for convenience
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return fmt.Errorf("write pairing token file: %w", err)
	}
	return nil
}

func newSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}
func readJSONBody(r *http.Request, out any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func writeRPCError(w http.ResponseWriter, status int, code int, msg string, data any) {
	writeJSON(w, status, map[string]any{
		"error": rpcErr{Code: code, Message: msg, Data: data},
	})
}
