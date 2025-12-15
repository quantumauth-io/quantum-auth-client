package http

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/quantumauth-io/quantum-auth-client/internal/login"
	"github.com/quantumauth-io/quantum-auth-client/internal/pairing"
	"github.com/quantumauth-io/quantum-auth-client/internal/qa"
	"github.com/quantumauth-io/quantum-go-utils/log"
)

const extensionPairHeader = "X-QA-Extension"
const agentSessionHeader = "X-QA-Session"

type Server struct {
	qaClient   *qa.Client
	authClient *login.QAClientLoginService
	mux        *http.ServeMux

	agentSessionToken string
	uiAllowedOrigins  map[string]struct{}

	perms            *PermissionStore
	pairingTokenPath string

	pairings   map[string]*Pairing
	pairingsMu sync.Mutex
}

type corsPolicy struct {
	allowedOrigins map[string]struct{}
	allowMethods   string

	allowHeaders string
	maxAge       int
}

type extensionRequest struct {
	Action string          `json:"action"`
	Data   json.RawMessage `json:"data,omitempty"`
}

type qaChallengeRequest struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	BackendHost string `json:"backendHost"`
	AppID       string `json:"appId,omitempty"`
	Origin      string `json:"origin"` // NEW: required for allowlist enforcement
}

type setPermissionRequest struct {
	Origin  string `json:"origin"`
	Allowed bool   `json:"allowed"`
}

type extensionResponse struct {
	OK    bool        `json:"ok"`
	Error string      `json:"error,omitempty"`
	Data  interface{} `json:"data,omitempty"`
}

type pairResp struct {
	OK               bool   `json:"ok"`
	PairingToken     string `json:"pairingToken"`
	PairingTokenPath string `json:"pairingTokenPath,omitempty"`
}

type signResp struct {
	Signature string `json:"signature"` // TODO: 0x...
}

type Pairing struct {
	CodeHash  []byte
	ExpiresAt time.Time
	Used      bool
	Token     string
}

type pairExchangeReq struct {
	PairID string `json:"pair_id"`
	Code   string `json:"code"`
}

type pairExchangeResp struct {
	OK     bool   `json:"ok"`
	Token  string `json:"token"`
	Header string `json:"header"`
}

func NewServer(qaClient *qa.Client, authState *login.QAClientLoginService, uiAllowedOrigins []string) (http.Handler, error) {
	s := &Server{
		qaClient:   qaClient,
		authClient: authState,
		mux:        http.NewServeMux(),
		pairings:   make(map[string]*Pairing),
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
		allowedOrigins: s.uiAllowedOrigins, // reuse your allowlist
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

	s.mux.HandleFunc("/pair/exchange", s.withCORS(pairCors, s.withLoopbackOnly(s.handleTokenPair)))

	s.mux.HandleFunc("/agent/extension/pair", s.withAgentGuards(s.handleAgentExtensionPair))
	s.mux.HandleFunc("/agent/extension/status", s.withAgentGuards(s.handleAgentExtensionStatus))
	s.mux.HandleFunc("/agent/session/validate", s.withAgentGuards(s.handleAgentSessionValidate))

	// Challenge endpoint
	s.mux.HandleFunc("/extension/auth", s.withExtensionPairedGuards(s.handleExtensionAuth))

	// Extension management (paired extension only)
	s.mux.HandleFunc("/extension/permissions", s.withExtensionPairedGuards(s.handleGetPermissions))
	s.mux.HandleFunc("/extension/permissions/status", s.withExtensionPairedGuards(s.handleGetPermissionStatus))
	s.mux.HandleFunc("/extension/permissions/set", s.withExtensionPairedGuards(s.handleSetPermission))

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

func newSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

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
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
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
