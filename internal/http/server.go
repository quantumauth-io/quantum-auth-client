package http

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/quantumauth-io/quantum-auth-client/internal/login"
	"github.com/quantumauth-io/quantum-auth-client/internal/qa"
	"github.com/quantumauth-io/quantum-go-utils/log"
)

type Server struct {
	qaClient  *qa.Client
	authState *login.State
	mux       *http.ServeMux
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
}

type extensionResponse struct {
	OK    bool        `json:"ok"`
	Error string      `json:"error,omitempty"`
	Data  interface{} `json:"data,omitempty"`
}

func NewServer(qaClient *qa.Client, authState *login.State) http.Handler {
	s := &Server{
		qaClient:  qaClient,
		authState: authState,
		mux:       http.NewServeMux(),
	}

	// extension bridge
	s.mux.HandleFunc("/extension/auth", s.handleExtensionAuth)

	// simple health/ping endpoint (optional)
	s.mux.HandleFunc("/healthz", s.handleHealth)

	return s
}

// ServeHTTP implements http.Handler
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
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

	log.Info("extension request",
		"path", r.URL.Path,
		"action", extReq.Action,
	)

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

func (s *Server) handleRequestChallenge(
	w http.ResponseWriter,
	ctx context.Context,
	extReq extensionRequest,
) {
	if s.authState == nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{
			OK:    false,
			Error: "auth state not initialised",
		})
		return
	}

	var req qaChallengeRequest
	if len(extReq.Data) > 0 {
		if err := json.Unmarshal(extReq.Data, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, extensionResponse{
				OK:    false,
				Error: err.Error(),
			})
			return
		}
	} else {
		writeJSON(w, http.StatusBadRequest, extensionResponse{
			OK:    false,
			Error: "missing data",
		})
		return
	}

	chID, err := s.qaClient.RequestChallenge(ctx, s.authState.DeviceID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, extensionResponse{
			OK:    false,
			Error: err.Error(),
		})
		return
	}

	signedHeaders, err := s.qaClient.SignRequest(
		req.Method,
		req.Path,
		req.BackendHost,
		s.authState.UserID,
		s.authState.DeviceID,
		chID,
		nil,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{
			OK:    false,
			Error: err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, extensionResponse{
		OK: true,
		Data: map[string]interface{}{
			"qaProof": signedHeaders,
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
