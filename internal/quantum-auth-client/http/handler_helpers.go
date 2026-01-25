package http

import (
	"encoding/json"
	"net/http"
)

// Handler is a convenience type so we can wrap common behavior.
type Handler func(http.ResponseWriter, *http.Request)

func requireMethod(method string, next Handler) Handler {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, HTTPErrorMethodNotAllowedText, http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

// Same idea, but for JSON-RPC style errors (some endpoints use writeRPCError).
func requireMethodRPC(method string, next Handler) Handler {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			writeRPCError(w, http.StatusMethodNotAllowed, JSONRPCErrorCodeMethodNotFound, HTTPErrorMethodNotAllowedText, nil)
			return
		}
		next(w, r)
	}
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		http.Error(w, HTTPErrorInvalidJSONText, http.StatusBadRequest)
		return false
	}
	return true
}

// For endpoints that want RPC semantics on invalid JSON.
func decodeJSONBodyRPC(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := readJSONBody(r, dst); err != nil {
		writeRPCError(w, http.StatusBadRequest, JSONRPCErrorCodeInvalidRequest, "invalid request", err.Error())
		return false
	}
	return true
}

func requireAuthState(w http.ResponseWriter, s *Server) bool {

	userID := s.identity.UserID
	deviceID := s.identity.DeviceID
	if userID == "" || deviceID == "" {
		http.Error(w, "device not registered", http.StatusPreconditionRequired)
		writeJSON(w, http.StatusPreconditionRequired, extensionResponse{OK: false, Error: "auth state not initialised"})
	}

	return true
}
