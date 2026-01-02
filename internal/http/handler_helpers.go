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

// Simple boolean guards to reduce repetitive nil checks.
// Keep them tiny: they only check + write the error.
func requireEthClient(w http.ResponseWriter, s *Server) bool {
	if s.ethClient == nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: WalletEthClientNotInitializedText})
		return false
	}
	return true
}

func requireWalletRuntime(w http.ResponseWriter, s *Server) bool {
	if s.onChain == nil || s.onChain.User == nil || s.onChain.Device == nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, WalletRuntimeNotInitializedText, nil)
		return false
	}
	return true
}

func requireAuthState(w http.ResponseWriter, s *Server) bool {
	if s.authClient == nil || s.authClient.State == nil {
		writeJSON(w, http.StatusInternalServerError, extensionResponse{OK: false, Error: "auth state not initialised"})
		return false
	}
	return true
}
