package http

import (
	"fmt"
	"net/http"

	"github.com/quantumauth-io/quantum-go-utils/log"
)

func (s *Server) withCORS(policy corsPolicy, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		originRaw := r.Header.Get("Origin")
		if originRaw != "" {
			origin := normalizeOrigin(originRaw)
			if origin == "" {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}

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

			if policy.allowHeaders != "" {
				w.Header().Set("Access-Control-Allow-Headers", policy.allowHeaders)
			} else if reqHdrs := r.Header.Get("Access-Control-Request-Headers"); reqHdrs != "" {
				w.Header().Set("Access-Control-Allow-Headers", reqHdrs)
			}

			if policy.maxAge > 0 {
				w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", policy.maxAge))
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next(w, r)
	}
}

func (s *Server) withAgentGuards(next http.HandlerFunc) http.HandlerFunc {
	cors := corsPolicy{
		allowedOrigins: s.uiAllowedOrigins,
		allowMethods:   "GET,POST,OPTIONS",
		allowHeaders:   "",
		maxAge:         600,
	}

	return s.withCORS(cors, func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackRequest(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		receivedToken := r.Header.Get(agentSessionHeader)
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
		allowedOrigins: nil,
		allowMethods:   "POST,OPTIONS",
		allowHeaders:   "",
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

func (s *Server) withExtensionPairedGuards(next http.HandlerFunc) http.HandlerFunc {
	extCors := corsPolicy{
		allowedOrigins: nil,
		allowMethods:   "GET,POST,OPTIONS",
		allowHeaders:   "",
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
