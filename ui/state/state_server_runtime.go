package state

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	clienthttp "github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/http"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/runtime"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/services"
	"github.com/quantumauth-io/quantum-go-utils/log"
)

type serverRuntime struct {
	httpServer *http.Server
	listenAddr string
	qa         *services.Client
	closeOnce  sync.Once
}

func (r *serverRuntime) Close(ctx context.Context) {
	if r == nil {
		return
	}

	r.closeOnce.Do(func() {
		// Stop HTTP server first so it can't call into deps while we close them.
		if r.httpServer != nil {
			shutdownCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			_ = r.httpServer.Shutdown(shutdownCtx)
			cancel()
			r.httpServer = nil
		}

		// Close backend client
		if r.qa != nil {
			_ = r.qa.Close()
			r.qa = nil
		}

		r.listenAddr = ""
	})
}

func (s *AppState) StartHTTPServer(ctx context.Context) error {
	// Must be unlocked
	if !s.PasswordSet() {
		return errors.New("unlock required")
	}

	s.mu.Lock()
	existing := s.srt
	if existing != nil && existing.httpServer != nil {
		s.mu.Unlock()
		return nil
	}
	settings := NormalizeGUISettings(s.GUISettings)
	pw := s.password
	cryptoRT := s.crypto
	id := (*VaultIdentity)(nil)
	if s.payload != nil {
		id = s.payload.Identity
	}
	s.mu.Unlock()

	// Need runtime for signatures (TPM+PQ)
	if cryptoRT == nil {
		if err := s.InitRuntime(ctx); err != nil {
			return err
		}
		s.mu.Lock()
		cryptoRT = s.crypto
		s.mu.Unlock()
	}
	if cryptoRT == nil {
		return errors.New("crypto runtime unavailable")
	}

	if id == nil || id.UserID == "" || id.DeviceID == "" {
		return errors.New("identity missing: complete Setup → Register")
	}

	// Ensure bind works
	listenAddr := net.JoinHostPort(settings.LocalHost, settings.Port)
	if err := ensureCanBind(listenAddr); err != nil {
		return err
	}

	// QA client (backend)
	qaClient, err := services.NewClient(services.ClientConfig{
		BaseURL:     settings.ServerURL,
		HTTPTimeout: 10 * time.Second,
		Crypto:      cryptoRT,
	})
	if err != nil {
		return err
	}

	// Pull default networks from config shim (see next file)
	cfg, err := buildConfigShim(settings)
	if err != nil {
		_ = qaClient.Close()

		return err
	}

	identity := runtime.Identity{
		UserID:   id.UserID,
		DeviceID: id.DeviceID,
	}

	handler, err := clienthttp.NewServerHandler(
		ctx,
		qaClient,
		identity,
		cfg,
		vaultPairTokenProvider{st: s},
		s,
		s,
	)

	if err != nil {
		_ = qaClient.Close()
		return err
	}

	httpServer := &http.Server{Addr: listenAddr, Handler: handler}

	s.mu.Lock()
	// re-check in case someone started it while we were building
	if s.srt != nil && s.srt.httpServer != nil {
		s.mu.Unlock()
		_ = qaClient.Close()
		return nil
	}
	if s.srt == nil {
		s.srt = &serverRuntime{}
	}
	s.srt.httpServer = httpServer
	s.srt.listenAddr = listenAddr
	s.srt.qa = qaClient
	s.mu.Unlock()

	go func() {
		s.Log.Addf("HTTP server starting on %s", listenAddr)

		// Optional: backend login attempt (non-fatal)
		go func() {
			if err := qaClient.FullLogin(ctx, id.UserID, id.DeviceID, []byte(pw)); err != nil {
				s.Log.Addf("backend login unavailable (offline ok): %v", err)
			} else {
				s.Log.Addf("backend login OK")
			}
		}()

		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("HTTP server error", "error", err)
			s.Log.Addf("HTTP server error: %v", err)
		}
	}()

	return nil
}

func (s *AppState) StopHTTPServer(ctx context.Context) {
	s.mu.Lock()
	srt := s.srt
	s.srt = nil
	s.mu.Unlock()

	if srt == nil {
		return
	}
	s.CloseServerOnly(ctx)
}
