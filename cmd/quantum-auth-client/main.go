package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	clientconfig "github.com/quantumauth-io/quantum-auth-client/cmd/quantum-auth-client/config"
	clienthttp "github.com/quantumauth-io/quantum-auth-client/internal/http"
	"github.com/quantumauth-io/quantum-auth-client/internal/login"
	"github.com/quantumauth-io/quantum-auth-client/internal/qa"
	clienttpm "github.com/quantumauth-io/quantum-auth-client/internal/tpm"
	"github.com/quantumauth-io/quantum-auth/pkg/tpmdevice"
	"github.com/quantumauth-io/quantum-go-utils/log"
)

var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

func main() {
	log.Info("quantum-auth-client",
		"version", Version,
		"commit", Commit,
		"build_date", BuildDate,
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := clientconfig.Load()
	if err != nil {
		log.Fatal("failed to parse config", "error", err)
	}
	// OS-aware TPM init
	tpmClient, err := clienttpm.NewRuntimeTPM(ctx)
	if err != nil {
		log.Error("TPM init failed", "error", err)
		return
	}
	defer func(tpmClient tpmdevice.Client) {
		if err = tpmClient.Close(); err != nil {
			log.Error("TPM close failed", "error", err)
		}
	}(tpmClient)

	qaClient, err := qa.NewClient(cfg.ClientSettings.ServerURL, tpmClient)
	if err != nil {
		log.Error("failed to init QA client", "error", err)
		return
	}
	defer func() {
		if err = qaClient.Close(); err != nil {
			log.Error("failed to close QA client", "error", err)
		}
	}()

	authState, err := login.EnsureLogin(ctx, qaClient, cfg.ClientSettings.Email, cfg.ClientSettings.DeviceLabel)
	if err != nil {
		log.Error("login/setup failed", "error", err)
		return
	}
	defer authState.Clear()

	handler := clienthttp.NewServer(qaClient, authState)

	addr := net.JoinHostPort(cfg.ClientSettings.LocalHost, cfg.ClientSettings.Port)
	server := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	go func() {
		if err = server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("HTTP server error", "error", err)
		}
	}()

	<-ctx.Done()
	log.Info("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err = server.Shutdown(shutdownCtx); err != nil {
		log.Error("HTTP server shutdown failed", "error", err)
	} else {
		log.Info("HTTP server gracefully stopped")
	}
}
