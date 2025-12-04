package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Madeindreams/quantum-auth-client/internal/config"
	clienthttp "github.com/Madeindreams/quantum-auth-client/internal/http"
	"github.com/Madeindreams/quantum-auth-client/internal/login"
	"github.com/Madeindreams/quantum-auth-client/internal/qa"
	clienttpm "github.com/Madeindreams/quantum-auth-client/internal/tpm"
	"github.com/Madeindreams/quantum-auth/pkg/tpmdevice"
	"github.com/Madeindreams/quantum-go-utils/log"
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

	cfg, err := config.Load()
	if err != nil {
		log.Error("failed to load config", "error", err)
		return
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

	qaClient, err := qa.NewClient(ctx, cfg.ServerURL, tpmClient)
	if err != nil {
		log.Error("failed to init QA client", "error", err)
		return
	}

	authState, err := login.EnsureLogin(ctx, qaClient, cfg.Email, cfg.DeviceLabel)
	if err != nil {
		log.Error("login/setup failed", "error", err)
		return
	}
	defer authState.Clear()

	defer func() {
		if err = qaClient.Close(); err != nil {
			log.Error("failed to close QA client", "error", err)
		}
	}()

	h := clienthttp.NewHandler(qaClient, authState)
	r := clienthttp.NewRouter(h)

	addr := ":8090"
	server := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	log.Info("quantum-auth-client listening",
		"address", addr,
		"server", cfg.ServerURL,
	)

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
