package main

import (
	"context"

	"github.com/Madeindreams/quantum-auth-client/internal/config"
	clienthttp "github.com/Madeindreams/quantum-auth-client/internal/http"
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
	log.Info("quantum-auth-client:", "version", Version, "commit", Commit, "build date", BuildDate)

	ctx := context.Background()

	// 1) load env config
	cfg, err := config.Load()
	if err != nil {
		log.Error("failed to load config", "error", err)
	}

	// OS-aware TPM init
	tpmClient, err := clienttpm.NewRuntimeTPM(ctx)
	if err != nil {
		log.Error("TPM init failed:", "error", err)
	}
	defer func(tpmClient tpmdevice.Client) {
		err := tpmClient.Close()
		if err != nil {
			log.Error("TPM close failed:", "error", err)
		}
	}(tpmClient)

	// 3) init QA client with baseURL + TPM
	qaClient, err := qa.NewClient(ctx, cfg.ServerURL, tpmClient)
	if err != nil {
		log.Error("failed to init QA client:", "error", err)
	}
	defer qaClient.Close()
	if err != nil {
		log.Error("failed to init QA client:", "error", err)
	}
	defer func(qaClient *qa.Client) {
		err = qaClient.Close()
		if err != nil {
			log.Error("failed to close QA client:", "error", err)

		}
	}(qaClient)

	h := clienthttp.NewHandler(qaClient)
	r := clienthttp.NewRouter(h)

	addr := ":8090"
	log.Info("quantum-auth-client listening on", "address", addr, "server", cfg.ServerURL)

	if err = r.Run(addr); err != nil {
		log.Error("failed to run router:", "error", err)
	}
}
