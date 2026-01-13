package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client"
	"github.com/quantumauth-io/quantum-go-utils/log"
)

var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

func main() {

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := quantum_auth_client.Run(ctx, quantum_auth_client.BuildInfo{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
	}); err != nil {
		log.Error("startup failed", "error", err)
		os.Exit(1)
	}

	// graceful shutdown
	<-ctx.Done()

}
