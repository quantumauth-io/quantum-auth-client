package http

import (
	"context"
	"net/http"

	"github.com/quantumauth-io/quantum-auth-client/cmd/quantum-auth-client/config"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/runtime"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/services"
)

func NewServerHandler(
	ctx context.Context,
	qaClient *services.Client,
	identity runtime.Identity,
	cfg *config.Config,
	pairTokenProvider PairTokenProvider,
	web3 Web3Provider,
	devKeys DevKeysProvider,
) (http.Handler, error) {

	s, err := NewServer(
		ctx,
		qaClient,
		cfg,
		identity,
		pairTokenProvider,
		web3,
		devKeys,
	)
	if err != nil {
		return nil, err
	}
	return s.mux, nil
}
