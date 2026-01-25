package state

import (
	"errors"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"
)

func buildChainServiceFromGUI(s GUISettings) (*chains.QAChainService, error) {
	cfg, err := buildConfigShim(s)

	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg.Networks == nil {
		return nil, errors.New("missing networks config")
	}

	return chains.NewQAChainService(chains.ChainConfig{
		Chains:               cfg.Networks,
		DefaultActiveNetwork: cfg.Networks.ActiveNetwork,
		PreferredRPCName:     cfg.Networks.ActiveRPC,
	})
}
