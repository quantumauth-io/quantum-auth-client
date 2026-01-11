package setup

import (
	"strings"

	"github.com/quantumauth-io/quantum-auth-client/cmd/quantum-auth-client/config"
	"github.com/quantumauth-io/quantum-auth-client/internal/shared"
)

// somewhere in setup.go or a small adapter package
func networksFromConfig(cfg *config.Config) []shared.Network {
	out := make([]shared.Network, 0, len(cfg.EthNetworks.Networks))

	for name, n := range cfg.EthNetworks.Networks {
		rpc := ""
		// choose rpc
		if strings.EqualFold(name, cfg.EthNetworks.ActiveNetwork) {
			// try ActiveRPC first
			for _, r := range n.RPCs {
				if strings.EqualFold(r.Name, cfg.EthNetworks.ActiveRPC) {
					rpc = r.URL
					break
				}
			}
		}
		if rpc == "" && len(n.RPCs) > 0 {
			rpc = n.RPCs[0].URL
		}

		out = append(out, shared.Network{
			Name:       name,
			ChainId:    int64(n.ChainID),
			ChainIdHex: n.ChainIDHex,
			Explorer:   n.Explorer,
			RpcUrl:     rpc,
			EntryPoint: n.EntryPoint,
		})
	}
	return out
}
