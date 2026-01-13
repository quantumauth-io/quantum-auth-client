package helpers

import (
	"sort"
	"strings"

	"github.com/quantumauth-io/quantum-auth-client/cmd/quantum-auth-client/config"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"
)

func NetworksMapFromConfig(cfg *config.Config) map[string]chains.NetworkConfig {
	list := NetworksFromConfig(cfg)
	out := make(map[string]chains.NetworkConfig, len(list))
	for _, n := range list {
		out[n.Name] = n
	}
	return out
}

func NetworksFromConfig(cfg *config.Config) []chains.NetworkConfig {
	if cfg == nil || cfg.Networks == nil || cfg.Networks.Networks == nil {
		return nil
	}

	out := make([]chains.NetworkConfig, 0, len(cfg.Networks.Networks))

	for name, n := range cfg.Networks.Networks {
		netName := strings.TrimSpace(n.Name)
		if netName == "" {
			netName = strings.TrimSpace(name)
		}

		rpcs := make([]chains.RPC, 0, len(n.RPCs))
		for _, r := range n.RPCs {
			rpcs = append(rpcs, chains.RPC{
				Name: strings.TrimSpace(r.Name),
				URL:  strings.TrimSpace(r.URL),
				WSS:  strings.TrimSpace(r.WSS),
			})
		}

		out = append(out, chains.NetworkConfig{
			Name:       strings.ToLower(strings.TrimSpace(netName)),
			ChainID:    n.ChainID, // uint64
			ChainIDHex: strings.ToLower(strings.TrimSpace(n.ChainIDHex)),
			Explorer:   strings.TrimSpace(n.Explorer),
			EntryPoint: strings.TrimSpace(n.EntryPoint),
			RPCs:       rpcs,
		})
	}

	// deterministic order (nice for testing / stable JSON)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out
}

func NormalizeHex0x(s string) string {
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return "0x" + s[2:]
	}
	return "0x" + s
}
