package config

import "github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"

func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}

	out := &Config{}

	// ClientSettings
	if c.ClientSettings != nil {
		cs := *c.ClientSettings
		out.ClientSettings = &cs
	} else {
		out.ClientSettings = &ClientSettings{}
	}

	// DefaultAssets (deep copy map[string][]string)
	out.DefaultAssets = DefaultAssetsConfig{}
	if c.DefaultAssets.Network != nil {
		out.DefaultAssets.Network = make(map[string][]string, len(c.DefaultAssets.Network))
		for k, v := range c.DefaultAssets.Network {
			cp := make([]string, len(v))
			copy(cp, v)
			out.DefaultAssets.Network[k] = cp
		}
	} else {
		out.DefaultAssets.Network = map[string][]string{}
	}

	// Networks (deep copy)
	if c.Networks != nil {
		out.Networks = cloneAllChainsConfig(c.Networks)
	} else {
		out.Networks = &chains.AllChainsConfig{Networks: map[string]chains.NetworkConfig{}}
	}

	return out
}

func cloneAllChainsConfig(in *chains.AllChainsConfig) *chains.AllChainsConfig {
	if in == nil {
		return &chains.AllChainsConfig{Networks: map[string]chains.NetworkConfig{}}
	}

	out := *in // copies scalar fields like ActiveNetwork/ActiveRPC etc

	// Deep-copy Networks map and nested RPC slices
	if in.Networks != nil {
		out.Networks = make(map[string]chains.NetworkConfig, len(in.Networks))
		for name, net := range in.Networks {
			nc := net
			if net.RPCs != nil {
				nc.RPCs = make([]chains.RPC, len(net.RPCs))
				copy(nc.RPCs, net.RPCs)
			}
			out.Networks[name] = nc
		}
	} else {
		out.Networks = map[string]chains.NetworkConfig{}
	}

	return &out
}
