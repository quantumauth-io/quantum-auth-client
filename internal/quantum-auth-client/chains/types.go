package chains

type AllChainsConfig struct {
	Networks      map[string]NetworkConfig `json:"networks" yaml:"networks"`
	ActiveNetwork string                   `json:"activeNetwork" yaml:"activeNetwork"`
	ActiveRPC     string                   `json:"activeRPC" yaml:"activeRPC"`
}

// NetworkConfig describes a network and its RPC endpoints.
type NetworkConfig struct {
	Name       string `json:"name" yaml:"name"`
	ChainID    uint64 `json:"chainId" yaml:"chainId"`
	ChainIDHex string `json:"chainIdHex" yaml:"chainIdHex"`
	EntryPoint string `json:"entryPoint" yaml:"entryPoint" mapstructure:"entryPoint"`
	RPCs       []RPC  `json:"rpcs" yaml:"rpcs"`
	Explorer   string `json:"explorer" yaml:"explorer" mapstructure:"explorer"`
}

type RPC struct {
	Name string `json:"name" yaml:"name"`
	URL  string `json:"url" yaml:"url"`
	WSS  string `json:"wss" yaml:"wss"`
}

func (mc *AllChainsConfig) Normalize() {
	if mc == nil {
		return
	}
	for name, n := range mc.Networks {
		n.Name = name
		mc.Networks[name] = n
	}
}
