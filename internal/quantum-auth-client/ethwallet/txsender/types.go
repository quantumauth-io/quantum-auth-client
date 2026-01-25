package txsender

type NetworkConfig struct {
	EntryPoint string
}

type NetworkResolver interface {
	ResolveNetworkByChainID(chainID uint64) (*NetworkConfig, error)
}
