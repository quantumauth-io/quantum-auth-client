package chains

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/quantumauth-io/quantum-go-utils/qa_evm"
)

type ChainConfig struct {
	Chains                                             *AllChainsConfig
	DefaultActiveNetwork                               string
	PreferredRPCName                                   string
	DurationBetweenGetLatestHeaderRequestsMilliseconds int
}

type ChainClients struct {
	WS   *ethclient.Client
	HTTP qa_evm.BlockchainClient
}

type ResolvedChain struct {
	NetworkName string
	ChainID     uint64
	ChainIDHex  string
	EntryPoint  string
	Explorer    string

	RPCName string
	URL     string
	WSS     string
}

type activeChain struct {
	networkName string
	clients     *ChainClients
}

type QAChainService struct {
	cfg              ChainConfig
	active           atomic.Pointer[activeChain]
	mu               sync.Mutex
	clientsByNetwork map[string]*ChainClients
}

func NewQAChainService(cfg ChainConfig) (*QAChainService, error) {
	if cfg.Chains == nil {
		return nil, errors.New("chains config is nil")
	}
	if strings.TrimSpace(cfg.DefaultActiveNetwork) == "" {
		return nil, errors.New("active network is empty")
	}

	service := &QAChainService{
		cfg:              cfg,
		clientsByNetwork: make(map[string]*ChainClients),
	}

	if err := service.SwitchChain(context.Background(), cfg.DefaultActiveNetwork); err != nil {
		return nil, err
	}

	return service, nil
}

func (s *QAChainService) Active() (*ChainClients, error) {
	current := s.active.Load()
	if current == nil {
		return nil, errors.New("no active chain")
	}
	return current.clients, nil
}

func (s *QAChainService) ActiveHTTP(ctx context.Context) (qa_evm.BlockchainClient, error) {
	_ = ctx // kept for future-proofing / symmetry

	current := s.active.Load()
	if current == nil || current.clients == nil || current.clients.HTTP == nil {
		return nil, errors.New("no active http client")
	}

	return current.clients.HTTP, nil
}

func (s *QAChainService) ActiveNetwork() (string, error) {
	current := s.active.Load()
	if current == nil {
		return "", errors.New("no active chain")
	}
	return current.networkName, nil
}

func (s *QAChainService) SwitchChain(ctx context.Context, networkName string) error {
	networkName = strings.TrimSpace(networkName)
	if networkName == "" {
		return errors.New("network name is empty")
	}

	// no-op if already active
	if current := s.active.Load(); current != nil {
		if strings.EqualFold(current.networkName, networkName) {
			return nil
		}
	}

	clients, err := s.ClientsForNetwork(ctx, networkName)
	if err != nil {
		return err
	}

	s.active.Store(&activeChain{
		networkName: networkName,
		clients:     clients,
	})
	return nil
}

func (s *QAChainService) SwitchChainByChainIDHex(
	ctx context.Context,
	chainIDHex string,
) (string, error) {
	resolved, err := s.ResolveNetworkByChainIDHex(chainIDHex)
	if err != nil {
		return "", err
	}

	if err := s.SwitchChain(ctx, resolved.NetworkName); err != nil {
		return "", err
	}

	return resolved.NetworkName, nil
}

// ClientsForNetwork returns (and caches) clients for a specific network WITHOUT changing active chain.
func (s *QAChainService) ClientsForNetwork(ctx context.Context, networkName string) (*ChainClients, error) {
	networkName = strings.TrimSpace(networkName)
	if networkName == "" {
		return nil, errors.New("network name is empty")
	}

	cacheKey := strings.ToLower(networkName)

	s.mu.Lock()
	if existing := s.clientsByNetwork[cacheKey]; existing != nil {
		s.mu.Unlock()
		return existing, nil
	}
	s.mu.Unlock()

	// Resolve URLs from config
	resolved, err := s.ResolveNetworkByName(networkName)
	if err != nil {
		return nil, err
	}

	// Dial outside the lock (avoid blocking concurrent readers)
	dialed, err := dialChainClients(ctx, resolved)
	if err != nil {
		return nil, err
	}

	// Store in cache (double-check in case another goroutine raced us)
	s.mu.Lock()
	if existing := s.clientsByNetwork[cacheKey]; existing != nil {
		s.mu.Unlock()
		// We raced; close what we just dialed and return existing
		safeCloseClients(dialed)
		return existing, nil
	}
	s.clientsByNetwork[cacheKey] = dialed
	s.mu.Unlock()

	return dialed, nil
}

// Close closes all cached clients (call on shutdown).
func (s *QAChainService) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, clients := range s.clientsByNetwork {
		if clients != nil {
			safeCloseClients(clients)
		}
		delete(s.clientsByNetwork, key)
	}

	s.active.Store(nil)
	return nil
}

func dialChainClients(ctx context.Context, chain ResolvedChain) (*ChainClients, error) {
	if strings.TrimSpace(chain.URL) == "" || strings.TrimSpace(chain.WSS) == "" {
		return nil, errors.New("invalid chain rpc config (missing url/wss)")
	}

	wsClient, err := ethclient.DialContext(ctx, chain.WSS)
	if err != nil {
		return nil, fmt.Errorf("dial wss %q: %w", chain.NetworkName, err)
	}

	httpClient, err := ethclient.DialContext(ctx, chain.URL)
	if err != nil {
		wsClient.Close()
		return nil, fmt.Errorf("dial http %q: %w", chain.NetworkName, err)
	}

	return &ChainClients{
		WS:   wsClient,
		HTTP: httpClient,
	}, nil
}

func safeCloseClients(c *ChainClients) {
	if c == nil {
		return
	}

	if c.WS != nil {
		c.WS.Close()
	}

	if c.HTTP != nil {
		if closer, ok := c.HTTP.(interface{ Close() }); ok {
			closer.Close()
		}
	}
}

func (s *QAChainService) ResolveNetworkByChainID(chainID uint64) (ResolvedChain, error) {
	if s.cfg.Chains == nil {
		return ResolvedChain{}, errors.New("chains config is nil")
	}
	if chainID == 0 {
		return ResolvedChain{}, errors.New("chainID is 0")
	}

	for networkName, network := range s.cfg.Chains.Networks {
		if network.ChainID != chainID {
			continue
		}
		return s.resolveFromNetworkConfig(networkName, network)
	}

	return ResolvedChain{}, fmt.Errorf("unknown chainID %d", chainID)
}

func (s *QAChainService) ResolveNetworkByChainIDHex(chainIDHex string) (ResolvedChain, error) {
	chainIDHex = strings.TrimSpace(strings.ToLower(chainIDHex))
	if chainIDHex == "" {
		return ResolvedChain{}, errors.New("chainIdHex is empty")
	}

	for networkName, network := range s.cfg.Chains.Networks {
		if strings.ToLower(strings.TrimSpace(network.ChainIDHex)) != chainIDHex {
			continue
		}
		return s.resolveFromNetworkConfig(networkName, network)
	}

	return ResolvedChain{}, fmt.Errorf("unknown chainIdHex %q", chainIDHex)
}
func (s *QAChainService) ResolveNetworkByName(networkName string) (ResolvedChain, error) {
	networkName = strings.TrimSpace(networkName)
	if networkName == "" {
		return ResolvedChain{}, errors.New("network name is empty")
	}

	network, ok := s.cfg.Chains.Networks[networkName]
	if !ok {
		return ResolvedChain{}, fmt.Errorf("unknown network %q", networkName)
	}
	return s.resolveFromNetworkConfig(networkName, network)
}

func (s *QAChainService) resolveFromNetworkConfig(networkName string, network NetworkConfig) (ResolvedChain, error) {
	// pick RPC by preferred name; otherwise first
	var selectedRPC *RPC

	if preferred := strings.TrimSpace(s.cfg.PreferredRPCName); preferred != "" {
		for i := range network.RPCs {
			if strings.EqualFold(strings.TrimSpace(network.RPCs[i].Name), preferred) {
				selectedRPC = &network.RPCs[i]
				break
			}
		}
	}
	if selectedRPC == nil {
		if len(network.RPCs) == 0 {
			return ResolvedChain{}, fmt.Errorf("network %q has no RPCs configured", networkName)
		}
		selectedRPC = &network.RPCs[0]
	}

	if strings.TrimSpace(selectedRPC.URL) == "" {
		return ResolvedChain{}, fmt.Errorf("network %q rpc %q url is empty", networkName, selectedRPC.Name)
	}
	if strings.TrimSpace(selectedRPC.WSS) == "" {
		return ResolvedChain{}, fmt.Errorf("network %q rpc %q wss is empty", networkName, selectedRPC.Name)
	}

	return ResolvedChain{
		NetworkName: networkName,
		ChainID:     network.ChainID,
		ChainIDHex:  network.ChainIDHex,
		EntryPoint:  network.EntryPoint,
		Explorer:    network.Explorer,
		RPCName:     selectedRPC.Name,
		URL:         selectedRPC.URL,
		WSS:         selectedRPC.WSS,
	}, nil
}
