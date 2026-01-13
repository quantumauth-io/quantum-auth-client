package networks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/constants"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/securefile"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/shared"
)

type Manager struct {
	path  string
	store Store
}

func NewManager() (*Manager, error) {
	if strings.TrimSpace(constants.AppName) == "" {
		return nil, fmt.Errorf("appName must not be empty")
	}

	path, err := resolveNetworksPath(constants.AppName)
	if err != nil {
		return nil, err
	}

	return &Manager{
		path:  path,
		store: NewEmptyStore(),
	}, nil
}

func (m *Manager) Path() string { return m.path }

// AddNetwork adds a new network (fails on duplicate name or chainIdHex).
func (m *Manager) AddNetwork(ctx context.Context, n chains.NetworkConfig) (chains.NetworkConfig, error) {
	if err := m.ensureLoadedIfExists(ctx); err != nil {
		return chains.NetworkConfig{}, err
	}
	if m.store.Schema == 0 {
		m.store.Schema = constants.SchemaV1
	}
	if m.store.Networks == nil {
		m.store.Networks = map[string]chains.NetworkConfig{}
	}

	normalized, err := normalizeNetworkConfig(n)
	if err != nil {
		return chains.NetworkConfig{}, err
	}

	if _, exists := m.store.Networks[normalized.Name]; exists {
		return chains.NetworkConfig{}, fmt.Errorf("network name already exists: %s", normalized.Name)
	}
	if key, ok := m.findKeyByChainIdHex(normalized.ChainIDHex); ok {
		return chains.NetworkConfig{}, fmt.Errorf("network already exists for chainIdHex %s (name: %s)", normalized.ChainIDHex, key)
	}

	m.store.Networks[normalized.Name] = normalized
	if err := m.persist(ctx); err != nil {
		return chains.NetworkConfig{}, err
	}
	return normalized, nil
}

func (m *Manager) RemoveNetworkByChainIdHex(ctx context.Context, chainIdHex string) error {
	if err := m.ensureLoadedIfExists(ctx); err != nil {
		return err
	}
	key, ok := m.findKeyByChainIdHex(chainIdHex)
	if !ok {
		return nil // idempotent
	}
	delete(m.store.Networks, key)
	return m.persist(ctx)
}

// UpdateNetworkByChainIdHex updates mutable fields only (keeps name + chain ids stable).
// If you want renames later, do it explicitly with a Rename API.
func (m *Manager) UpdateNetworkByChainIdHex(
	ctx context.Context,
	chainIdHex string,
	patch shared.UpdateNetworkPatch,
) (chains.NetworkConfig, error) {
	if err := m.ensureLoadedIfExists(ctx); err != nil {
		return chains.NetworkConfig{}, err
	}

	key, ok := m.findKeyByChainIdHex(chainIdHex)
	if !ok {
		return chains.NetworkConfig{}, fmt.Errorf("network not found: %s", normalizeChainIdHex(chainIdHex))
	}

	n := m.store.Networks[key]

	if patch.Explorer != nil {
		n.Explorer = strings.TrimSpace(*patch.Explorer)
	}
	if patch.EntryPoint != nil {
		n.EntryPoint = strings.TrimSpace(*patch.EntryPoint)
	}

	// Backward compat: rpcUrl -> rpcs[0] (only if rpcs not provided)
	if patch.Rpcs == nil && patch.RpcUrl != nil {
		url := strings.TrimSpace(*patch.RpcUrl)
		if url != "" {
			n.RPCs = normalizeRPCs([]chains.RPC{{Name: "Custom", URL: url}})
		}
	}

	// New: explicit RPC list (can be empty to clear)
	if patch.Rpcs != nil {
		n.RPCs = normalizeRPCs(*patch.Rpcs)
	}

	// re-normalize invariants
	n.Name = normalizeNetworkKey(n.Name)
	n.ChainIDHex = normalizeChainIdHex(n.ChainIDHex)

	m.store.Networks[key] = n
	if err := m.persist(ctx); err != nil {
		return chains.NetworkConfig{}, err
	}
	return n, nil
}

func (m *Manager) Load(ctx context.Context) error {
	_ = ctx

	b, err := os.ReadFile(m.path)
	if err != nil {
		return fmt.Errorf("read networks file: %w", err)
	}

	var s Store
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("unmarshal networks file: %w", err)
	}
	if s.Schema == 0 {
		s.Schema = constants.SchemaV1
	}
	if s.Networks == nil {
		s.Networks = map[string]chains.NetworkConfig{}
	}

	norm := NewEmptyStore()
	norm.Schema = s.Schema

	for key, n := range s.Networks {
		if strings.TrimSpace(n.Name) == "" {
			n.Name = key
		}

		normalized, err := normalizeNetworkConfig(n)
		if err != nil {
			// skip invalid entries rather than bricking startup
			continue
		}

		norm.Networks[normalized.Name] = normalized
	}

	m.store = norm
	return nil
}

func (m *Manager) ensureLoadedIfExists(ctx context.Context) error {
	if m.store.Networks != nil && len(m.store.Networks) > 0 {
		return nil
	}
	if exists(m.path) {
		return m.Load(ctx)
	}
	m.store = NewEmptyStore()
	return nil
}

func (m *Manager) persist(ctx context.Context) error {
	_ = ctx

	if err := os.MkdirAll(filepath.Dir(m.path), constants.DirectoryPerm); err != nil {
		return fmt.Errorf("mkdir networks dir: %w", err)
	}

	b, err := json.MarshalIndent(m.store, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal networks store: %w", err)
	}

	return securefile.AtomicWriteFile(m.path, b, constants.FilePerm)
}

// EnsureFromConfig merges config networks into networks.json:
// - first run: creates file
// - later runs: adds only missing networks
// - fills blank explorer/entryPoint/rpcs without overwriting user values
func (m *Manager) EnsureFromConfig(ctx context.Context, defaults map[string]chains.NetworkConfig) error {
	if err := m.ensureLoadedIfExists(ctx); err != nil {
		return err
	}
	if m.store.Schema == 0 {
		m.store.Schema = constants.SchemaV1
	}
	if m.store.Networks == nil {
		m.store.Networks = map[string]chains.NetworkConfig{}
	}

	changed := false

	// chainIdHex -> nameKey
	byChain := map[string]string{}
	for nameKey, n := range m.store.Networks {
		if n.ChainIDHex != "" {
			byChain[normalizeChainIdHex(n.ChainIDHex)] = nameKey
		}
	}

	// defaults key is the network name in config
	for nameKey, dn := range defaults {
		if strings.TrimSpace(dn.Name) == "" {
			dn.Name = nameKey
		}

		dnNorm, err := normalizeNetworkConfig(dn)
		if err != nil {
			continue
		}

		// match by name first
		if existing, ok := m.store.Networks[dnNorm.Name]; ok {
			updated := existing

			if updated.Explorer == "" && dnNorm.Explorer != "" {
				updated.Explorer = dnNorm.Explorer
				changed = true
			}
			if updated.EntryPoint == "" && dnNorm.EntryPoint != "" {
				updated.EntryPoint = dnNorm.EntryPoint
				changed = true
			}
			if len(updated.RPCs) == 0 && len(dnNorm.RPCs) > 0 {
				updated.RPCs = dnNorm.RPCs
				changed = true
			}
			if updated.ChainID == 0 && dnNorm.ChainID != 0 {
				updated.ChainID = dnNorm.ChainID
				changed = true
			}
			if updated.ChainIDHex == "" && dnNorm.ChainIDHex != "" {
				updated.ChainIDHex = dnNorm.ChainIDHex
				changed = true
			}

			m.store.Networks[dnNorm.Name] = updated
			byChain[normalizeChainIdHex(updated.ChainIDHex)] = dnNorm.Name
			continue
		}

		// match by chainIdHex (avoid dup if renamed)
		if key, ok := byChain[normalizeChainIdHex(dnNorm.ChainIDHex)]; ok {
			updated := m.store.Networks[key]

			if updated.Explorer == "" && dnNorm.Explorer != "" {
				updated.Explorer = dnNorm.Explorer
				changed = true
			}
			if updated.EntryPoint == "" && dnNorm.EntryPoint != "" {
				updated.EntryPoint = dnNorm.EntryPoint
				changed = true
			}
			if len(updated.RPCs) == 0 && len(dnNorm.RPCs) > 0 {
				updated.RPCs = dnNorm.RPCs
				changed = true
			}
			if updated.ChainID == 0 && dnNorm.ChainID != 0 {
				updated.ChainID = dnNorm.ChainID
				changed = true
			}
			if updated.ChainIDHex == "" && dnNorm.ChainIDHex != "" {
				updated.ChainIDHex = dnNorm.ChainIDHex
				changed = true
			}

			m.store.Networks[key] = updated
			continue
		}

		// add
		m.store.Networks[dnNorm.Name] = dnNorm
		byChain[normalizeChainIdHex(dnNorm.ChainIDHex)] = dnNorm.Name
		changed = true
	}

	if !exists(m.path) {
		changed = true
	}

	if changed {
		return m.persist(ctx)
	}
	return nil
}

func (m *Manager) List(ctx context.Context) ([]chains.NetworkConfig, error) {
	if err := m.ensureLoadedIfExists(ctx); err != nil {
		return nil, err
	}

	out := make([]chains.NetworkConfig, 0, len(m.store.Networks))
	for _, n := range m.store.Networks {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (m *Manager) ListFromFile(ctx context.Context) ([]chains.NetworkConfig, error) {
	if err := m.ensureLoadedIfExists(ctx); err != nil {
		return nil, err
	}

	out := make([]chains.NetworkConfig, 0, len(m.store.Networks))
	for _, n := range m.store.Networks {
		out = append(out, n)
	}
	// You already sort in List(); reuse if you want:
	// sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Manager) FindByChainIdHex(ctx context.Context, chainIdHex string) (chains.NetworkConfig, bool, error) {
	if err := m.ensureLoadedIfExists(ctx); err != nil {
		return chains.NetworkConfig{}, false, err
	}

	want := normalizeChainIdHex(chainIdHex)
	if want == "" {
		return chains.NetworkConfig{}, false, fmt.Errorf("missing chainIdHex")
	}

	for _, n := range m.store.Networks {
		if normalizeChainIdHex(n.ChainIDHex) == want {
			return n, true, nil
		}
	}
	return chains.NetworkConfig{}, false, nil
}

func resolveNetworksPath(appName string) (string, error) {
	cands, err := securefile.ConfigPathCandidates(appName, constants.NetworksFile)
	if err != nil {
		return "", err
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("no config path candidates returned")
	}
	for _, p := range cands {
		if exists(p) {
			return p, nil
		}
	}
	return cands[0], nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func normalizeNetworkKey(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func normalizeChainIdHex(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "0x") {
		s = "0x" + s
	}
	return s
}

func normalizeRPCs(in []chains.RPC) []chains.RPC {
	out := make([]chains.RPC, 0, len(in))
	seen := map[string]struct{}{} // by url
	for _, r := range in {
		name := strings.TrimSpace(r.Name)
		url := strings.TrimSpace(r.URL)
		wss := strings.TrimSpace(r.WSS)

		// require at least URL; WSS optional depending on your needs
		if url == "" {
			continue
		}

		key := strings.ToLower(url)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		out = append(out, chains.RPC{
			Name: name,
			URL:  url,
			WSS:  wss,
		})
	}
	return out
}

func normalizeNetworkConfig(n chains.NetworkConfig) (chains.NetworkConfig, error) {
	n.Name = normalizeNetworkKey(n.Name)
	n.ChainIDHex = normalizeChainIdHex(n.ChainIDHex)
	n.Explorer = strings.TrimSpace(n.Explorer)
	n.EntryPoint = strings.TrimSpace(n.EntryPoint)
	n.RPCs = normalizeRPCs(n.RPCs)

	if n.Name == "" {
		return chains.NetworkConfig{}, fmt.Errorf("network.name is required")
	}
	if n.ChainIDHex == "" {
		return chains.NetworkConfig{}, fmt.Errorf("network.chainIdHex is required")
	}
	// ChainID can be 0 for “unknown” if you want, but typically you have it.
	return n, nil
}

func (m *Manager) findKeyByChainIdHex(chainIdHex string) (string, bool) {
	ch := normalizeChainIdHex(chainIdHex)
	if ch == "" {
		return "", false
	}
	for k, n := range m.store.Networks {
		if normalizeChainIdHex(n.ChainIDHex) == ch {
			return k, true
		}
	}
	return "", false
}
