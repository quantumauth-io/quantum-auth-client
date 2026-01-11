package networks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/quantumauth-io/quantum-auth-client/internal/constants"
	"github.com/quantumauth-io/quantum-auth-client/internal/securefile"
	"github.com/quantumauth-io/quantum-auth-client/internal/shared"
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

func (m *Manager) AddNetwork(ctx context.Context, n shared.Network) (shared.Network, error) {
	if err := m.ensureLoadedIfExists(ctx); err != nil {
		return shared.Network{}, err
	}
	if m.store.Schema == 0 {
		m.store.Schema = constants.SchemaV1
	}
	if m.store.Networks == nil {
		m.store.Networks = map[string]shared.Network{}
	}

	n.Name = normalizeNetworkKey(n.Name)
	n.ChainIdHex = normalizeChainIdHex(n.ChainIdHex)
	n.Explorer = strings.TrimSpace(n.Explorer)
	n.RpcUrl = strings.TrimSpace(n.RpcUrl)
	n.EntryPoint = strings.TrimSpace(n.EntryPoint)
	n.Rpcs = normalizeRPCs(n.Rpcs)

	if n.Name == "" {
		return shared.Network{}, fmt.Errorf("network.name is required")
	}
	if n.ChainIdHex == "" {
		return shared.Network{}, fmt.Errorf("network.chainIdHex is required")
	}

	// If chainId provided but chainIdHex missing, you could compute it; but you said chainIdHex exists.
	// Prevent duplicates by chainIdHex.
	if key, ok := m.findKeyByChainIdHex(n.ChainIdHex); ok {
		return shared.Network{}, fmt.Errorf("network already exists for chainIdHex %s (name: %s)", n.ChainIdHex, key)
	}

	// Also prevent duplicate by name (optional). If you prefer "overwrite", change behavior.
	if _, exists := m.store.Networks[n.Name]; exists {
		return shared.Network{}, fmt.Errorf("network name already exists: %s", n.Name)
	}

	m.store.Networks[n.Name] = n
	if err := m.persist(ctx); err != nil {
		return shared.Network{}, err
	}
	return n, nil
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

func (m *Manager) UpdateNetworkByChainIdHex(ctx context.Context, chainIdHex string, patch shared.UpdateNetworkPatch) (shared.Network, error) {
	if err := m.ensureLoadedIfExists(ctx); err != nil {
		return shared.Network{}, err
	}

	key, ok := m.findKeyByChainIdHex(chainIdHex)
	if !ok {
		return shared.Network{}, fmt.Errorf("network not found: %s", chainIdHex)
	}

	n := m.store.Networks[key]

	if patch.Explorer != nil {
		n.Explorer = strings.TrimSpace(*patch.Explorer)
	}
	if patch.EntryPoint != nil {
		n.EntryPoint = strings.TrimSpace(*patch.EntryPoint)
	}
	if patch.RpcUrl != nil {
		n.RpcUrl = strings.TrimSpace(*patch.RpcUrl)
	}
	if patch.Rpcs != nil {
		n.Rpcs = normalizeRPCs(*patch.Rpcs)
	}

	// keep normalized invariants
	n.Name = normalizeNetworkKey(n.Name)
	n.ChainIdHex = normalizeChainIdHex(n.ChainIdHex)

	m.store.Networks[key] = n
	if err := m.persist(ctx); err != nil {
		return shared.Network{}, err
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
		s.Networks = map[string]shared.Network{}
	}

	// normalize keys + fields defensively
	norm := NewEmptyStore()
	norm.Schema = s.Schema

	for k, n := range s.Networks {
		name := normalizeNetworkKey(n.Name)
		if name == "" {
			name = normalizeNetworkKey(k)
		}
		if name == "" {
			continue
		}

		n.Name = name
		n.ChainIdHex = strings.ToLower(strings.TrimSpace(n.ChainIdHex))
		n.Explorer = strings.TrimSpace(n.Explorer)
		n.RpcUrl = strings.TrimSpace(n.RpcUrl)
		n.EntryPoint = strings.TrimSpace(n.EntryPoint)

		// must have chainIdHex to be usable by wallet logic / UI
		if n.ChainIdHex == "" {
			continue
		}

		norm.Networks[name] = n
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
// - optionally fills empty explorer/rpcUrl fields without overwriting user values
func (m *Manager) EnsureFromConfig(ctx context.Context, defaults []shared.Network) error {
	if err := m.ensureLoadedIfExists(ctx); err != nil {
		return err
	}
	if m.store.Schema == 0 {
		m.store.Schema = constants.SchemaV1
	}
	if m.store.Networks == nil {
		m.store.Networks = map[string]shared.Network{}
	}

	changed := false

	// Build quick lookup by chainIdHex too (helps avoid duplicates if names differ)
	byChain := map[string]string{} // chainIdHex -> nameKey
	for nameKey, n := range m.store.Networks {
		if n.ChainIdHex != "" {
			byChain[strings.ToLower(n.ChainIdHex)] = nameKey
		}
	}

	for _, dn := range defaults {
		name := normalizeNetworkKey(dn.Name)
		if name == "" {
			continue
		}
		dn.Name = name
		dn.ChainIdHex = strings.ToLower(strings.TrimSpace(dn.ChainIdHex))
		dn.Explorer = strings.TrimSpace(dn.Explorer)
		dn.RpcUrl = strings.TrimSpace(dn.RpcUrl)
		dn.EntryPoint = strings.TrimSpace(dn.EntryPoint)

		if dn.ChainIdHex == "" {
			// skip invalid config entries
			continue
		}

		// Do we already have it?
		if existingKey, ok := m.store.Networks[name]; ok {
			// fill blanks only
			updated := existingKey
			if updated.Explorer == "" && dn.Explorer != "" {
				updated.Explorer = dn.Explorer
				changed = true
			}
			if updated.RpcUrl == "" && dn.RpcUrl != "" {
				updated.RpcUrl = dn.RpcUrl
				changed = true
			}
			if updated.EntryPoint == "" && dn.EntryPoint != "" {
				updated.EntryPoint = dn.EntryPoint
				changed = true
			}
			if updated.ChainId == 0 && dn.ChainId != 0 {
				updated.ChainId = dn.ChainId
				changed = true
			}
			m.store.Networks[name] = updated
			continue
		}

		// Or match by chainIdHex (avoid duplicates if renamed)
		if key, ok := byChain[dn.ChainIdHex]; ok {
			// same chain exists under different name; fill blanks only
			updated := m.store.Networks[key]
			if updated.Explorer == "" && dn.Explorer != "" {
				updated.Explorer = dn.Explorer
				changed = true
			}
			if updated.RpcUrl == "" && dn.RpcUrl != "" {
				updated.RpcUrl = dn.RpcUrl
				changed = true
			}
			if updated.EntryPoint == "" && dn.EntryPoint != "" {
				updated.EntryPoint = dn.EntryPoint
				changed = true
			}
			if updated.ChainId == 0 && dn.ChainId != 0 {
				updated.ChainId = dn.ChainId
				changed = true
			}
			m.store.Networks[key] = updated
			continue
		}

		// Otherwise: add new network (config-added)
		m.store.Networks[name] = dn
		byChain[dn.ChainIdHex] = name
		changed = true
	}

	// Ensure file exists even if defaults empty (optional)
	if !exists(m.path) {
		changed = true
	}

	if changed {
		return m.persist(ctx)
	}
	return nil
}

func (m *Manager) List() []shared.Network {
	out := make([]shared.Network, 0, len(m.store.Networks))
	for _, n := range m.store.Networks {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func (m *Manager) ListFromFile(ctx context.Context) ([]shared.Network, error) {
	if err := m.ensureLoadedIfExists(ctx); err != nil {
		return nil, err
	}

	out := make([]shared.Network, 0, len(m.store.Networks))
	for _, n := range m.store.Networks {
		out = append(out, n)
	}
	// You already sort in List(); reuse if you want:
	// sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Manager) FindByChainIdHex(ctx context.Context, chainIdHex string) (shared.Network, bool, error) {
	if err := m.ensureLoadedIfExists(ctx); err != nil {
		return shared.Network{}, false, err
	}

	want := strings.ToLower(strings.TrimSpace(chainIdHex))
	if want == "" {
		return shared.Network{}, false, fmt.Errorf("missing chainIdHex")
	}

	// Normalize 0x prefix like you do elsewhere if needed:
	if !strings.HasPrefix(want, "0x") {
		want = "0x" + want
	}

	for _, n := range m.store.Networks {
		if strings.ToLower(strings.TrimSpace(n.ChainIdHex)) == want {
			return n, true, nil
		}
	}

	return shared.Network{}, false, nil
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
		// allow "1" -> "0x1" (optional; if you want strict, remove this)
		s = "0x" + s
	}
	return s
}

func normalizeRPCs(in []shared.RPC) []shared.RPC {
	out := make([]shared.RPC, 0, len(in))
	seen := map[string]bool{} // by url
	for _, r := range in {
		name := strings.TrimSpace(r.Name)
		url := strings.TrimSpace(r.Url)
		if url == "" {
			continue
		}
		key := strings.ToLower(url)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, shared.RPC{Name: name, Url: url})
	}
	return out
}

func (m *Manager) findKeyByChainIdHex(chainIdHex string) (string, bool) {
	ch := normalizeChainIdHex(chainIdHex)
	if ch == "" {
		return "", false
	}
	for k, n := range m.store.Networks {
		if normalizeChainIdHex(n.ChainIdHex) == ch {
			return k, true
		}
	}
	return "", false
}
