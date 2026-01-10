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
		s.Networks = map[string]Network{}
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
func (m *Manager) EnsureFromConfig(ctx context.Context, defaults []Network) error {
	if err := m.ensureLoadedIfExists(ctx); err != nil {
		return err
	}
	if m.store.Schema == 0 {
		m.store.Schema = constants.SchemaV1
	}
	if m.store.Networks == nil {
		m.store.Networks = map[string]Network{}
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

func (m *Manager) List() []Network {
	out := make([]Network, 0, len(m.store.Networks))
	for _, n := range m.store.Networks {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
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
