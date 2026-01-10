package assets

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/quantumauth-io/quantum-auth-client/internal/constants"
	"github.com/quantumauth-io/quantum-auth-client/internal/securefile"
	"github.com/quantumauth-io/quantum-go-utils/ethrpc"
)

type Manager struct {
	path       string
	clients    *ethrpc.Client
	store      Store
	fetchDelay time.Duration
}

// NewManager resolves assets.json path using securefile.ConfigPathCandidates.
// It picks the first existing candidate, else the first candidate as the target path.
func NewManager(clients *ethrpc.Client) (*Manager, error) {
	if strings.TrimSpace(constants.AppName) == "" {
		return nil, fmt.Errorf("appName must not be empty")
	}

	path, err := resolveAssetsPath(constants.AppName)
	if err != nil {
		return nil, err
	}

	m := &Manager{
		path:    path,
		clients: clients,
		store: Store{
			Schema:   constants.SchemaV1,
			Networks: map[string]map[string]Asset{},
		},
		fetchDelay: 500 * time.Millisecond,
	}
	return m, nil
}

// Path returns the resolved assets.json path.
func (m *Manager) Path() string { return m.path }

func (m *Manager) backendForNetwork(network string) bind.ContractBackend {
	return m.clients.Backend()
}

// EnsureStore:
// - if assets.json exists: loads it
// - else: builds store from defaults by fetching token metadata, then writes assets.json
func (m *Manager) EnsureStore(ctx context.Context, defaults map[string][]string) error {
	if exists(m.path) {
		return m.Load(ctx)
	}

	s := Store{
		Schema:   constants.SchemaV1,
		Networks: map[string]map[string]Asset{},
	}

	for netKey, addrs := range defaults {
		nk := normalizeNetworkKey(netKey)
		if nk == "" {
			continue
		}
		if _, ok := s.Networks[nk]; !ok {
			s.Networks[nk] = map[string]Asset{}
		}

		for _, raw := range addrs {
			addr, err := normalizeAddress(raw)
			if err != nil {
				return fmt.Errorf("defaults[%s]: %w", netKey, err)
			}

			a, err := m.fetchAsset(ctx, nk, addr)
			if err != nil {
				return fmt.Errorf("fetch asset %s[%s]: %w", nk, addr, err)
			}

			s.Networks[nk][a.Address] = a
		}
	}

	m.store = s
	return m.persist(ctx)
}

// Load reads assets.json into memory (plain JSON).
func (m *Manager) Load(ctx context.Context) error {
	_ = ctx // reserved if you later want context-aware IO

	b, err := os.ReadFile(m.path)
	if err != nil {
		return fmt.Errorf("read assets file: %w", err)
	}

	var s Store
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("unmarshal assets file: %w", err)
	}
	if s.Schema == 0 {
		s.Schema = constants.SchemaV1
	}
	if s.Networks == nil {
		s.Networks = map[string]map[string]Asset{}
	}

	// normalize network keys + addresses on load (defensive)
	normalized := Store{Schema: s.Schema, Networks: map[string]map[string]Asset{}}
	for netKey, byAddr := range s.Networks {
		nk := normalizeNetworkKey(netKey)
		if nk == "" {
			continue
		}
		if normalized.Networks[nk] == nil {
			normalized.Networks[nk] = map[string]Asset{}
		}
		for addrKey, asset := range byAddr {
			addr, err := normalizeAddress(addrKey)
			if err != nil {
				// skip bad entries rather than hard-fail; your call
				continue
			}
			asset.Address = addr
			normalized.Networks[nk][addr] = asset
		}
	}

	m.store = normalized
	return nil
}

func (m *Manager) EnsureStoreForNetwork(ctx context.Context, network string, defaultAddrs []string) error {
	nk := normalizeNetworkKey(network)
	if nk == "" {
		return fmt.Errorf("network must not be empty")
	}

	// Load if exists (don’t overwrite user-added assets)
	if exists(m.path) {
		if err := m.Load(ctx); err != nil {
			return err
		}
	}

	if m.store.Networks == nil {
		m.store.Networks = map[string]map[string]Asset{}
	}
	if m.store.Schema == 0 {
		m.store.Schema = constants.SchemaV1
	}
	if m.store.Networks[nk] == nil {
		m.store.Networks[nk] = map[string]Asset{}
	}

	changed := false

	for _, raw := range defaultAddrs {
		addr, err := normalizeAddress(raw)
		if err != nil {
			return fmt.Errorf("defaults[%s]: %w", nk, err)
		}

		// already present? skip
		if _, ok := m.store.Networks[nk][addr]; ok {
			continue
		}

		if m.fetchDelay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(m.fetchDelay):
			}
		}

		a, err := m.fetchAsset(ctx, nk, addr)
		if err != nil {
			return fmt.Errorf("fetch asset %s[%s]: %w", nk, addr, err)
		}

		m.store.Networks[nk][a.Address] = a
		changed = true
	}

	// If file didn’t exist, we should write it even if defaults were empty (optional).
	if !exists(m.path) {
		changed = true
	}

	if changed {
		return m.persist(ctx)
	}
	return nil
}

func (m *Manager) GetStore() Store {
	return m.store
}

func (m *Manager) ListAssets(network string) []Asset {
	nk := normalizeNetworkKey(network)
	byAddr := m.store.Networks[nk]
	if byAddr == nil {
		return nil
	}

	out := make([]Asset, 0, len(byAddr))
	for _, a := range byAddr {
		out = append(out, a)
	}

	// stable for UI
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Symbol) < strings.ToLower(out[j].Symbol)
	})
	return out
}

func (m *Manager) ListForNetwork(ctx context.Context, network string) ([]Asset, error) {
	_ = ctx

	nk := normalizeNetworkKey(network)
	if nk == "" {
		return []Asset{}, nil
	}

	byAddr := m.store.Networks[nk]
	if byAddr == nil {
		return []Asset{}, nil
	}

	out := make([]Asset, 0, len(byAddr))
	for _, a := range byAddr {
		out = append(out, a)
	}

	// stable order for UI
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Symbol) < strings.ToLower(out[j].Symbol)
	})

	return out, nil
}

func (m *Manager) AddAsset(ctx context.Context, network string, address string) (Asset, error) {
	nk := normalizeNetworkKey(network)
	addr, err := normalizeAddress(address)
	if err != nil {
		return Asset{}, err
	}

	if err := m.ensureLoadedIfExists(ctx); err != nil {
		return Asset{}, err
	}
	if m.store.Networks[nk] == nil {
		m.store.Networks[nk] = map[string]Asset{}
	}

	a, err := m.fetchAsset(ctx, nk, addr)
	if err != nil {
		return Asset{}, err
	}

	m.store.Networks[nk][a.Address] = a
	if err := m.persist(ctx); err != nil {
		return Asset{}, err
	}
	return a, nil
}

func (m *Manager) RemoveAsset(ctx context.Context, network string, address string) error {
	nk := normalizeNetworkKey(network)
	addr, err := normalizeAddress(address)
	if err != nil {
		return err
	}

	if err := m.ensureLoadedIfExists(ctx); err != nil {
		return err
	}

	byAddr := m.store.Networks[nk]
	if byAddr == nil {
		return nil
	}

	delete(byAddr, addr)
	if len(byAddr) == 0 {
		delete(m.store.Networks, nk)
	}

	return m.persist(ctx)
}

func (m *Manager) ensureLoadedIfExists(ctx context.Context) error {
	// if we already have something loaded, skip
	if m.store.Networks != nil && len(m.store.Networks) > 0 {
		return nil
	}
	if exists(m.path) {
		return m.Load(ctx)
	}
	// no file yet => keep empty store
	m.store = Store{Schema: constants.SchemaV1, Networks: map[string]map[string]Asset{}}
	return nil
}

func (m *Manager) persist(ctx context.Context) error {
	_ = ctx

	if err := os.MkdirAll(filepath.Dir(m.path), constants.DirectoryPerm); err != nil {
		return fmt.Errorf("mkdir assets dir: %w", err)
	}

	b, err := json.MarshalIndent(m.store, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal assets store: %w", err)
	}

	// atomic write via your securefile package
	return securefile.AtomicWriteFile(m.path, b, constants.FilePerm)
}

func resolveAssetsPath(appName string) (string, error) {
	cands, err := securefile.ConfigPathCandidates(appName, constants.AssetsFile)
	if err != nil {
		return "", err
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("no config path candidates returned")
	}

	// pick first existing, else first candidate
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

// normalizeAddress => checksummed canonical form
func normalizeAddress(addr string) (string, error) {
	a := strings.TrimSpace(addr)
	if a == "" {
		return "", fmt.Errorf("empty address")
	}
	if !strings.HasPrefix(a, "0x") && !strings.HasPrefix(a, "0X") {
		a = "0x" + a
	}
	a = strings.ToLower(a)
	if !common.IsHexAddress(a) {
		return "", fmt.Errorf("invalid address: %q", addr)
	}
	return common.HexToAddress(a).Hex(), nil
}
