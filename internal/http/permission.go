package http

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// On-disk representation
type permissionFile struct {
	Allowed map[string]bool `json:"allowed"`
	Updated string          `json:"updated,omitempty"`
}

// PermissionStore is the authoritative allowlist for domains
type PermissionStore struct {
	mu      sync.RWMutex
	path    string
	allowed map[string]bool
}

// NewPermissionStore creates a new store backed by a JSON file.
func NewPermissionStore(path string) *PermissionStore {
	return &PermissionStore{
		path:    path,
		allowed: make(map[string]bool),
	}
}

// Load reads the allowlist from disk.
// Missing file = empty allowlist (first run).
func (ps *PermissionStore) Load() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	b, err := os.ReadFile(ps.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read permissions file: %w", err)
	}

	var pf permissionFile
	if err := json.Unmarshal(b, &pf); err != nil {
		return fmt.Errorf("parse permissions file: %w", err)
	}

	if pf.Allowed == nil {
		pf.Allowed = make(map[string]bool)
	}

	ps.allowed = pf.Allowed
	return nil
}

// Save writes the allowlist to disk.
func (ps *PermissionStore) Save() error {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(ps.path), 0o700); err != nil {
		return fmt.Errorf("mkdir permissions dir: %w", err)
	}

	pf := permissionFile{
		Allowed: ps.allowed,
		Updated: time.Now().UTC().Format(time.RFC3339),
	}

	b, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal permissions: %w", err)
	}

	if err := os.WriteFile(ps.path, b, 0o600); err != nil {
		return fmt.Errorf("write permissions file: %w", err)
	}

	return nil
}

// IsAllowed checks whether an origin is allowed.
func (ps *PermissionStore) IsAllowed(origin string) bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.allowed[origin]
}

// Set updates permission for an origin and persists it.
func (ps *PermissionStore) Set(origin string, allowed bool) error {
	ps.mu.Lock()
	ps.allowed[origin] = allowed
	ps.mu.Unlock()

	if err := ps.Save(); err != nil {
		return err
	}

	return nil
}

// List returns a copy of the allowlist (safe for JSON responses).
func (ps *PermissionStore) List() map[string]bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	out := make(map[string]bool, len(ps.allowed))
	for k, v := range ps.allowed {
		out[k] = v
	}
	return out
}
