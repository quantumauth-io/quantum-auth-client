package http

import (
	"fmt"
	"os"
	"path/filepath"
)

// qaConfigDir returns the canonical directory where the QA client can
// persist local state (allowlist, pairing token, etc.).
//
// Priority:
//  1. SNAP_REAL_HOME (snap installs)
//  2. HOME (normal installs)
//  3. os.UserConfigDir() fallback
func qaConfigDir() (string, error) {
	// Snap: use the real user home, not the confined snap home
	if realHome := os.Getenv("SNAP_REAL_HOME"); realHome != "" {
		return filepath.Join(realHome, ".config", "quantumauth"), nil
	}

	// Normal environment
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".config", "quantumauth"), nil
	}

	// Fallback
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("UserConfigDir: %w", err)
	}
	return filepath.Join(dir, "quantumauth"), nil
}

// permissionsFilePath is where we store the origin allowlist.
func permissionsFilePath() (string, error) {
	dir, err := qaConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "allowed_origins.json"), nil
}

// pairingTokenFilePath is where the agent/UI writes the extension pairing token.
// The extension will copy/paste this token and then include it as X-QA-Extension.
func pairingTokenFilePath() (string, error) {
	dir, err := qaConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "extension_pair_token.txt"), nil
}
