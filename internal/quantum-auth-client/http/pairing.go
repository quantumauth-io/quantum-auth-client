package http

import (
	"fmt"
	"os"
	"strings"
)

// loadPairingToken loads the extension pairing token from disk.
// The token is treated as opaque bytes stored as text.
// Missing file = not paired yet.
func loadPairingToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("empty pairing token")
	}

	return token, nil
}
