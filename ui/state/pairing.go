package state

import (
	"crypto/rand"
	"encoding/base64"
)

func GeneratePairToken() (string, error) {
	b := make([]byte, 32) // 256-bit token
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// URL-safe, no padding is nice for copy/paste
	return base64.RawURLEncoding.EncodeToString(b), nil
}
