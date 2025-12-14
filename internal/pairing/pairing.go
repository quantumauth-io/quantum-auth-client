package pairing

import (
	crand "crypto/rand"
	"crypto/sha256"
)

func GeneratePairCode() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no 0 O I 1
	const length = 8

	b := make([]byte, length)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}

	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}

	return string(b), nil
}

func HashCode(code string) []byte {
	h := sha256.Sum256([]byte(code))
	return h[:]
}
