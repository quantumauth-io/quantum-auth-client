package ethwallet

import (
	"errors"
	"fmt"
)

// --- helpers ---

func HexToBytesStrict(hexStr string) ([]byte, error) {
	// Accept hex without 0x prefix
	if len(hexStr) == 0 {
		return nil, errors.New("empty hex string")
	}
	// normalize
	if len(hexStr) >= 2 && (hexStr[0:2] == "0x" || hexStr[0:2] == "0X") {
		hexStr = hexStr[2:]
	}
	// must be 32 bytes for secp256k1 private key
	if len(hexStr) != 64 {
		return nil, fmt.Errorf("invalid privkey hex length: got %d want 64", len(hexStr))
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hi, ok := fromHexChar(hexStr[i*2])
		if !ok {
			return nil, fmt.Errorf("invalid hex char at %d", i*2)
		}
		lo, ok := fromHexChar(hexStr[i*2+1])
		if !ok {
			return nil, fmt.Errorf("invalid hex char at %d", i*2+1)
		}
		out[i] = (hi << 4) | lo
	}
	return out, nil
}

func fromHexChar(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
