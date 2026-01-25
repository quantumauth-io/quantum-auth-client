package walletsigner

import (
	"encoding/hex"
	"fmt"
)

func SigToHex(sig []byte) (string, error) {
	if len(sig) == 0 {
		return "", fmt.Errorf("empty signature")
	}
	return "0x" + hex.EncodeToString(sig), nil
}
