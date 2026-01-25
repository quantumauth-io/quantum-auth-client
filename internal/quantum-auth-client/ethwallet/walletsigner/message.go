package walletsigner

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func ParsePersonalSignMessage(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty message")
	}

	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		raw := s[2:]
		if raw == "" {
			return []byte{}, nil
		}

		if len(raw)%2 == 1 {
			raw = "0" + raw
		}
		b, err := hex.DecodeString(raw)
		if err != nil {
			return nil, err
		}
		return b, nil
	}

	return []byte(s), nil
}
