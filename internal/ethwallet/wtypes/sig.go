package wtypes

import "fmt"

func EnsureDigest32(d []byte) error {
	if len(d) != 32 {
		return fmt.Errorf("digest must be 32 bytes, got %d", len(d))
	}
	return nil
}

// SigToV27 converts V 0/1 -> 27/28 (some APIs expect this).
// If V is already 27/28, it leaves it unchanged.
func SigToV27(sig65 []byte) ([]byte, error) {
	if len(sig65) != 65 {
		return nil, fmt.Errorf("signature must be 65 bytes, got %d", len(sig65))
	}
	out := make([]byte, 65)
	copy(out, sig65)

	switch out[64] {
	case 0, 1:
		out[64] += 27
	case 27, 28:
		// ok
	default:
		return nil, fmt.Errorf("unexpected v value %d", out[64])
	}
	return out, nil
}
