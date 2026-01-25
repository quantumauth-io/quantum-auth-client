package devkeys

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

type circlCryptoMLDSA65 struct {
	scheme sign.Scheme
}

func NewCIRCLCryptoMLDSA65() (Crypto, error) {
	s := schemes.ByName("ML-DSA-65")
	if s == nil {
		return nil, fmt.Errorf("PQ scheme ML-DSA-65 not found in CIRCL")
	}
	return &circlCryptoMLDSA65{scheme: s}, nil
}

func (c *circlCryptoMLDSA65) GenerateKeypair(ctx context.Context) (publicKeyB64 string, privateKeyBytes []byte, err error) {

	_ = ctx

	pk, sk, err := c.scheme.GenerateKey()
	if err != nil {
		return "", nil, fmt.Errorf("PQ keygen failed: %w", err)
	}

	pubBytes, err := pk.MarshalBinary()
	if err != nil {
		return "", nil, fmt.Errorf("PQ public key marshal failed: %w", err)
	}
	privBytes, err := sk.MarshalBinary()
	if err != nil {
		return "", nil, fmt.Errorf("PQ private key marshal failed: %w", err)
	}

	pubB64 := base64.RawStdEncoding.EncodeToString(pubBytes)
	return pubB64, privBytes, nil
}
