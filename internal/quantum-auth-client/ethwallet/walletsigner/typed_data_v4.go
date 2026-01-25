package walletsigner

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

type SignTypedDataV4Request struct {
	Address       common.Address
	TypedDataJSON string // raw JSON string from request
}

type SignTypedDataV4Result struct {
	Signature []byte
}

// SignTypedDataV4 computes the EIP-712 v4 digest from JSON then signs it.
func (s *Service) SignTypedDataV4(ctx context.Context, req SignTypedDataV4Request) (*SignTypedDataV4Result, error) {
	if s == nil || s.Pick == nil {
		return nil, fmt.Errorf("walletsigner not initialized")
	}
	if req.TypedDataJSON == "" {
		return nil, fmt.Errorf("empty typed data json")
	}

	wallet, err := s.Pick.PickWallet(req.Address)
	if err != nil {
		// caller maps to unauthorized
		return nil, err
	}

	digest, err := EIP712DigestV4(req.TypedDataJSON)
	if err != nil {
		return nil, fmt.Errorf("invalid typed data: %w", err)
	}

	sig, err := wallet.SignHash(ctx, digest)
	if err != nil {
		return nil, fmt.Errorf("sign failed: %w", err)
	}

	return &SignTypedDataV4Result{Signature: sig}, nil
}
