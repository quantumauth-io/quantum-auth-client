package walletsigner

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/wtypes"
)

// Wallet is the minimal capability needed for personal_sign.
type Wallet interface {
	SignHash(ctx context.Context, digest []byte) ([]byte, error)
}

// WalletPicker selects the correct wallet for an address.
type WalletPicker interface {
	PickWallet(from common.Address) (wtypes.Wallet, error)
}

type Service struct {
	Pick WalletPicker
}

type PersonalSignRequest struct {
	Address common.Address
	Message string // raw input from JSON (could be hex or utf-8 depending on your current semantics)
}

type PersonalSignResult struct {
	Signature []byte
}

func (s *Service) PersonalSign(ctx context.Context, req PersonalSignRequest) (*PersonalSignResult, error) {
	if s == nil || s.Pick == nil {
		return nil, fmt.Errorf("walletsigner not initialized")
	}

	wallet, err := s.Pick.PickWallet(req.Address)
	if err != nil {

		return nil, err
	}

	msgBytes, err := ParsePersonalSignMessage(req.Message)
	if err != nil {
		return nil, fmt.Errorf("invalid message: %w", err)
	}

	digest := EIP191HashPersonalMessage(msgBytes)

	sig, err := wallet.SignHash(ctx, digest)
	if err != nil {
		return nil, fmt.Errorf("sign failed: %w", err)
	}

	return &PersonalSignResult{Signature: sig}, nil
}
