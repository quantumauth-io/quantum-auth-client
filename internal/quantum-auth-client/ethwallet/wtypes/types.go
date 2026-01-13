package wtypes

import (
	"context"
	"crypto/ecdsa"
	"errors"

	"github.com/ethereum/go-ethereum/common"
)

var ErrNotExportable = errors.New("private key is not exportable")

// Wallet is the unified interface for any EOA-like signer we expose.
//   - Device wallets MUST return ErrNotExportable for ExportPrivateKey.
//   - User wallets MAY export.
//   - SignHash signs a 32-byte digest and returns a 65-byte signature (R || S || V),
//     where V is 0/1 as produced by go-ethereum's crypto.Sign.
type Wallet interface {
	Address() common.Address
	SignHash(ctx context.Context, digest32 []byte) ([]byte, error)
	ExportPrivateKey(ctx context.Context) (*ecdsa.PrivateKey, error)
}

type TPMBackedWallet interface {
	Wallet
	TPMKeyID() [32]byte
}
