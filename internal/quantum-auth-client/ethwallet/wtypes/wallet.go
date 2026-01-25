package wtypes

import (
	"context"
	"crypto/ecdsa"
	"errors"

	"github.com/ethereum/go-ethereum/common"
)

var ErrNotExportable = errors.New("private key is not exportable")

type Wallet interface {
	Address() common.Address
	SignHash(ctx context.Context, digest32 []byte) ([]byte, error)
	ExportPrivateKey(ctx context.Context) (*ecdsa.PrivateKey, error)
}

type TPMBackedWallet interface {
	Wallet
	TPMKeyID() [32]byte
}
