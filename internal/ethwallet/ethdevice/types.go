package ethdevice

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
)

var ErrNotExportable = errors.New("device wallet key is not exportable")

type Wallet interface {
	Address() common.Address
	SignHash(digest32 []byte) ([]byte, error)
	// Deliberately non-exportable
	ExportPrivateKey() error
}
