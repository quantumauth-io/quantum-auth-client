package ethdevice

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/quantumauth-io/quantum-auth-client/internal/ethwallet/wtypes"
)

type DeviceWallet struct {
	addr  common.Address
	store *Store // whatever your concrete type is
}

func (w *DeviceWallet) Address() common.Address { return w.addr }

func (w *DeviceWallet) ExportPrivateKey(ctx context.Context) (*ecdsa.PrivateKey, error) {
	_ = ctx
	return nil, wtypes.ErrNotExportable
}
func (w *DeviceWallet) TPMKeyID() [32]byte {
	var out [32]byte
	copy(out[12:], w.addr.Bytes())
	return out
}

// SignHash expects a 32-byte digest (already hashed). Returns 65-byte sig (R||S||V, V=0/1).
func (w *DeviceWallet) SignHash(ctx context.Context, digest32 []byte) ([]byte, error) {
	if len(digest32) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes, got %d", len(digest32))
	}
	if w == nil || w.store == nil {
		return nil, fmt.Errorf("ethdevice: wallet not initialized")
	}

	// Load file each time (simple + safe). We can add caching later.
	wf, err := w.store.readFile()
	if err != nil {
		return nil, fmt.Errorf("read device wallet: %w", err)
	}

	// Decrypt private key bytes (32 bytes)
	priv32, err := w.store.decryptPrivKeyBytes(ctx, wf)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(priv32)

	key, err := crypto.ToECDSA(priv32)
	if err != nil {
		return nil, fmt.Errorf("to ecdsa: %w", err)
	}

	sig, err := crypto.Sign(digest32, key)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return sig, nil
}
