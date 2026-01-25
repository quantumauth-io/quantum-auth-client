package userwallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet"
)

type Wallet struct {
	Version    int    `json:"version"`
	AddressHex string `json:"address"`
	PrivKeyHex string `json:"priv_key_hex"`
	CreatedAt  string `json:"created_at,omitempty"`
}

func NewRandomWallet() (*Wallet, error) {
	// Generate secp256k1 key
	key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	privBytes := crypto.FromECDSA(key)
	privHex := fmt.Sprintf("%x", privBytes)

	addr := crypto.PubkeyToAddress(key.PublicKey)

	return &Wallet{
		Version:    1,
		AddressHex: addr.Hex(),
		PrivKeyHex: privHex,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (w *Wallet) Address() common.Address {
	return common.HexToAddress(w.AddressHex)
}

func (w *Wallet) privateKey() (*ecdsa.PrivateKey, error) {
	b, err := ethwallet.HexToBytesStrict(w.PrivKeyHex)
	if err != nil {
		return nil, err
	}
	k, err := crypto.ToECDSA(b)
	if err != nil {
		return nil, fmt.Errorf("to ecdsa: %w", err)
	}
	return k, nil
}

func (w *Wallet) ExportPrivateKey(ctx context.Context) (*ecdsa.PrivateKey, error) {
	_ = ctx // no-op for user wallet
	return w.privateKey()
}

func (w *Wallet) SignHash(ctx context.Context, digest32 []byte) ([]byte, error) {
	_ = ctx // unused for now; keeps interface symmetric

	if len(digest32) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes, got %d", len(digest32))
	}

	key, err := w.privateKey()
	if err != nil {
		return nil, err
	}
	return crypto.Sign(digest32, key) // returns V=0/1
}
