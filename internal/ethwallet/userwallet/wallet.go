package userwallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/quantumauth-io/quantum-auth-client/internal/securefile"
)

const (
	AppName     = "quantumauth"
	WalletFile  = "wallet.json"
	AADConstant = "quantumauth:ethwallet:v1"
)

type Wallet struct {
	Version    int    `json:"version"`
	AddressHex string `json:"address"` // stored as hex string
	PrivKeyHex string `json:"priv_key_hex"`

	// Optional metadata
	CreatedAt string `json:"created_at,omitempty"` // RFC3339
}

type Store struct {
	Path string
	Opt  securefile.Options
}

func (w *Wallet) Address() common.Address {
	return common.HexToAddress(w.AddressHex)
}

func (w *Wallet) privateKey() (*ecdsa.PrivateKey, error) {
	b, err := hexToBytesStrict(w.PrivKeyHex)
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

// NewStore sets up a wallet store at the canonical config path.
func NewStore() (*Store, error) {
	paths, err := securefile.ConfigPathCandidates(AppName, WalletFile)
	if err != nil {
		return nil, err
	}

	return &Store{
		Path: paths[0],
		Opt: securefile.Options{
			// IMPORTANT: keep this identical for read + write.
			AADFunc: func(_ string) []byte { return []byte(AADConstant) },
		},
	}, nil
}

// Ensure loads an existing encrypted wallet or creates + persists a new one if missing.
func (s *Store) Ensure(password []byte) (*Wallet, error) {
	// Try read first.
	w, err := securefile.ReadEncryptedJSON[Wallet](s.Path, password, s.Opt)
	if err == nil {
		return &w, nil
	}

	// If file is missing, create it.
	if errors.Is(err, os.ErrNotExist) {
		nw, err := NewRandomWallet()
		if err != nil {
			return nil, err
		}
		if err := securefile.WriteEncryptedJSON(s.Path, *nw, password, s.Opt); err != nil {
			return nil, err
		}
		return nw, nil
	}

	// Any other error = decrypt fail / permission / corrupt file etc.
	return nil, fmt.Errorf("load wallet %s: %w", s.Path, err)
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

// --- helpers ---

func hexToBytesStrict(hexStr string) ([]byte, error) {
	// Accept hex without 0x prefix
	if len(hexStr) == 0 {
		return nil, errors.New("empty hex string")
	}
	// normalize
	if len(hexStr) >= 2 && (hexStr[0:2] == "0x" || hexStr[0:2] == "0X") {
		hexStr = hexStr[2:]
	}
	// must be 32 bytes for secp256k1 private key
	if len(hexStr) != 64 {
		return nil, fmt.Errorf("invalid privkey hex length: got %d want 64", len(hexStr))
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hi, ok := fromHexChar(hexStr[i*2])
		if !ok {
			return nil, fmt.Errorf("invalid hex char at %d", i*2)
		}
		lo, ok := fromHexChar(hexStr[i*2+1])
		if !ok {
			return nil, fmt.Errorf("invalid hex char at %d", i*2+1)
		}
		out[i] = (hi << 4) | lo
	}
	return out, nil
}

func fromHexChar(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
