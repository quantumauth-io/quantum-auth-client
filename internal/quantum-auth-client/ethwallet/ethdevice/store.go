package ethdevice

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/constants"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/securefile"
	"github.com/quantumauth-io/quantum-go-utils/tpmdevice"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	AppName        = "quantumauth"
	DeviceFileName = "device_wallet.json"

	// Scope the sealed DEK so it can’t be mixed with other sealed blobs.
	SealerLabel = "quantumauth:ethdevice:dek:v1"

	// AAD for payload encryption (must match on decrypt).
	PayloadAAD = "quantumauth:ethdevice:payload:v1"
)

type Store struct {
	Path   string
	Sealer tpmdevice.Sealer
}

func (s *Store) decryptPrivKeyBytes(ctx context.Context, wf deviceWalletFile) ([]byte, error) {
	if wf.Version != 1 {
		return nil, fmt.Errorf("unsupported device wallet version: %d", wf.Version)
	}

	nonce, err := base64.StdEncoding.DecodeString(wf.NonceB64)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(wf.CTB64)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	sealed, err := base64.StdEncoding.DecodeString(wf.SealedDEKB64)
	if err != nil {
		return nil, fmt.Errorf("decode sealed dek: %w", err)
	}

	dek, err := s.Sealer.Unseal(ctx, SealerLabel, sealed)
	if err != nil {
		return nil, fmt.Errorf("unseal dek: %w", err)
	}
	if len(dek) != 32 {
		return nil, fmt.Errorf("unexpected dek length: %d", len(dek))
	}
	defer zeroBytes(dek)

	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, fmt.Errorf("aead: %w", err)
	}

	plainJSON, err := aead.Open(nil, nonce, ct, []byte(PayloadAAD))
	if err != nil {
		return nil, errors.New("device wallet decrypt failed (TPM policy changed or file corrupted)")
	}

	var plain deviceWalletPlain
	if err := json.Unmarshal(plainJSON, &plain); err != nil {
		return nil, fmt.Errorf("unmarshal plain: %w", err)
	}

	privBytes, err := hexToBytes32(plain.PrivKeyHex)
	if err != nil {
		return nil, fmt.Errorf("privkey hex: %w", err)
	}
	return privBytes, nil
}

// NewStore chooses canonical config path and binds to your TPM sealer.
func NewStore(sealer tpmdevice.Sealer) (*Store, error) {
	if sealer == nil {
		return nil, errors.New("ethdevice: sealer is required")
	}
	paths, err := securefile.ConfigPathCandidates(constants.AppName, constants.DeviceFileName)
	if err != nil {
		return nil, err
	}
	return &Store{
		Path:   paths[0],
		Sealer: sealer,
	}, nil
}

// Ensure loads device wallet if present; otherwise creates + persists one.
func (s *Store) Ensure(ctx context.Context) (*DeviceWallet, error) {
	wf, err := s.readFile()
	if err == nil {
		return s.loadWalletMeta(ctx, wf)
	}
	if errors.Is(err, os.ErrNotExist) {
		w, wf, err := s.createNew(ctx)
		if err != nil {
			return nil, err
		}
		if err := s.writeFile(wf); err != nil {
			return nil, err
		}
		return w, nil
	}
	return nil, err
}

type deviceWalletFile struct {
	Version int `json:"version"`

	Address   string `json:"address"`
	CreatedAt string `json:"created_at,omitempty"`

	NonceB64 string `json:"nonce_b64"`
	CTB64    string `json:"ct_b64"`

	SealedDEKB64 string `json:"sealed_dek_b64"`
}

type deviceWalletPlain struct {
	PrivKeyHex string `json:"priv_key_hex"` // 64 hex chars
}

func (s *Store) createNew(ctx context.Context) (*DeviceWallet, deviceWalletFile, error) {
	// 1) Create eth key
	key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, deviceWalletFile{}, fmt.Errorf("generate key: %w", err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)

	// 2) Random DEK
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, deviceWalletFile{}, fmt.Errorf("rand dek: %w", err)
	}

	// 3) Seal DEK with TPM
	sealed, err := s.Sealer.Seal(ctx, SealerLabel, dek)
	if err != nil {
		return nil, deviceWalletFile{}, fmt.Errorf("seal dek: %w", err)
	}

	// 4) Encrypt plaintext payload with DEK
	plain := deviceWalletPlain{PrivKeyHex: fmt.Sprintf("%x", crypto.FromECDSA(key))}
	plainJSON, err := json.Marshal(plain)
	if err != nil {
		return nil, deviceWalletFile{}, fmt.Errorf("marshal plain: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, deviceWalletFile{}, fmt.Errorf("rand nonce: %w", err)
	}

	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, deviceWalletFile{}, fmt.Errorf("aead: %w", err)
	}

	ct := aead.Seal(nil, nonce, plainJSON, []byte(PayloadAAD))

	wf := deviceWalletFile{
		Version:      1,
		Address:      addr.Hex(),
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		NonceB64:     base64.StdEncoding.EncodeToString(nonce),
		CTB64:        base64.StdEncoding.EncodeToString(ct),
		SealedDEKB64: base64.StdEncoding.EncodeToString(sealed),
	}

	return &DeviceWallet{addr: addr, store: s}, wf, nil
}

func (s *Store) loadWalletMeta(ctx context.Context, wf deviceWalletFile) (*DeviceWallet, error) {
	if wf.Version != 1 {
		return nil, fmt.Errorf("unsupported device wallet version: %d", wf.Version)
	}

	nonce, err := base64.StdEncoding.DecodeString(wf.NonceB64)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(wf.CTB64)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	sealed, err := base64.StdEncoding.DecodeString(wf.SealedDEKB64)
	if err != nil {
		return nil, fmt.Errorf("decode sealed dek: %w", err)
	}

	// Unseal DEK with TPM
	dek, err := s.Sealer.Unseal(ctx, SealerLabel, sealed)
	if err != nil {
		return nil, fmt.Errorf("unseal dek: %w", err)
	}
	if len(dek) != 32 {
		return nil, fmt.Errorf("unexpected dek length: %d", len(dek))
	}

	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, fmt.Errorf("aead: %w", err)
	}

	plainJSON, err := aead.Open(nil, nonce, ct, []byte(PayloadAAD))
	if err != nil {
		return nil, errors.New("device wallet decrypt failed (TPM policy changed or file corrupted)")
	}

	var plain deviceWalletPlain
	if err := json.Unmarshal(plainJSON, &plain); err != nil {
		return nil, fmt.Errorf("unmarshal plain: %w", err)
	}

	privBytes, err := hexToBytes32(plain.PrivKeyHex)
	if err != nil {
		return nil, fmt.Errorf("privkey hex: %w", err)
	}

	key, err := crypto.ToECDSA(privBytes)
	if err != nil {
		return nil, fmt.Errorf("to ecdsa: %w", err)
	}

	addr := common.HexToAddress(wf.Address)
	derived := crypto.PubkeyToAddress(key.PublicKey)
	if derived != addr {
		return nil, errors.New("device wallet mismatch: address does not match private key")
	}

	return &DeviceWallet{addr: addr, store: s}, nil
}

func (s *Store) readFile() (deviceWalletFile, error) {
	var wf deviceWalletFile
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return wf, os.ErrNotExist
		}
		return wf, fmt.Errorf("read %s: %w", s.Path, err)
	}
	if err := json.Unmarshal(b, &wf); err != nil {
		return wf, fmt.Errorf("unmarshal %s: %w", s.Path, err)
	}
	return wf, nil
}

func (s *Store) writeFile(wf deviceWalletFile) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(s.Path), err)
	}
	b, err := json.MarshalIndent(wf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal device file: %w", err)
	}
	return atomicWriteFile(s.Path, b, 0o600)
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

func hexToBytes32(hexStr string) ([]byte, error) {
	if len(hexStr) >= 2 && (hexStr[0:2] == "0x" || hexStr[0:2] == "0X") {
		hexStr = hexStr[2:]
	}
	if len(hexStr) != 64 {
		return nil, fmt.Errorf("invalid length: got %d want 64", len(hexStr))
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

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
