package state

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"fyne.io/fyne/v2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

type VaultFlags struct {
	WalletCreated         bool `json:"walletCreated"`
	RegistrationCompleted bool `json:"registrationCompleted"`
	ExtensionPaired       bool `json:"extensionPaired"`
	PairTokenGenerated    bool `json:"pairTokenGenerated"`
}

type VaultIdentity struct {
	UserID   string `json:"userId"`
	DeviceID string `json:"deviceId"`
}

type vaultFile struct {
	Version int    `json:"v"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	CT      []byte `json:"ct"`
}

// Payload lives encrypted inside CT.
type VaultPayload struct {
	Version   int         `json:"v"`
	CreatedAt time.Time   `json:"createdAt"`
	UpdatedAt time.Time   `json:"updatedAt"`
	Settings  GUISettings `json:"settings"`
	Flags     VaultFlags  `json:"flags"`

	Identity  *VaultIdentity `json:"identity,omitempty"`
	PairToken string         `json:"pairToken,omitempty"`
}

const (
	vaultFileVersion    = 2
	vaultPayloadVersion = 1

	// For v1 compatibility (your previous design)
	vaultMagicV1 = "QA_VAULT_V1"
)

func vaultPath() (string, error) {
	app := fyne.CurrentApp()
	if app == nil {
		return "", errors.New("fyne app not initialized")
	}
	dir := app.Storage().RootURI().Path()
	return filepath.Join(dir, "vault.json"), nil
}

func VaultExists() (bool, error) {
	p, err := vaultPath()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(p)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func CreateVaultWithPayload(password string, payload VaultPayload) (*VaultPayload, error) {
	if len(password) < 8 {
		return nil, errors.New("password must be at least 8 characters")
	}

	p, err := vaultPath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}

	// Ensure payload timestamps
	now := time.Now()
	if payload.Version == 0 {
		payload.Version = vaultPayloadVersion
	}
	if payload.CreatedAt.IsZero() {
		payload.CreatedAt = now
	}
	payload.UpdatedAt = now

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}

	key := deriveKey(password, salt)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	pt, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	ct := aead.Seal(nil, nonce, pt, nil)

	vf := &vaultFile{
		Version: vaultFileVersion,
		Salt:    salt,
		Nonce:   nonce,
		CT:      ct,
	}

	if err := writeVaultFile(p, vf); err != nil {
		return nil, err
	}

	return &payload, nil
}

// UnlockVault verifies the password and returns the decrypted payload.
func UnlockVault(password string) (*VaultPayload, error) {
	p, err := vaultPath()
	if err != nil {
		return nil, err
	}

	vf, err := readVaultFile(p)
	if err != nil {
		return nil, err
	}

	key := deriveKey(password, vf.Salt)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	pt, err := aead.Open(nil, vf.Nonce, vf.CT, nil)
	if err != nil {
		return nil, errors.New("wrong password")
	}

	// v1 compatibility: previously plaintext was vaultMagicV1
	if vf.Version == 1 {
		if string(pt) == vaultMagicV1 {
			// Upgrade path: return empty payload; caller can SaveVaultPayload.
			return &VaultPayload{
				Version:   vaultPayloadVersion,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				Settings:  GUISettings{},
			}, nil
		}
		return nil, errors.New("wrong password")
	}

	var payload VaultPayload
	if err := json.Unmarshal(pt, &payload); err != nil {
		return nil, fmt.Errorf("vault payload decode failed: %w", err)
	}
	return &payload, nil
}

// SaveVaultPayload updates the vault contents using the provided password (password unchanged).
func SaveVaultPayload(password string, payload VaultPayload) error {
	p, err := vaultPath()
	if err != nil {
		return err
	}

	vf, err := readVaultFile(p)
	if err != nil {
		return err
	}

	// Verify first (ensures wrong password doesn't overwrite)
	if _, err := UnlockVault(password); err != nil {
		return err
	}

	payload.UpdatedAt = time.Now()
	if payload.Version == 0 {
		payload.Version = vaultPayloadVersion
	}

	key := deriveKey(password, vf.Salt)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}

	pt, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	vf.Version = vaultFileVersion
	vf.Nonce = nonce
	vf.CT = aead.Seal(nil, nonce, pt, nil)

	return writeVaultFile(p, vf)
}

// ChangeVaultPassword re-encrypts the vault payload under a new password.
func ChangeVaultPassword(oldPassword, newPassword string) error {
	if len(newPassword) < 8 {
		return errors.New("new password must be at least 8 characters")
	}

	payload, err := UnlockVault(oldPassword)
	if err != nil {
		return err
	}

	// Create new salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("salt: %w", err)
	}

	key := deriveKey(newPassword, salt)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}

	payload.UpdatedAt = time.Now()
	pt, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	vf := &vaultFile{
		Version: vaultFileVersion,
		Salt:    salt,
		Nonce:   nonce,
		CT:      aead.Seal(nil, nonce, pt, nil),
	}

	p, err := vaultPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return writeVaultFile(p, vf)
}

func readVaultFile(path string) (*vaultFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vf vaultFile
	if err := json.Unmarshal(b, &vf); err != nil {
		return nil, err
	}
	if vf.Version != 1 && vf.Version != 2 {
		return nil, fmt.Errorf("unsupported vault version: %d", vf.Version)
	}
	if len(vf.Salt) == 0 || len(vf.Nonce) == 0 || len(vf.CT) == 0 {
		return nil, errors.New("vault is corrupted")
	}
	return &vf, nil
}

func writeVaultFile(path string, vf *vaultFile) error {
	b, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
}
