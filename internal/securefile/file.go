// Package securefile provides encrypted JSON file read/write with atomic writes.
// Uses Argon2id for KDF and XChaCha20-Poly1305 for AEAD.
package securefile

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/quantumauth-io/quantum-go-utils/log"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	// ErrInvalidPasswordOrCorrupt is returned when decryption fails.
	// Keep this generic to avoid leaking details.
	ErrInvalidPasswordOrCorrupt = errors.New("invalid password or corrupted file")
)

// KDFParams describes the on-disk encryption envelope.
// NOTE: now supports both password-derived and TPM-derived keys.
type KDFParams struct {
	Version int    `json:"version"`
	Mode    string `json:"mode,omitempty"` // "password" (default) or "tpm"

	// Argon2id params (password mode)
	ArgonTime    uint32 `json:"argon_time,omitempty"`
	ArgonMemory  uint32 `json:"argon_memory_kib,omitempty"`
	ArgonThreads uint8  `json:"argon_threads,omitempty"`
	ArgonKeyLen  uint32 `json:"argon_key_len,omitempty"`
	SaltB64      string `json:"salt_b64,omitempty"`

	// TPM mode
	SealedDEKB64 string `json:"sealed_dek_b64,omitempty"`

	// Envelope (both modes)
	NonceB64 string `json:"nonce_b64"`
	CTB64    string `json:"ct_b64"`
}

var DefaultKDF = KDFParams{
	Version:      2,
	Mode:         "password",
	ArgonTime:    2,
	ArgonMemory:  64 * 1024,
	ArgonThreads: 1,
	ArgonKeyLen:  32,
}

// Options controls encryption behavior.
type Options struct {
	KDF KDFParams

	FilePerm      os.FileMode
	DirectoryPerm os.FileMode

	AADFunc func(path string) []byte

	// TPM support (optional)
	TPMSealer TPMSealer // interface; keep securefile independent from tpmdevice package
	TPMLabel  string    // used to scope the sealed DEK
}

// TPMSealer is implemented by  tpmdevice.Sealer.
type TPMSealer interface {
	Seal(ctx context.Context, label string, secret []byte) ([]byte, error)
	Unseal(ctx context.Context, label string, blob []byte) ([]byte, error)
}

// ReadEncryptedJSONAuto tries TPM first, then falls back to password with warning.
func ReadEncryptedJSONAuto[T any](ctx context.Context, path string, password []byte, opt ...Options) (T, error) {
	o := mergeOptions(opt...)

	if o.TPMSealer != nil && o.TPMLabel != "" {
		out, err := ReadTPMEncryptedJSON[T](ctx, path, o)
		if err == nil {
			return out, nil
		}
		log.Warn("securefile: TPM decrypt failed, falling back to password mode", "error", err)
	}

	return ReadEncryptedJSON[T](path, password, o)
}

// WriteEncryptedJSONAuto prefers TPM; falls back to password with warning.
func WriteEncryptedJSONAuto[T any](ctx context.Context, path string, v T, password []byte, opt ...Options) error {
	o := mergeOptions(opt...)

	if o.TPMSealer != nil && o.TPMLabel != "" {
		if err := WriteTPMEncryptedJSON[T](ctx, path, v, o); err == nil {
			return nil
		} else {
			log.Warn("securefile: TPM encrypt failed, falling back to password mode", "error", err)
		}
	}

	return WriteEncryptedJSON[T](path, v, password, o)
}

func defaultOptions() Options {
	return Options{
		KDF:           DefaultKDF,
		FilePerm:      0o600,
		DirectoryPerm: 0o700,
		AADFunc:       nil,
	}
}

// WriteEncryptedJSON MODE PASSWORD
func WriteEncryptedJSON[T any](path string, v T, password []byte, opt ...Options) error {
	o := mergeOptions(opt...)

	if len(password) == 0 {
		return errors.New("securefile w: empty password")
	}
	if isAllZero(password) {
		return errors.New("securefile w: zeroed password buffer")
	}

	if err := os.MkdirAll(filepath.Dir(path), o.DirectoryPerm); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}

	plain, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	ver := o.KDF.Version
	if ver == 0 {
		ver = 2
	}
	if ver != 1 && ver != 2 {
		return fmt.Errorf("unsupported kdf version: %d", ver)
	}

	// salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("rand salt: %w", err)
	}

	key := argon2.IDKey(
		password,
		salt,
		o.KDF.ArgonTime,
		o.KDF.ArgonMemory,
		o.KDF.ArgonThreads,
		o.KDF.ArgonKeyLen,
	)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("aead: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("rand nonce: %w", err)
	}

	var aad []byte
	if o.AADFunc != nil {
		aad = o.AADFunc(path)
	}

	ct := aead.Seal(nil, nonce, plain, aad)

	out := o.KDF
	out.Version = ver
	if ver == 2 && out.Mode == "" {
		out.Mode = "password"
	}

	out.SaltB64 = base64.StdEncoding.EncodeToString(salt)
	out.NonceB64 = base64.StdEncoding.EncodeToString(nonce)
	out.CTB64 = base64.StdEncoding.EncodeToString(ct)

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal enc file: %w", err)
	}

	return atomicWriteFile(path, b, o.FilePerm)
}

// WriteTPMEncryptedJSON MODE TPM
func WriteTPMEncryptedJSON[T any](ctx context.Context, path string, v T, opt ...Options) error {
	o := mergeOptions(opt...)
	if o.TPMSealer == nil {
		return errors.New("securefile w: TPMSealer is required")
	}
	if o.TPMLabel == "" {
		return errors.New("securefile w: TPMLabel is required")
	}

	if err := os.MkdirAll(filepath.Dir(path), o.DirectoryPerm); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}

	plain, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	// random DEK (always 32 bytes for XChaCha20-Poly1305)
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return fmt.Errorf("rand dek: %w", err)
	}
	defer zeroBytes(dek)

	sealed, err := o.TPMSealer.Seal(ctx, o.TPMLabel, dek)
	if err != nil {
		return fmt.Errorf("tpm seal dek: %w", err)
	}

	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return fmt.Errorf("aead: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("rand nonce: %w", err)
	}

	var aad []byte
	if o.AADFunc != nil {
		aad = o.AADFunc(path)
	}

	ct := aead.Seal(nil, nonce, plain, aad)

	out := KDFParams{
		Version:      2,
		Mode:         "tpm",
		SealedDEKB64: base64.StdEncoding.EncodeToString(sealed),
		NonceB64:     base64.StdEncoding.EncodeToString(nonce),
		CTB64:        base64.StdEncoding.EncodeToString(ct),
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal enc file: %w", err)
	}

	return atomicWriteFile(path, b, o.FilePerm)
}

// ReadEncryptedJSON MODE PASSWORD
func ReadEncryptedJSON[T any](path string, password []byte, opt ...Options) (T, error) {

	var zero T
	o := mergeOptions(opt...)

	b, err := os.ReadFile(path)
	if err != nil {
		return zero, fmt.Errorf("read file: %w", err)
	}

	if len(password) == 0 {
		return zero, errors.New("securefile r: empty password")
	}
	if isAllZero(password) {
		return zero, errors.New("securefile r: zeroed password buffer")
	}

	var ef KDFParams
	if err := json.Unmarshal(b, &ef); err != nil {
		return zero, fmt.Errorf("unmarshal enc file: %w", err)
	}

	switch ef.Version {
	case 1:
		// legacy password envelope
	case 2:
		// v2 password envelope
		if ef.Mode != "" && strings.ToLower(ef.Mode) != "password" {
			return zero, fmt.Errorf("unsupported v2 mode: %q", ef.Mode)
		}
	default:
		return zero, fmt.Errorf("unsupported file version: %d", ef.Version)
	}

	salt, err := base64.StdEncoding.DecodeString(ef.SaltB64)
	if err != nil {
		return zero, fmt.Errorf("decode salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(ef.NonceB64)
	if err != nil {
		return zero, fmt.Errorf("decode nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(ef.CTB64)
	if err != nil {
		return zero, fmt.Errorf("decode ciphertext: %w", err)
	}

	key := argon2.IDKey(password, salt, ef.ArgonTime, ef.ArgonMemory, ef.ArgonThreads, ef.ArgonKeyLen)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return zero, fmt.Errorf("aead: %w", err)
	}

	var aad []byte
	if o.AADFunc != nil {
		aad = o.AADFunc(path)
	}

	plain, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return zero, ErrInvalidPasswordOrCorrupt
	}

	var out T
	if err := json.Unmarshal(plain, &out); err != nil {
		return zero, fmt.Errorf("unmarshal json: %w", err)
	}
	return out, nil
}

// ReadTPMEncryptedJSON MODE TPM
func ReadTPMEncryptedJSON[T any](ctx context.Context, path string, opt ...Options) (T, error) {
	var zero T
	o := mergeOptions(opt...)
	if o.TPMSealer == nil {
		return zero, errors.New("securefile r: TPMSealer is required")
	}
	if o.TPMLabel == "" {
		return zero, errors.New("securefile r: TPMLabel is required")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return zero, fmt.Errorf("read file: %w", err)
	}

	var ef KDFParams
	if err := json.Unmarshal(b, &ef); err != nil {
		return zero, fmt.Errorf("unmarshal enc file: %w", err)
	}
	// accept v2 tpm only here
	if ef.Version != 2 || strings.ToLower(ef.Mode) != "tpm" {
		return zero, fmt.Errorf("not a v2 tpm file")
	}

	nonce, err := base64.StdEncoding.DecodeString(ef.NonceB64)
	if err != nil {
		return zero, fmt.Errorf("decode nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(ef.CTB64)
	if err != nil {
		return zero, fmt.Errorf("decode ciphertext: %w", err)
	}
	sealed, err := base64.StdEncoding.DecodeString(ef.SealedDEKB64)
	if err != nil {
		return zero, fmt.Errorf("decode sealed dek: %w", err)
	}

	dek, err := o.TPMSealer.Unseal(ctx, o.TPMLabel, sealed)
	if err != nil {
		return zero, ErrInvalidPasswordOrCorrupt // same generic error
	}
	if len(dek) != 32 {
		zeroBytes(dek)
		return zero, ErrInvalidPasswordOrCorrupt
	}
	defer zeroBytes(dek)

	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return zero, fmt.Errorf("aead: %w", err)
	}

	var aad []byte
	if o.AADFunc != nil {
		aad = o.AADFunc(path)
	}

	plain, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return zero, ErrInvalidPasswordOrCorrupt
	}

	var out T
	if err := json.Unmarshal(plain, &out); err != nil {
		return zero, fmt.Errorf("unmarshal json: %w", err)
	}
	return out, nil
}

// AtomicWriteFile MODE PLAN TEXT (NOT ENCRYPTED)
func AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
	return atomicWriteFile(path, data, perm)
}

// ConfigPathCandidates returns config paths to try, in priority order.
// Uses QA_ENV to optionally add a subfolder: local/ or develop/.
func ConfigPathCandidates(app, filename string) ([]string, error) {
	envFolder, err := QaEnvFolder()
	if err != nil {
		return nil, err
	}
	return configPathCandidatesForEnvFolder(app, filename, envFolder)
}

// WriteJSON marshals v as pretty JSON and writes it atomically to path.
// Creates parent directories using permDir.
func WriteJSON[T any](path string, v T, permFile, permDir os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), permDir); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}

	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	return AtomicWriteFile(path, b, permFile)
}

// ReadJSON reads and unmarshals JSON from path into T.
func ReadJSON[T any](path string) (T, error) {
	var zero T
	b, err := os.ReadFile(path)
	if err != nil {
		return zero, fmt.Errorf("read file: %w", err)
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		return zero, fmt.Errorf("unmarshal json: %w", err)
	}
	return out, nil
}

// configPathCandidatesForEnvFolder builds candidates for a specific envFolder.
// envFolder == "" means production layout (no subfolder).
func configPathCandidatesForEnvFolder(app, filename, envFolder string) ([]string, error) {
	if app == "" {
		return nil, errors.New("app must not be empty")
	}
	if filename == "" {
		return nil, errors.New("filename must not be empty")
	}

	var paths []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		paths = append(paths, p)
	}

	joinHomeStyle := func(homeLike string) string {
		// <home>/.config/<app>/<env?>/<filename>
		dir := filepath.Join(homeLike, ".config", app)
		if envFolder != "" {
			dir = filepath.Join(dir, envFolder)
		}
		return filepath.Join(dir, filename)
	}

	// 1) SNAP_REAL_HOME
	if realHome := os.Getenv("SNAP_REAL_HOME"); realHome != "" {
		add(joinHomeStyle(realHome))
	}

	// 2) HOME
	if home := os.Getenv("HOME"); home != "" {
		add(joinHomeStyle(home))
	}

	// 3) UserConfigDir fallback: <UserConfigDir>/<app>/<env?>/<filename>
	if dir, err := os.UserConfigDir(); err == nil {
		baseDir := filepath.Join(dir, app)
		if envFolder != "" {
			baseDir = filepath.Join(baseDir, envFolder)
		}
		add(filepath.Join(baseDir, filename))
	} else if len(paths) == 0 {
		return nil, fmt.Errorf("UserConfigDir: %w", err)
	}

	return paths, nil
}

func mergeOptions(opt ...Options) Options {
	o := defaultOptions()
	if len(opt) == 0 {
		return o
	}
	in := opt[0]

	// KDF
	if in.KDF.Version != 0 {
		o.KDF = in.KDF
	}

	// perms
	if in.FilePerm != 0 {
		o.FilePerm = in.FilePerm
	}
	if in.DirectoryPerm != 0 {
		o.DirectoryPerm = in.DirectoryPerm
	}

	// aad
	if in.AADFunc != nil {
		o.AADFunc = in.AADFunc
	}

	// TPM
	if in.TPMSealer != nil {
		o.TPMSealer = in.TPMSealer
	}
	if in.TPMLabel != "" {
		o.TPMLabel = in.TPMLabel
	}

	return o
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"

	// Best effort cleanup if something already exists.
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

func QaEnvFolder() (string, error) {
	raw := strings.TrimSpace(os.Getenv("QA_ENV"))
	if raw == "" {
		return "", nil // prod default
	}
	switch strings.ToLower(raw) {
	case "local":
		return "local", nil
	case "dev", "develop", "development":
		return "develop", nil
	case "prod", "production":
		return "", nil
	default:
		return "", fmt.Errorf("invalid QA_ENV %q (allowed: local, develop, empty)", raw)
	}
}

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
