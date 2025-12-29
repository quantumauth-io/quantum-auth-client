// Package securefile provides encrypted JSON file read/write with atomic writes.
// Uses Argon2id for KDF and XChaCha20-Poly1305 for AEAD.
package securefile

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	// ErrInvalidPasswordOrCorrupt is returned when decryption fails.
	// Keep this generic to avoid leaking details.
	ErrInvalidPasswordOrCorrupt = errors.New("invalid password or corrupted file")
)

// KDFParams describes the on-disk encryption envelope and KDF settings.
// This is what gets marshaled to disk (as JSON).
type KDFParams struct {
	Version int `json:"version"`

	// Argon2id params
	ArgonTime    uint32 `json:"argon_time"`
	ArgonMemory  uint32 `json:"argon_memory_kib"`
	ArgonThreads uint8  `json:"argon_threads"`
	ArgonKeyLen  uint32 `json:"argon_key_len"`

	// Envelope
	SaltB64  string `json:"salt_b64"`
	NonceB64 string `json:"nonce_b64"`
	CTB64    string `json:"ct_b64"`
}

// DefaultKDF are reasonable defaults for a local encrypted file.
// Tune for your threat model and target hardware.
var DefaultKDF = KDFParams{
	Version:      1,
	ArgonTime:    2,
	ArgonMemory:  64 * 1024, // 64 MiB in KiB
	ArgonThreads: 1,
	ArgonKeyLen:  32,
}

// Options controls encryption behavior.
type Options struct {
	// KDF parameters to use (Version must be 1).
	KDF KDFParams

	// File permissions for the final file and directory.
	// DirectoryPerm is used for MkdirAll(filepath.Dir(path)).
	FilePerm      os.FileMode
	DirectoryPerm os.FileMode

	// AADFunc returns associated data for AEAD.
	// If non-nil, the returned bytes must be identical on read + write.
	// Common patterns:
	//  - nil (no AAD)
	//  - func(path string) []byte { return []byte("quantumauth:client_identity:v1") } (stable binding)
	//  - func(path string) []byte { return []byte(path) } (bind to path; moving file breaks decrypt)
	AADFunc func(path string) []byte
}

func defaultOptions() Options {
	return Options{
		KDF:           DefaultKDF,
		FilePerm:      0o600,
		DirectoryPerm: 0o700,
		AADFunc:       nil,
	}
}

// WriteEncryptedJSON marshals v as pretty JSON, encrypts it, and writes it atomically to path.
func WriteEncryptedJSON[T any](path string, v T, password []byte, opt ...Options) error {
	o := mergeOptions(opt...)

	if err := os.MkdirAll(filepath.Dir(path), o.DirectoryPerm); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}

	plain, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	if o.KDF.Version != 1 {
		return fmt.Errorf("unsupported kdf version: %d", o.KDF.Version)
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
	out.SaltB64 = base64.StdEncoding.EncodeToString(salt)
	out.NonceB64 = base64.StdEncoding.EncodeToString(nonce)
	out.CTB64 = base64.StdEncoding.EncodeToString(ct)

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal enc file: %w", err)
	}

	return atomicWriteFile(path, b, o.FilePerm)
}

// ReadEncryptedJSON reads path, decrypts it using password, and unmarshals JSON into T.
func ReadEncryptedJSON[T any](path string, password []byte, opt ...Options) (T, error) {
	var zero T
	o := mergeOptions(opt...)

	b, err := os.ReadFile(path)
	if err != nil {
		return zero, fmt.Errorf("read file: %w", err)
	}

	var ef KDFParams
	if err := json.Unmarshal(b, &ef); err != nil {
		return zero, fmt.Errorf("unmarshal enc file: %w", err)
	}
	if ef.Version != 1 {
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

// ConfigPathCandidates returns config paths to try, in priority order.
// Uses QA_ENV to optionally add a subfolder: local/ or develop/.
func ConfigPathCandidates(app, filename string) ([]string, error) {
	envFolder, err := QaEnvFolder()
	if err != nil {
		return nil, err
	}
	return configPathCandidatesForEnvFolder(app, filename, envFolder)
}

// ConfigPathCandidatesWithProdFallback returns env-aware candidates first,
// and if QA_ENV is set to a non-prod value, also returns prod candidates as fallback.
func ConfigPathCandidatesWithProdFallback(app, filename string) ([]string, error) {
	envFolder, err := QaEnvFolder()
	if err != nil {
		return nil, err
	}

	// First: env-aware paths (may be prod if envFolder == "")
	envPaths, err := configPathCandidatesForEnvFolder(app, filename, envFolder)
	if err != nil {
		return nil, err
	}

	// If we're effectively prod, no need to add prod fallback.
	if !isNonProdEnvSet() || envFolder == "" {
		return envPaths, nil
	}

	// Append prod paths (envFolder == "")
	prodPaths, err := configPathCandidatesForEnvFolder(app, filename, "")
	if err != nil {
		return nil, err
	}

	// Merge unique, preserve order
	seen := map[string]bool{}
	out := make([]string, 0, len(envPaths)+len(prodPaths))
	for _, p := range envPaths {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range prodPaths {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
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
	// Single options struct; if you want layering, we can add it, but keep it simple.
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

func isNonProdEnvSet() bool {
	raw := strings.TrimSpace(os.Getenv("QA_ENV"))
	if raw == "" {
		return false
	}
	switch strings.ToLower(raw) {
	case "prod", "production":
		return false
	default:
		return true
	}
}
