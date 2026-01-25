package devkeys

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/securefile"
	"github.com/quantumauth-io/quantum-go-utils/qa/requests"
)

type SecureStore struct {
	dir         string
	opt         securefile.Options
	mu          sync.Mutex
	indexFn     string
	labelPrefix string
	now         func() time.Time
}

type indexFile struct {
	Version int       `json:"version"`
	Keys    []Key     `json:"keys"`
	Updated time.Time `json:"updatedAt"`
}

type privFile struct {
	PrivateKeyB64 string `json:"privateKeyB64"`
}

func NewSecureStore(dir string, tpm securefile.TPMSealer, labelPrefix string, now func() time.Time) *SecureStore {
	if labelPrefix == "" {
		labelPrefix = "qa.devkeys"
	}
	if now == nil {
		now = time.Now
	}

	return &SecureStore{
		dir:         dir,
		indexFn:     "devkeys_index.json",
		labelPrefix: labelPrefix,
		now:         now,
		opt: securefile.Options{
			FilePerm:      0o600,
			DirectoryPerm: 0o700,
			TPMSealer:     tpm,
			AADFunc: func(path string) []byte {
				abs := path
				if a, err := filepath.Abs(path); err == nil {
					abs = a
				}
				return []byte("quantumauth:devkeys|" + labelPrefix + "|" + abs)
			},
		},
	}
}

func (s *SecureStore) indexPath() string {
	return filepath.Join(s.dir, s.indexFn)
}

func (s *SecureStore) privPath(appID string) (string, error) {
	appID = strings.TrimSpace(appID)
	if _, err := requests.ValidateUUIDv4(appID); err != nil {
		return "", ErrInvalidInput
	}
	return filepath.Join(s.dir, fmt.Sprintf("devkey_%s.json.enc", appID)), nil
}

func (s *SecureStore) tpmLabelFor(path string) string {
	return s.labelPrefix + ":" + filepath.Base(path)
}

// ---- PLAINTEXT INDEX HELPERS ----

func (s *SecureStore) readIndexPlain() (indexFile, error) {
	p := s.indexPath()

	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return indexFile{Version: 1, Keys: []Key{}}, nil
		}
		return indexFile{}, err
	}

	var out indexFile
	if err := json.Unmarshal(b, &out); err != nil {
		return indexFile{}, err
	}
	if out.Version == 0 {
		out.Version = 1
	}
	if out.Keys == nil {
		out.Keys = []Key{}
	}
	return out, nil
}

func (s *SecureStore) writeIndexPlain(idx indexFile) error {
	if err := os.MkdirAll(s.dir, s.opt.DirectoryPerm); err != nil {
		return err
	}

	p := s.indexPath()
	tmp := p + ".tmp"

	idx.Version = 1
	idx.Updated = s.now()

	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}

	// atomic-ish write
	if err := os.WriteFile(tmp, b, s.opt.FilePerm); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// ---- Store interface implementation ----

func (s *SecureStore) List(ctx context.Context) ([]Key, error) {
	_ = ctx

	s.mu.Lock()
	defer s.mu.Unlock()

	idx, err := s.readIndexPlain()
	if err != nil {
		return nil, err
	}
	out := make([]Key, len(idx.Keys))
	copy(out, idx.Keys)
	return out, nil
}

func (s *SecureStore) Get(ctx context.Context, appID string) (Key, error) {
	_ = ctx

	s.mu.Lock()
	defer s.mu.Unlock()

	idx, err := s.readIndexPlain()
	if err != nil {
		return Key{}, err
	}
	for _, k := range idx.Keys {
		if k.AppID == appID {
			return k, nil
		}
	}
	return Key{}, ErrNotFound
}

func (s *SecureStore) Insert(ctx context.Context, k Key, privateKeyBytes []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := requests.ValidateUUIDv4(strings.TrimSpace(k.AppID)); err != nil {
		return ErrInvalidInput
	}
	if strings.TrimSpace(k.AppName) == "" {
		return ErrInvalidInput
	}
	if strings.TrimSpace(k.PQPublicKey) == "" {
		return ErrInvalidInput
	}

	defer func() {
		for i := range privateKeyBytes {
			privateKeyBytes[i] = 0
		}
	}()

	idx, err := s.readIndexPlain()
	if err != nil {
		return err
	}
	for _, existing := range idx.Keys {
		if existing.AppID == k.AppID {
			return ErrConflict
		}
	}

	privP, err := s.privPath(k.AppID)
	if err != nil {
		return err
	}

	// write private key (TPM-encrypted)
	opt := s.opt
	opt.TPMLabel = s.tpmLabelFor(privP)

	pf := privFile{PrivateKeyB64: base64.RawStdEncoding.EncodeToString(privateKeyBytes)}
	if err := securefile.WriteTPMEncryptedJSON(ctx, privP, pf, opt); err != nil {
		return err
	}

	idx.Keys = append(idx.Keys, k)
	return s.writeIndexPlain(idx)
}

func (s *SecureStore) UpdateMeta(ctx context.Context, appID string, patch Patch) error {
	_ = ctx

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := requests.ValidateUUIDv4(strings.TrimSpace(appID)); err != nil {
		return ErrInvalidInput
	}
	if patch.AppName == nil {
		return ErrInvalidInput
	}
	v := strings.TrimSpace(*patch.AppName)
	if v == "" {
		return ErrInvalidInput
	}

	idx, err := s.readIndexPlain()
	if err != nil {
		return err
	}

	found := false
	for i := range idx.Keys {
		if idx.Keys[i].AppID == appID {
			idx.Keys[i].AppName = v
			found = true
			break
		}
	}
	if !found {
		return ErrNotFound
	}

	return s.writeIndexPlain(idx)
}

func (s *SecureStore) DeletePrivateKey(ctx context.Context, appID string) error {
	_ = ctx

	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.privPath(appID)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *SecureStore) Delete(ctx context.Context, appID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := requests.ValidateUUIDv4(strings.TrimSpace(appID)); err != nil {
		return ErrInvalidInput
	}

	// remove priv file too (best-effort)
	if p, err := s.privPath(appID); err == nil {
		_ = os.Remove(p)
	}

	idx, err := s.readIndexPlain()
	if err != nil {
		return err
	}

	out := idx.Keys[:0]
	found := false
	for _, k := range idx.Keys {
		if k.AppID == appID {
			found = true
			continue
		}
		out = append(out, k)
	}
	if !found {
		return ErrNotFound
	}

	idx.Keys = out
	return s.writeIndexPlain(idx)
}

func (s *SecureStore) ExportPrivateKeyB64(ctx context.Context, appID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.privPath(appID)
	if err != nil {
		return "", err
	}

	if _, err := os.Stat(p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotFound
		}
		return "", err
	}

	// TPM-encrypted private key read
	opt := s.opt
	opt.TPMLabel = s.tpmLabelFor(p)

	pf, err := securefile.ReadTPMEncryptedJSON[privFile](ctx, p, opt)
	if err != nil {
		return "", err
	}

	out := strings.TrimSpace(pf.PrivateKeyB64)
	if out == "" {
		return "", fmt.Errorf("devkeys: private key file is empty")
	}
	return out, nil
}
