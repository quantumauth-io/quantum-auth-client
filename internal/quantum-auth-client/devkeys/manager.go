package devkeys

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	ErrNotFound     = errors.New("dev key not found")
	ErrConflict     = errors.New("dev key already exists")
	ErrInvalidInput = errors.New("invalid input")
)

type Key struct {
	AppName     string    `json:"appName"`
	AppID       string    `json:"appId"`
	PQPublicKey string    `json:"pqPublicKey"`
	CreatedAt   time.Time `json:"createdAt"`
}

type Patch struct {
	AppName *string
}

type Manager interface {
	List(ctx context.Context) ([]Key, error)
	Create(ctx context.Context, appID, appName string) (Key, error)
	Update(ctx context.Context, appID string, patch Patch) error
	Delete(ctx context.Context, appID string) error
	ExportPrivateKey(ctx context.Context, appID string) (string, error)
}

type Store interface {
	List(ctx context.Context) ([]Key, error)
	Get(ctx context.Context, appID string) (Key, error)

	Insert(ctx context.Context, k Key, privateKeyBytes []byte) error
	UpdateMeta(ctx context.Context, appID string, patch Patch) error
	Delete(ctx context.Context, appID string) error
	DeletePrivateKey(ctx context.Context, appID string) error
	ExportPrivateKeyB64(ctx context.Context, appID string) (string, error)
}

type Crypto interface {
	GenerateKeypair(ctx context.Context) (publicKeyB64 string, privateKeyBytes []byte, err error)
}

type manager struct {
	store  Store
	crypto Crypto
	now    func() time.Time
}

func New(store Store, crypto Crypto, now func() time.Time) Manager {
	if now == nil {
		now = time.Now
	}
	return &manager{
		store:  store,
		crypto: crypto,
		now:    now,
	}
}

func (m *manager) List(ctx context.Context) ([]Key, error) {
	return m.store.List(ctx)
}

func (m *manager) Create(ctx context.Context, appID, appName string) (Key, error) {
	appID = strings.TrimSpace(appID)
	appName = strings.TrimSpace(appName)

	if appID == "" || appName == "" {
		return Key{}, ErrInvalidInput
	}

	if _, err := m.store.Get(ctx, appID); err == nil {
		return Key{}, ErrConflict
	} else if !errors.Is(err, ErrNotFound) {
		return Key{}, err
	}

	pub, priv, err := m.crypto.GenerateKeypair(ctx)
	if err != nil {
		return Key{}, err
	}

	k := Key{
		AppID:       appID,
		AppName:     appName,
		PQPublicKey: pub,
		CreatedAt:   m.now(),
	}

	if err := m.store.Insert(ctx, k, priv); err != nil {
		return Key{}, err
	}
	return k, nil
}

func (m *manager) Update(ctx context.Context, appID string, patch Patch) error {
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return ErrInvalidInput
	}

	if patch.AppName != nil {
		v := strings.TrimSpace(*patch.AppName)
		patch.AppName = &v
		if v == "" {
			return ErrInvalidInput
		}
	}

	if patch.AppName == nil {
		return ErrInvalidInput
	}

	if _, err := m.store.Get(ctx, appID); err != nil {
		return err
	}

	return m.store.UpdateMeta(ctx, appID, patch)
}

func (m *manager) Delete(ctx context.Context, appID string) error {
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return ErrInvalidInput
	}

	if _, err := m.store.Get(ctx, appID); err != nil {
		return err
	}

	if err := m.store.DeletePrivateKey(ctx, appID); err != nil {
		return err
	}
	return m.store.Delete(ctx, appID)
}

func (m *manager) ExportPrivateKey(ctx context.Context, appID string) (string, error) {
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return "", ErrInvalidInput
	}
	if _, err := m.store.Get(ctx, appID); err != nil {
		return "", err
	}
	return m.store.ExportPrivateKeyB64(ctx, appID)
}
