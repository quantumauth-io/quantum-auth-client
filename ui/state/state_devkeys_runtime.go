package state

import (
	"context"
	"errors"
	"sync"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/devkeys"
	clienthttp "github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/http"
)

type devKeysRuntime struct {
	once sync.Once
	mgr  devkeys.Manager
	err  error
}

func (r *devKeysRuntime) Close(ctx context.Context) {
	_ = ctx
	if r == nil {
		return
	}
	r.mgr = nil
	r.err = nil
}

// SnapshotDevKeys implements http.DevKeysProvider
func (s *AppState) SnapshotDevKeys(ctx context.Context) (clienthttp.DevKeysSnapshot, bool, error) {
	// Must be unlocked
	if !s.PasswordSet() {
		return clienthttp.DevKeysSnapshot{}, false, nil
	}

	s.mu.Lock()
	if s.drt == nil {
		s.drt = &devKeysRuntime{}
	}
	drt := s.drt
	settings := NormalizeGUISettings(s.GUISettings)
	s.mu.Unlock()

	drt.once.Do(func() {
		mgr, err := buildDevKeysManager(settings.TPMOwnerAuth)
		if err != nil {
			drt.err = err
			return
		}
		drt.mgr = mgr
	})

	if drt.err != nil {
		return clienthttp.DevKeysSnapshot{}, false, drt.err
	}
	if drt.mgr == nil {
		return clienthttp.DevKeysSnapshot{}, false, errors.New("devkeys manager unavailable")
	}

	return clienthttp.DevKeysSnapshot{
		Manager: drt.mgr,
	}, true, nil
}
