package http

import (
	"context"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/devkeys"
)

type DevKeysSnapshot struct {
	Manager devkeys.Manager
}

type DevKeysProvider interface {
	SnapshotDevKeys(ctx context.Context) (snap DevKeysSnapshot, ok bool, err error)
}
