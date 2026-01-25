package state

import "errors"

var (
	ErrUnlockRequired    = errors.New("unlock required")
	ErrWalletsNotCreated = errors.New("wallets not created")
)
