package userwallet

import (
	"errors"
	"fmt"
	"os"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/constants"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/securefile"
)

type Store struct {
	Path string
	Opt  securefile.Options
}

func NewStore() (*Store, error) {
	paths, err := securefile.ConfigPathCandidates(constants.AppName, constants.WalletFile)
	if err != nil {
		return nil, err
	}

	return &Store{
		Path: paths[0],
		Opt: securefile.Options{
			AADFunc: func(_ string) []byte { return []byte(constants.AADConstant) },
		},
	}, nil
}

func (s *Store) Exists() (bool, error) {
	_, err := os.Stat(s.Path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("stat wallet %s: %w", s.Path, err)
}

func (s *Store) Load(password []byte) (*Wallet, error) {
	w, err := securefile.ReadEncryptedJSON[Wallet](s.Path, password, s.Opt)
	if err == nil {
		return &w, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	return nil, fmt.Errorf("load wallet %s: %w", s.Path, err)
}

func (s *Store) Create(password []byte) (*Wallet, error) {
	if ok, err := s.Exists(); err != nil {
		return nil, err
	} else if ok {
		return nil, fmt.Errorf("wallet already exists at %s", s.Path)
	}

	nw, err := NewRandomWallet()
	if err != nil {
		return nil, err
	}
	if err := securefile.WriteEncryptedJSON(s.Path, *nw, password, s.Opt); err != nil {
		return nil, err
	}
	return nw, nil
}

func (s *Store) Ensure(password []byte) (*Wallet, error) {
	w, err := s.Load(password)
	if err == nil {
		return w, nil
	}

	if errors.Is(err, os.ErrNotExist) {
		return s.Create(password)
	}

	return nil, err
}
