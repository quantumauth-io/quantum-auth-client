package contractwallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/constants"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/securefile"
)

type Store struct {
	Path string
}

func NewStore() (*Store, error) {
	paths, err := securefile.ConfigPathCandidates(constants.AppName, constants.ContractFile)
	if err != nil {
		return nil, err
	}
	return &Store{Path: paths[0]}, nil
}

func (s *Store) LoadForChain(chainID uint64) (*Config, error) {
	all, err := s.LoadAll()
	if err != nil {
		return nil, err
	}

	cfg, ok := all[chainID]
	if !ok || !isConfigComplete(cfg) {
		return nil, ErrContractNotConfigured
	}

	c := cfg
	return &c, nil
}

func (s *Store) LoadAll() (map[uint64]Config, error) {
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[uint64]Config{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", s.Path, err)
	}

	var v2 fileV2
	if err := json.Unmarshal(b, &v2); err == nil && v2.Contracts != nil {
		out := make(map[uint64]Config, len(v2.Contracts))
		for k, cfg := range v2.Contracts {
			id, perr := strconv.ParseUint(k, 10, 64)
			if perr != nil {
				continue
			}
			out[id] = cfg
		}
		return out, nil
	}

	var v1 fileV1
	if err := json.Unmarshal(b, &v1); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", s.Path, err)
	}

	if v1.Address == "" || v1.ChainID == 0 {
		return map[uint64]Config{}, nil
	}

	return map[uint64]Config{
		v1.ChainID: {
			ChainID:     v1.ChainID,
			Address:     v1.Address,
			UpdatedAt:   v1.UpdatedAt,
			EntryPoint:  "",
			TPMVerifier: "",
		},
	}, nil
}

func (s *Store) SaveForChain(cfg Config) error {
	if cfg.ChainID == 0 {
		return errors.New("contract config requires chain_id")
	}

	// These should be present if you consider it "configured"
	if cfg.Address == "" {
		return errors.New("contract config requires address")
	}
	if cfg.EntryPoint == "" {
		return errors.New("contract config requires entry_point")
	}
	if cfg.TPMVerifier == "" {
		return errors.New("contract config requires tpm_verifier")
	}

	// Validate addresses
	if !common.IsHexAddress(cfg.Address) {
		return fmt.Errorf("invalid address %q", cfg.Address)
	}
	if !common.IsHexAddress(cfg.EntryPoint) {
		return fmt.Errorf("invalid entry_point %q", cfg.EntryPoint)
	}
	if !common.IsHexAddress(cfg.TPMVerifier) {
		return fmt.Errorf("invalid tpm_verifier %q", cfg.TPMVerifier)
	}

	cfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	all, err := s.LoadAll()
	if err != nil {
		return err
	}
	all[cfg.ChainID] = cfg

	// encode v2
	v2 := fileV2{Contracts: map[string]Config{}}
	for id, c := range all {
		v2.Contracts[strconv.FormatUint(id, 10)] = c
	}

	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(s.Path), err)
	}

	b, err := json.MarshalIndent(v2, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal contract config: %w", err)
	}

	return atomicWriteFile(s.Path, b, 0o600)
}
