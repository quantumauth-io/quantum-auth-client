package contractwallet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/constants"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/wtypes"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/securefile"
	"github.com/quantumauth-io/quantum-go-utils/qa_evm"
)

const (
	AppName      = "quantumauth"
	ContractFile = "contract.json"
)

var ErrContractNotConfigured = errors.New("contract not configured")

// v2 file format: map per chain
type fileV2 struct {
	Contracts map[string]Config `json:"contracts"` // key = chainID as string
}

// v1 legacy format: single config at top-level (only ChainID + Address existed)
type fileV1 struct {
	ChainID   uint64 `json:"chain_id"`
	Address   string `json:"address"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// Config is intentionally simple + editable by users.
type Config struct {
	ChainID uint64 `json:"chain_id"`

	// QuantumAuthAccount address
	Address string `json:"address"` // 0x...

	// ERC-4337 EntryPoint used for this chain
	EntryPoint string `json:"entry_point,omitempty"` // 0x...

	// TPMVerifierSecp256k1 address for this chain
	TPMVerifier string `json:"tpm_verifier,omitempty"` // 0x...

	UpdatedAt string `json:"updated_at,omitempty"`
}

type Runtime struct {
	ChainService *chains.QAChainService
	User         wtypes.Wallet
	Device       wtypes.Wallet
	Contract     *Config
}

type Store struct {
	Path string
}

func (r *Runtime) activeHTTP(ctx context.Context) (qa_evm.BlockchainClient, error) {
	return r.ChainService.ActiveHTTP(ctx)
}

func (r *Runtime) Ready() error {
	client, err := r.ChainService.ActiveHTTP(context.Background())
	if err != nil {
		return err
	}
	if client == nil || r.User == nil || r.Device == nil {
		return fmt.Errorf("contractWallet: runtime not initialized")
	}
	return nil
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

	// Try v2 first
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

	// Fallback to v1
	var v1 fileV1
	if err := json.Unmarshal(b, &v1); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", s.Path, err)
	}

	// If v1 is empty/partial, treat as not configured
	if v1.Address == "" || v1.ChainID == 0 {
		return map[uint64]Config{}, nil
	}

	// Promote v1 -> v2-style entry (missing fields remain empty)
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

func (r *Runtime) LoadContractForCurrentChain(ctx context.Context, store *Store) error {
	if store == nil {
		r.Contract = nil
		return nil
	}
	client, err := r.activeHTTP(ctx)
	if err != nil {
		return err
	}

	chainID, err := client.ChainID(ctx)
	if err != nil {
		return err
	}

	cfg, err := store.LoadForChain(chainID.Uint64())
	if err != nil {
		if errors.Is(err, ErrContractNotConfigured) {
			r.Contract = nil
			return nil
		}
		return err
	}

	r.Contract = cfg
	return nil
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

func isConfigComplete(cfg Config) bool {
	if cfg.ChainID == 0 {
		return false
	}
	if cfg.Address == "" || !common.IsHexAddress(cfg.Address) {
		return false
	}
	if cfg.EntryPoint == "" || !common.IsHexAddress(cfg.EntryPoint) {
		return false
	}
	if cfg.TPMVerifier == "" || !common.IsHexAddress(cfg.TPMVerifier) {
		return false
	}
	return true
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
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

func (r *Runtime) UserAddress() common.Address {
	return r.User.Address()
}

func (r *Runtime) DeviceAddress() common.Address {
	return r.Device.Address()
}

func (r *Runtime) ContractAddress() (common.Address, error) {
	if r.Contract == nil {
		return common.Address{}, ErrContractNotConfigured
	}
	return common.HexToAddress(r.Contract.Address), nil
}

func (r *Runtime) ValidateChain(ctx context.Context) error {
	if r.Contract == nil {
		return ErrContractNotConfigured
	}

	client, err := r.activeHTTP(ctx)
	if err != nil {
		return err
	}

	chainID, err := client.ChainID(ctx)
	if err != nil {
		return err
	}
	if r.Contract.ChainID != chainID.Uint64() {
		return fmt.Errorf("contractwallet: wrong chain (rpc=%d config=%d)", chainID.Uint64(), r.Contract.ChainID)
	}
	return nil
}
