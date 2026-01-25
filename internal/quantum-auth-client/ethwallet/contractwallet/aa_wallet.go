package contractwallet

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/wtypes"
	"github.com/quantumauth-io/quantum-go-utils/evm"
)

var ErrContractNotConfigured = errors.New("contract not configured")

type fileV2 struct {
	Contracts map[string]Config `json:"contracts"`
}

type fileV1 struct {
	ChainID   uint64 `json:"chain_id"`
	Address   string `json:"address"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type Config struct {
	ChainID     uint64 `json:"chain_id"`
	Address     string `json:"address"`
	EntryPoint  string `json:"entry_point,omitempty"`
	TPMVerifier string `json:"tpm_verifier,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

type Runtime struct {
	ChainService *chains.QAChainService
	User         wtypes.Wallet
	Device       wtypes.Wallet
	Contract     *Config
}

func (r *Runtime) activeHTTP(ctx context.Context) (evm.BlockchainClient, error) {
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
