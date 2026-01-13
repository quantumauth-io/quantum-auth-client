package contractwallet

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/wtypes"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/helpers"
	"github.com/quantumauth-io/quantum-go-utils/log"
	"github.com/quantumauth-io/quantum-go-utils/qa_evm"
)

type ChainService interface {
	SwitchChainByChainIDHex(ctx context.Context, chainIDHex string) (string, error)
	ActiveHTTP(ctx context.Context) (qa_evm.BlockchainClient, error)
}

type ContractStore interface {
	LoadForChain(chainID uint64) (*Config, error)
	SaveForChain(cfg Config) error
}

type WalletProvider interface {
	UserWallet(ctx context.Context) (wtypes.Wallet, error)
	DeviceWallet(ctx context.Context) (wtypes.Wallet, error)
}

type DeployerConfig struct {
	Chains  ChainService
	Store   ContractStore
	Wallets WalletProvider

	EntryPointByNetworkName func(networkName string) (common.Address, error)
}

type AADeployResult struct {
	ChainIDHex  string `json:"chainIdHex"`
	NetworkName string `json:"networkName"`

	EntryPoint common.Address `json:"entryPoint"`

	TPMVerifierAddress common.Address `json:"tpmVerifierAddress"`
	TPMVerifierTxHash  common.Hash    `json:"tpmVerifierTxHash"`

	AccountAddress common.Address `json:"accountAddress"`
	AccountTxHash  common.Hash    `json:"accountTxHash"`

	AlreadyDeployed bool `json:"alreadyDeployed"`
}

type ContractDeployer struct {
	chains  ChainService
	store   ContractStore
	wallets WalletProvider

	entryPointByNetwork func(networkName string) (common.Address, error)
}

func (d *ContractDeployer) SetEntryPointResolver(fn func(string) (common.Address, error)) {
	d.entryPointByNetwork = fn
}

func NewContractDeployer(cfg DeployerConfig) (*ContractDeployer, error) {
	if cfg.Chains == nil {
		return nil, fmt.Errorf("contract deployer: missing chain service")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("contract deployer: missing Store")
	}
	if cfg.Wallets == nil {
		return nil, fmt.Errorf("contract deployer: missing WalletProvider")
	}

	return &ContractDeployer{
		chains:              cfg.Chains,
		store:               cfg.Store,
		wallets:             cfg.Wallets,
		entryPointByNetwork: cfg.EntryPointByNetworkName,
	}, nil
}

func (d *ContractDeployer) DeployAAOnChainIDHex(ctx context.Context, chainIDHex string, recoveryAddress string) (*AADeployResult, error) {
	if d == nil {
		return nil, fmt.Errorf("deploy: nil deployer")
	}
	if d.chains == nil {
		return nil, fmt.Errorf("deploy: chains not configured (server.AttachDeployer not called)")
	}
	if d.entryPointByNetwork == nil {
		return nil, fmt.Errorf("deploy: entryPoint resolver not configured (server.AttachDeployer not called)")
	}
	client, err := d.chains.ActiveHTTP(ctx)
	if client == nil || d.store == nil || d.wallets == nil {
		return nil, fmt.Errorf("deploy: deployer not initialized (missing eth/store/wallets)")
	}

	if !common.IsHexAddress(recoveryAddress) {
		return nil, fmt.Errorf("invalid recovery address: %q", recoveryAddress)
	}

	recoveryAddr := common.HexToAddress(recoveryAddress)

	want := helpers.NormalizeHex0x(strings.TrimSpace(chainIDHex))
	if want == "" {
		return nil, fmt.Errorf("deploy: missing chainIdHex")
	}

	networkName, err := d.chains.SwitchChainByChainIDHex(ctx, want)
	if err != nil {
		return nil, err
	}

	chainID, err := client.ChainID(ctx)
	if err != nil {
		return nil, err
	}

	// ✅ Idempotent: return config if already present & complete
	if cfg, lerr := d.store.LoadForChain(chainID.Uint64()); lerr == nil && cfg != nil {
		return &AADeployResult{
			ChainIDHex:         want,
			NetworkName:        networkName,
			EntryPoint:         common.HexToAddress(cfg.EntryPoint),
			TPMVerifierAddress: common.HexToAddress(cfg.TPMVerifier),
			AccountAddress:     common.HexToAddress(cfg.Address),
			AlreadyDeployed:    true,
		}, nil
	} else if lerr != nil && !errors.Is(lerr, ErrContractNotConfigured) {
		return nil, lerr
	}

	entryPoint, err := d.entryPointByNetwork(networkName)
	if err != nil {
		return nil, err
	}

	userW, err := d.wallets.UserWallet(ctx)
	if err != nil {
		return nil, err
	}
	deviceW, err := d.wallets.DeviceWallet(ctx)
	if err != nil {
		return nil, err
	}

	tpmWallet, ok := deviceW.(wtypes.TPMBackedWallet)
	if !ok {
		return nil, fmt.Errorf("device wallet is not TPM-backed (missing TPMKeyID())")
	}
	tpmKeyID := tpmWallet.TPMKeyID()

	log.Info("AA deployment starting",
		"network", networkName,
		"chain_id", chainID.String(),
		"entry_point", entryPoint.Hex(),
		"deployer", userW.Address().Hex(),
	)

	tpmVerifierAddr, tpmTx, err := DeployTPMVerifierSecp256k1(ctx, client, userW)
	if err != nil {
		return nil, err
	}

	params := AccountDeployParams{
		EntryPoint:  entryPoint,
		EOA1:        userW.Address(),
		EOA2:        recoveryAddr, // TODO Implement the recovery method. we never asked for a private key for this account.
		TPMVerifier: tpmVerifierAddr,
		TPMKeyID:    tpmKeyID,
	}

	log.Info("deploying account",
		"entryPoint", params.EntryPoint.Hex(),
		"eoa1", params.EOA1.Hex(),
		"eoa2", params.EOA2.Hex(),
		"tpmVerifier", params.TPMVerifier.Hex(),
		"tpmKeyID", params.TPMKeyID,
	)

	accountAddr, accountTx, err := DeployQuantumAuthAccount(ctx, client, userW, params)
	if err != nil {
		return nil, err
	}

	if err := d.store.SaveForChain(Config{
		ChainID:     chainID.Uint64(),
		Address:     accountAddr.Hex(),
		EntryPoint:  entryPoint.Hex(),
		TPMVerifier: tpmVerifierAddr.Hex(),
	}); err != nil {
		return nil, err
	}

	return &AADeployResult{
		ChainIDHex:  want,
		NetworkName: networkName,
		EntryPoint:  entryPoint,

		TPMVerifierAddress: tpmVerifierAddr,
		TPMVerifierTxHash:  tpmTx,

		AccountAddress: accountAddr,
		AccountTxHash:  accountTx,

		AlreadyDeployed: false,
	}, nil
}
