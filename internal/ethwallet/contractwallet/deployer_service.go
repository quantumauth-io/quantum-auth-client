package contractwallet

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/quantumauth-io/quantum-auth-client/internal/ethwallet/wtypes"
	utilsEth "github.com/quantumauth-io/quantum-go-utils/ethrpc"
	"github.com/quantumauth-io/quantum-go-utils/log"
)

type SwitchChainFunc func(ctx context.Context, chainIDHex string) (networkName string, err error)

type ContractStore interface {
	LoadForChain(chainID uint64) (*Config, error)
	SaveForChain(cfg Config) error
}

type WalletProvider interface {
	UserWallet(ctx context.Context) (wtypes.Wallet, error)
	DeviceWallet(ctx context.Context) (wtypes.Wallet, error)
}

type DeployerConfig struct {
	EthClient *utilsEth.Client
	Store     ContractStore
	Wallets   WalletProvider

	// Optional at construction time; typically attached by Server.AttachDeployer(...)
	SwitchChain             SwitchChainFunc
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
	eth         *utilsEth.Client
	switchChain SwitchChainFunc
	store       ContractStore
	wallets     WalletProvider

	entryPointByNetwork func(networkName string) (common.Address, error)
}

func (d *ContractDeployer) SetSwitchChainFunc(fn SwitchChainFunc) {
	d.switchChain = fn
}
func (d *ContractDeployer) SetEntryPointResolver(fn func(string) (common.Address, error)) {
	d.entryPointByNetwork = fn
}

func NewContractDeployer(cfg DeployerConfig) (*ContractDeployer, error) {
	if cfg.EthClient == nil {
		return nil, fmt.Errorf("contract deployer: missing eth client")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("contract deployer: missing Store")
	}
	if cfg.Wallets == nil {
		return nil, fmt.Errorf("contract deployer: missing WalletProvider")
	}

	// SwitchChain + EntryPointByNetworkName are intentionally optional here;
	// they can be attached later by the HTTP server.
	return &ContractDeployer{
		eth:                 cfg.EthClient,
		switchChain:         cfg.SwitchChain,
		store:               cfg.Store,
		wallets:             cfg.Wallets,
		entryPointByNetwork: cfg.EntryPointByNetworkName,
	}, nil
}

func (d *ContractDeployer) DeployAAOnChainIDHex(ctx context.Context, chainIDHex string) (*AADeployResult, error) {
	if d == nil {
		return nil, fmt.Errorf("deploy: nil deployer")
	}
	if d.switchChain == nil {
		return nil, fmt.Errorf("deploy: switchChain not configured (server.AttachDeployer not called)")
	}
	if d.entryPointByNetwork == nil {
		return nil, fmt.Errorf("deploy: entryPoint resolver not configured (server.AttachDeployer not called)")
	}
	if d.eth == nil || d.store == nil || d.wallets == nil {
		return nil, fmt.Errorf("deploy: deployer not initialized (missing eth/store/wallets)")
	}

	want := utilsEth.NormalizeHex0x(strings.TrimSpace(chainIDHex))
	if want == "" {
		return nil, fmt.Errorf("deploy: missing chainIdHex")
	}

	networkName, err := d.switchChain(ctx, want)
	if err != nil {
		return nil, err
	}

	if err := d.eth.EnsureBackend(ctx); err != nil {
		return nil, err
	}

	chainID, err := d.eth.ChainID(ctx)
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

	tpmVerifierAddr, tpmTx, err := DeployTPMVerifierSecp256k1(ctx, d.eth, userW)
	if err != nil {
		return nil, err
	}

	params := AccountDeployParams{
		EntryPoint:  entryPoint,
		EOA1:        userW.Address(),
		EOA2:        deviceW.Address(),
		TPMVerifier: tpmVerifierAddr,
		TPMKeyID:    tpmKeyID,
	}

	accountAddr, accountTx, err := DeployQuantumAuthAccount(ctx, d.eth, userW, params)
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
