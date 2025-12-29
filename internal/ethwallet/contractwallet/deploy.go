package contractwallet

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/quantumauth-io/quantum-go-utils/log"

	"github.com/quantumauth-io/quantum-auth-client/internal/ethwallet/wtypes"
	utilsEth "github.com/quantumauth-io/quantum-go-utils/ethrpc"

	// IMPORTANT: adjust these import paths to your generated bindings.
	quantumauthaccount "github.com/quantumauth-io/quantum-auth-client/internal/contracts/bindings/go/quantumauthaccount"
	tpmverifier "github.com/quantumauth-io/quantum-auth-client/internal/contracts/bindings/go/tpmverifiersecp256k1"
)

type AccountDeployParams struct {
	EntryPoint  common.Address
	EOA1        common.Address
	EOA2        common.Address
	TPMVerifier common.Address
	TPMKeyID    [32]byte
}

// DeployTPMVerifierSecp256k1 deploys TPMVerifierSecp256k1 using deployer wallet.
// Returns deployed contract address + deployment tx hash.
func DeployTPMVerifierSecp256k1(
	ctx context.Context,
	eth *utilsEth.Client,
	deployer wtypes.Wallet,
) (common.Address, common.Hash, error) {

	if eth == nil || deployer == nil {
		return common.Address{}, common.Hash{}, fmt.Errorf("deploy: missing eth client or deployer")
	}

	if err := eth.EnsureBackend(ctx); err != nil {
		return common.Address{}, common.Hash{}, err
	}

	chainID, err := eth.ChainID(ctx) // should be *big.Int in go-utils
	if err != nil {
		return common.Address{}, common.Hash{}, err
	}

	opts, err := transactorFromWallet(ctx, eth, deployer, chainID)
	if err != nil {
		return common.Address{}, common.Hash{}, err
	}

	backend, err := eth.EthClient(ctx)
	if err != nil {
		return common.Address{}, common.Hash{}, err
	}

	addr, tx, _, err := tpmverifier.DeployTPMVerifierSecp256k1(opts, backend)
	if err != nil {
		return common.Address{}, common.Hash{}, fmt.Errorf("deploy TPMVerifierSecp256k1: %w", err)
	}

	receipt, err := bind.WaitMined(ctx, backend, tx)
	if err != nil {
		return common.Address{}, common.Hash{}, fmt.Errorf("wait mined: %w", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return common.Address{}, common.Hash{}, fmt.Errorf("deploy reverted: tx=%s", tx.Hash().Hex())
	}

	return addr, tx.Hash(), nil
}

// DeployQuantumAuthAccount deploys QuantumAuthAccount using deployer wallet.
// Returns deployed contract address + deployment tx hash.
func DeployQuantumAuthAccount(
	ctx context.Context,
	eth *utilsEth.Client,
	deployer wtypes.Wallet,
	p AccountDeployParams,
) (common.Address, common.Hash, error) {

	if eth == nil || deployer == nil {
		return common.Address{}, common.Hash{}, fmt.Errorf("deploy: missing eth client or deployer")
	}

	if err := eth.EnsureBackend(ctx); err != nil {
		return common.Address{}, common.Hash{}, err
	}

	chainID, err := eth.ChainID(ctx) // should be *big.Int in go-utils
	if err != nil {
		return common.Address{}, common.Hash{}, err
	}

	opts, err := transactorFromWallet(ctx, eth, deployer, chainID)
	if err != nil {
		return common.Address{}, common.Hash{}, err
	}

	backend, err := eth.EthClient(ctx)
	if err != nil {
		return common.Address{}, common.Hash{}, err
	}

	log.Info("entry point deployement", "address", p.EntryPoint)

	addr, tx, _, err := quantumauthaccount.DeployQuantumAuthAccount(
		opts,
		backend,
		p.EntryPoint,
		p.EOA1,
		p.EOA2,
		p.TPMVerifier,
		p.TPMKeyID,
	)
	if err != nil {
		return common.Address{}, common.Hash{}, fmt.Errorf("deploy QuantumAuthAccount: %w", err)
	}

	receipt, err := bind.WaitMined(ctx, backend, tx)
	if err != nil {
		return common.Address{}, common.Hash{}, fmt.Errorf("wait mined: %w", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return common.Address{}, common.Hash{}, fmt.Errorf("deploy reverted: tx=%s", tx.Hash().Hex())
	}

	return addr, tx.Hash(), nil
}

func transactorFromWallet(
	ctx context.Context,
	eth *utilsEth.Client,
	w wtypes.Wallet,
	chainID *big.Int,
) (*bind.TransactOpts, error) {

	priv, err := w.ExportPrivateKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("export private key: %w", err)
	}

	opts, err := bind.NewKeyedTransactorWithChainID(priv, chainID)
	if err != nil {
		return nil, err
	}

	// Nonce
	nonce, err := eth.PendingNonceAt(ctx, w.Address())
	if err != nil {
		return nil, err
	}
	opts.Nonce = new(big.Int).SetUint64(nonce)

	// Fees: 1559 preferred, else legacy
	tip, tipErr := eth.SuggestGasTipCap(ctx)
	hdr, hdrErr := eth.HeaderByNumber(ctx, nil)

	if tipErr == nil && hdrErr == nil && hdr.BaseFee != nil {
		feeCap := new(big.Int).Mul(hdr.BaseFee, big.NewInt(2))
		feeCap.Add(feeCap, tip)
		opts.GasTipCap = tip
		opts.GasFeeCap = feeCap
	} else {
		gp, err := eth.SuggestGasPrice(ctx)
		if err != nil {
			return nil, err
		}
		opts.GasPrice = gp
	}

	opts.Context = ctx
	return opts, nil
}
