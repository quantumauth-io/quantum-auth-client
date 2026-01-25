package contractwallet

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/quantumauth-io/quantum-go-utils/evm"
	"github.com/quantumauth-io/quantum-go-utils/log"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/contracts/bindings/go/quantumauthaccount"
	tpmverifier "github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/contracts/bindings/go/tpmverifiersecp256k1"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/wtypes"
)

type AccountDeployParams struct {
	EntryPoint  common.Address
	EOA1        common.Address
	EOA2        common.Address
	TPMVerifier common.Address
	TPMKeyID    [32]byte
}

func DeployTPMVerifierSecp256k1(ctx context.Context, client evm.BlockchainClient, deployer wtypes.Wallet) (common.Address, common.Hash, error) {

	if client == nil || deployer == nil {
		return common.Address{}, common.Hash{}, fmt.Errorf("deploy: missing eth client or deployer")
	}

	chainID, err := client.ChainID(ctx) // should be *big.Int in go-utils
	if err != nil {
		return common.Address{}, common.Hash{}, err
	}

	opts, err := transactorFromWallet(ctx, client, deployer, chainID)
	if err != nil {
		return common.Address{}, common.Hash{}, err
	}

	addr, tx, _, err := tpmverifier.DeployTPMVerifierSecp256k1(opts, client)
	if err != nil {
		return common.Address{}, common.Hash{}, fmt.Errorf("deploy TPMVerifierSecp256k1: %w", err)
	}

	log.Info("QuantumAuthAccount deployed", "address", addr, "tx", tx.Hash().Hex())

	return addr, tx.Hash(), nil
}

func DeployQuantumAuthAccount(ctx context.Context, client evm.BlockchainClient, deployer wtypes.Wallet, params AccountDeployParams) (common.Address, common.Hash, error) {

	if client == nil || deployer == nil {
		return common.Address{}, common.Hash{}, fmt.Errorf("deploy: missing eth client or deployer")
	}

	chainID, err := client.ChainID(ctx) // should be *big.Int in go-utils
	if err != nil {
		return common.Address{}, common.Hash{}, err
	}

	opts, err := transactorFromWallet(ctx, client, deployer, chainID)
	if err != nil {
		return common.Address{}, common.Hash{}, err
	}

	addr, tx, _, err := quantumauthaccount.DeployQuantumAuthAccount(
		opts,
		client,
		params.EntryPoint,
		params.EOA1,
		params.EOA2,
		params.TPMVerifier,
		params.TPMKeyID,
	)
	if err != nil {
		return common.Address{}, common.Hash{}, fmt.Errorf("deploy QuantumAuthAccount: %w", err)
	}

	log.Info("TPMVerifierSecp256k1 deployed", "address", addr, "tx", tx.Hash().Hex())

	return addr, tx.Hash(), nil
}

func transactorFromWallet(ctx context.Context, client evm.BlockchainClient, wallet wtypes.Wallet, chainID *big.Int) (*bind.TransactOpts, error) {

	priv, err := wallet.ExportPrivateKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("export private key: %w", err)
	}

	opts, err := bind.NewKeyedTransactorWithChainID(priv, chainID)
	if err != nil {
		return nil, err
	}

	nonce, err := client.PendingNonceAt(ctx, wallet.Address())
	if err != nil {
		return nil, err
	}
	opts.Nonce = new(big.Int).SetUint64(nonce)

	tip, tipErr := client.SuggestGasTipCap(ctx)
	hdr, hdrErr := client.HeaderByNumber(ctx, nil)

	if tipErr == nil && hdrErr == nil && hdr.BaseFee != nil {
		feeCap := new(big.Int).Mul(hdr.BaseFee, big.NewInt(2))
		feeCap.Add(feeCap, tip)
		opts.GasTipCap = tip
		opts.GasFeeCap = feeCap
	} else {
		gp, err := client.SuggestGasPrice(ctx)
		if err != nil {
			return nil, err
		}
		opts.GasPrice = gp
	}

	opts.Context = ctx
	return opts, nil
}
