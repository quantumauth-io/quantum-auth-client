package txsender

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/contracts/bindings/go/entrypoint"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/contracts/bindings/go/quantumauthaccount"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/wtypes"
	"github.com/quantumauth-io/quantum-go-utils/evm"
)

type Network struct {
	Name       string
	EntryPoint string
}

type WalletPicker interface {
	PickWallet(from common.Address) (wtypes.Wallet, error)
}

type UserOpSigner interface {
	SignUserOpHash(ctx context.Context, userOpHash32 []byte) ([]byte, error)
}

type RelayerAuthProvider interface {
	RelayerAuth(ctx context.Context) (*bind.TransactOpts, common.Address, error)
}

type Sender struct {
	Eth        evm.BlockchainClient
	Networks   NetworkResolver
	OnChain    AAOnChain
	Pick       WalletPicker
	SignUserOp UserOpSigner
	Relayer    RelayerAuthProvider
}

type AAOnChain interface {
	ContractAddress() (common.Address, error)
}

type TxRequest struct {
	From  common.Address
	To    *common.Address
	Value *big.Int
	Data  []byte

	MaxFeePerGas         *big.Int
	MaxPriorityFeePerGas *big.Int
}

func (s *Sender) Send(ctx context.Context, req TxRequest) (common.Hash, error) {
	aaAddr, err := s.OnChain.ContractAddress()
	if err == nil && aaAddr != (common.Address{}) && req.From == aaAddr {
		return s.SendAA(ctx, req)
	}
	return s.SendEOA(ctx, req)
}

func (s *Sender) SendEOA(ctx context.Context, req TxRequest) (common.Hash, error) {
	wlt, err := s.Pick.PickWallet(req.From)
	if err != nil {
		return common.Hash{}, err
	}

	chainID, err := s.Eth.ChainID(ctx)
	if err != nil {
		return common.Hash{}, err
	}

	nonce, err := s.Eth.PendingNonceAt(ctx, req.From)
	if err != nil {
		return common.Hash{}, err
	}

	msg := ethereum.CallMsg{
		From:  req.From,
		To:    req.To,
		Value: req.Value,
		Data:  req.Data,
	}

	gas, err := s.Eth.EstimateGas(ctx, msg)
	if err != nil {
		return common.Hash{}, err
	}

	// fees: if req has explicit fee caps use them, else delegate
	maxFee := req.MaxFeePerGas
	maxPrio := req.MaxPriorityFeePerGas
	if maxFee == nil || maxPrio == nil {
		// You can design ResolveEIP1559 to take TxRequest instead.
		// Here shown as separate.
		maxFee, maxPrio, err = ResolveEIP1559Fees(ctx, s.Eth, maxFee, maxPrio)
		if err != nil {
			return common.Hash{}, err
		}
	}

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		Gas:       applyBpsBuffer(gas, 1_000),
		To:        req.To,
		Value:     req.Value,
		Data:      req.Data,
		GasTipCap: maxPrio,
		GasFeeCap: maxFee,
	})

	signedTx, err := SignEOATransaction(ctx, wlt, tx, chainID)
	if err != nil {
		return common.Hash{}, err
	}

	if err := s.Eth.SendTransaction(ctx, signedTx); err != nil {
		return common.Hash{}, err
	}

	return signedTx.Hash(), nil
}

func (s *Sender) SendAA(ctx context.Context, req TxRequest) (common.Hash, error) {
	chainID, err := s.Eth.ChainID(ctx)
	if err != nil {
		return common.Hash{}, err
	}

	netCfg, err := s.Networks.ResolveNetworkByChainID(chainID.Uint64())
	if err != nil {
		return common.Hash{}, err
	}

	entryPointAddr := common.HexToAddress(netCfg.EntryPoint)

	entryPoint, err := entrypoint.NewEntryPoint(entryPointAddr, s.Eth)
	if err != nil {
		return common.Hash{}, err
	}

	sender := req.From
	to := common.Address{}
	if req.To != nil {
		to = *req.To
	}

	value := req.Value
	if value == nil {
		value = new(big.Int)
	}

	accABI, err := quantumauthaccount.QuantumAuthAccountMetaData.GetAbi()
	if err != nil {
		return common.Hash{}, err
	}
	callData, err := accABI.Pack("execute", to, value, req.Data)
	if err != nil {
		return common.Hash{}, err
	}

	maxFee, maxPrio, err := ResolveEIP1559Fees(ctx, s.Eth, req.MaxFeePerGas, req.MaxPriorityFeePerGas)
	if err != nil {
		return common.Hash{}, err
	}

	est := &AAGasEstimator{
		Eth:        s.Eth,
		EntryPoint: entryPointAddr,
		SignUserOp: s.SignUserOp,
	}

	gasEst, err := est.Estimate(ctx, EstimateAARequest{
		Sender: sender,
		To:     to,
		Value:  value,
		Data:   req.Data,
	})
	if err != nil {
		return common.Hash{}, err
	}

	nonce, err := entryPoint.GetNonce(&bind.CallOpts{Context: ctx}, sender, big.NewInt(UserOpDefaultNonceKeyInt64))
	if err != nil {
		return common.Hash{}, err
	}

	userOp := entrypoint.PackedUserOperation{
		Sender:             sender,
		Nonce:              nonce,
		InitCode:           []byte{},
		CallData:           callData,
		AccountGasLimits:   gasEst.AccountGasLimits,
		PreVerificationGas: gasEst.PreVerificationGas,
		GasFees:            PackU128Pair(maxPrio, maxFee),
		PaymasterAndData:   []byte{},
		Signature:          []byte{},
	}

	userOpHash, err := entryPoint.GetUserOpHash(&bind.CallOpts{Context: ctx}, userOp)
	if err != nil {
		return common.Hash{}, err
	}

	sig, err := s.SignUserOp.SignUserOpHash(ctx, userOpHash[:])
	if err != nil {
		return common.Hash{}, err
	}
	userOp.Signature = sig

	auth, beneficiary, err := s.Relayer.RelayerAuth(ctx)
	if err != nil {
		return common.Hash{}, err
	}

	tx, err := entryPoint.HandleOps(auth, []entrypoint.PackedUserOperation{userOp}, beneficiary)
	if err != nil {
		return common.Hash{}, err
	}

	return tx.Hash(), nil
}
