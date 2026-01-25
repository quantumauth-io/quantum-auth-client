package txsender

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/contracts/bindings/go/entrypoint"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/contracts/bindings/go/quantumauthaccount"
	"github.com/quantumauth-io/quantum-go-utils/evm"
)

type EOAEstimate struct {
	GasLimit uint64

	MaxPriorityFeePerGasWei *big.Int
	MaxFeePerGasWei         *big.Int
}

type EstimateAARequest struct {
	Sender common.Address
	To     common.Address
	Value  *big.Int
	Data   []byte
}

type AAEstimate struct {
	// fees
	MaxPriorityFeePerGasWei *big.Int
	MaxFeePerGasWei         *big.Int

	// userOp gas
	CallGasLimit         *big.Int
	VerificationGasLimit *big.Int
	PreVerificationGas   *big.Int

	AccountGasLimits [32]byte
	GasFees          [32]byte

	// optional debug
	AccountGasLimitsHex string
	GasFeesHex          string
}

type EstimateAAResponse struct {
	// optional
	BaseFeeWei *big.Int

	// fees
	MaxPriorityFeePerGasWei *big.Int
	MaxFeePerGasWei         *big.Int

	// gas
	CallGasLimit         *big.Int
	VerificationGasLimit *big.Int
	PreVerificationGas   *big.Int

	// packed fields
	AccountGasLimits [32]byte
	GasFees          [32]byte

	// debug strings
	AccountGasLimitsHex string
	GasFeesHex          string
}

type AAGasEstimator struct {
	Eth        evm.BlockchainClient
	EntryPoint common.Address
	SignUserOp UserOpSigner
}

type FeeOracle interface {
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
}

// Estimate decides between AA and EOA based on req.From
func (s *Sender) Estimate(ctx context.Context, req TxRequest) (*EOAEstimate, *AAEstimate, error) {
	aaAddr, err := s.OnChain.ContractAddress()
	if err == nil && aaAddr != (common.Address{}) && req.From == aaAddr {
		aa, err := s.EstimateAA(ctx, req)
		return nil, aa, err
	}
	eoa, err := s.EstimateEOA(ctx, req)
	return eoa, nil, err
}

func (s *Sender) EstimateEOA(ctx context.Context, req TxRequest) (*EOAEstimate, error) {
	msg := ethereum.CallMsg{
		From:  req.From,
		To:    req.To,
		Value: req.Value,
		Data:  req.Data,
	}

	gas, err := s.Eth.EstimateGas(ctx, msg)
	if err != nil {
		return nil, err
	}
	gas = applyBpsBuffer(gas, 1_000) // +10%

	maxFee, tip, err := ResolveEIP1559Fees(ctx, s.Eth, req.MaxFeePerGas, req.MaxPriorityFeePerGas)
	if err != nil {
		return nil, err
	}

	return &EOAEstimate{
		GasLimit:                gas,
		MaxPriorityFeePerGasWei: tip,
		MaxFeePerGasWei:         maxFee,
	}, nil
}

func (s *Sender) EstimateAA(ctx context.Context, req TxRequest) (*AAEstimate, error) {
	chainID, err := s.Eth.ChainID(ctx)
	if err != nil {
		return nil, err
	}

	netCfg, err := s.Networks.ResolveNetworkByChainID(chainID.Uint64())
	if err != nil {
		return nil, err
	}

	entryPointAddr := common.HexToAddress(netCfg.EntryPoint)

	// fees
	maxFee, tip, err := ResolveEIP1559Fees(ctx, s.Eth, req.MaxFeePerGas, req.MaxPriorityFeePerGas)
	if err != nil {
		return nil, err
	}

	// build AA estimator that knows how to sign the temp userOp
	est := &AAGasEstimator{
		Eth:        s.Eth,
		EntryPoint: entryPointAddr,
		SignUserOp: s.SignUserOp,
	}

	to := common.Address{}
	if req.To != nil {
		to = *req.To
	}
	val := req.Value
	if val == nil {
		val = new(big.Int)
	}

	resp, err := est.Estimate(ctx, EstimateAARequest{
		Sender: req.From,
		To:     to,
		Value:  val,
		Data:   req.Data,
	})
	if err != nil {
		return nil, err
	}

	// overwrite GasFees to match requested fees (estimator may have used defaults)
	gf := PackU128Pair(tip, maxFee)

	return &AAEstimate{
		MaxPriorityFeePerGasWei: tip,
		MaxFeePerGasWei:         maxFee,
		CallGasLimit:            resp.CallGasLimit,
		VerificationGasLimit:    resp.VerificationGasLimit,
		PreVerificationGas:      resp.PreVerificationGas,
		AccountGasLimits:        resp.AccountGasLimits,
		GasFees:                 gf,
		AccountGasLimitsHex:     resp.AccountGasLimitsHex,
		GasFeesHex:              "0x" + fmtBytes32Hex(gf),
	}, nil
}

func ResolveEIP1559Fees(ctx context.Context, eth evm.BlockchainClient, maxFee, tip *big.Int) (*big.Int, *big.Int, error) {
	oracle, ok := any(eth).(FeeOracle)
	if !ok {
		return nil, nil, fmt.Errorf("eth client does not support fee oracle methods (SuggestGasTipCap/HeaderByNumber): %T", eth)
	}

	// Tip
	if tip == nil || tip.Sign() == 0 {
		suggestedTip, err := oracle.SuggestGasTipCap(ctx)
		if err != nil {
			return nil, nil, err
		}
		tip = suggestedTip
	} else {
		tip = new(big.Int).Set(tip)
	}

	// Max fee
	if maxFee == nil || maxFee.Sign() == 0 {
		hdr, err := oracle.HeaderByNumber(ctx, nil)
		if err != nil {
			return nil, nil, err
		}
		baseFee := hdr.BaseFee
		if baseFee == nil {
			baseFee = big.NewInt(0)
		}
		// heuristic: maxFee = 2*baseFee + tip
		maxFee = new(big.Int).Add(new(big.Int).Mul(baseFee, big.NewInt(2)), tip)
	} else {
		maxFee = new(big.Int).Set(maxFee)
	}

	return maxFee, tip, nil
}

func (e *AAGasEstimator) Estimate(ctx context.Context, req EstimateAARequest) (*EstimateAAResponse, error) {
	if e == nil || e.Eth == nil || e.SignUserOp == nil {
		return nil, fmt.Errorf("AA estimator not initialized")
	}
	if e.EntryPoint == (common.Address{}) {
		return nil, fmt.Errorf("entryPoint missing")
	}
	if req.Value == nil {
		req.Value = new(big.Int)
	}

	ep, err := entrypoint.NewEntryPoint(e.EntryPoint, e.Eth)
	if err != nil {
		return nil, err
	}

	accABI, err := quantumauthaccount.QuantumAuthAccountMetaData.GetAbi()
	if err != nil {
		return nil, err
	}

	callData, err := accABI.Pack("execute", req.To, req.Value, req.Data)
	if err != nil {
		return nil, err
	}

	nonce, err := ep.GetNonce(&bind.CallOpts{Context: ctx}, req.Sender, big.NewInt(UserOpDefaultNonceKeyInt64))
	if err != nil {
		return nil, err
	}

	// fees (use same resolver as EOA)
	maxFee, tip, err := ResolveEIP1559Fees(ctx, e.Eth, nil, nil)
	if err != nil {
		return nil, err
	}

	// temp values used for estimation
	preVerificationGas := new(big.Int).SetUint64(UserOpDefaultPreVerificationGasUint64)
	callGasTmp := new(big.Int).SetUint64(UserOpEstimateTmpCallGasLimitUint64)
	verificationGasTmp := new(big.Int).SetUint64(UserOpEstimateTmpVerificationGasLimitUint64)

	userOp := entrypoint.PackedUserOperation{
		Sender:             req.Sender,
		Nonce:              nonce,
		InitCode:           []byte{},
		CallData:           callData,
		AccountGasLimits:   PackU128Pair(callGasTmp, verificationGasTmp),
		PreVerificationGas: preVerificationGas,
		GasFees:            PackU128Pair(tip, maxFee),
		PaymasterAndData:   []byte{},
		Signature:          []byte{},
	}

	userOpHash, err := ep.GetUserOpHash(&bind.CallOpts{Context: ctx}, userOp)
	if err != nil {
		return nil, err
	}

	sig, err := e.SignUserOp.SignUserOpHash(ctx, userOpHash[:])
	if err != nil {
		return nil, err
	}
	userOp.Signature = sig

	callGasU64, err := e.Eth.EstimateGas(ctx, ethereum.CallMsg{
		From: e.EntryPoint,
		To:   &req.Sender,
		Data: callData,
	})
	if err != nil {

		callGasU64 = GasEstimateCallGasFallbackUint64
	}
	callGasLimit := new(big.Int).SetUint64(applyBpsBuffer(callGasU64, GasBufferBpsCallGasLimit))

	missingFunds := big.NewInt(UserOpDefaultMissingFundsWeiInt64)

	validateCalldata, err := accABI.Pack("validateUserOp", userOp, userOpHash, missingFunds)
	if err != nil {
		return nil, err
	}

	verificationGasU64, err := e.Eth.EstimateGas(ctx, ethereum.CallMsg{
		From: e.EntryPoint,
		To:   &req.Sender,
		Data: validateCalldata,
	})
	if err != nil {
		verificationGasU64 = GasEstimateVerificationGasFallbackUint64
	}
	verificationGasLimit := new(big.Int).SetUint64(applyBpsBuffer(verificationGasU64, GasBufferBpsVerificationGasLimit))

	agl := PackU128Pair(callGasLimit, verificationGasLimit)
	gf := PackU128Pair(tip, maxFee)

	return &EstimateAAResponse{
		BaseFeeWei:              nil, // optional (you can return hdr.BaseFee if you want)
		MaxPriorityFeePerGasWei: new(big.Int).Set(tip),
		MaxFeePerGasWei:         new(big.Int).Set(maxFee),

		CallGasLimit:         callGasLimit,
		VerificationGasLimit: verificationGasLimit,
		PreVerificationGas:   preVerificationGas,

		AccountGasLimits: agl,
		GasFees:          gf,

		AccountGasLimitsHex: "0x" + hex.EncodeToString(agl[:]),
		GasFeesHex:          "0x" + hex.EncodeToString(gf[:]),
	}, nil
}
