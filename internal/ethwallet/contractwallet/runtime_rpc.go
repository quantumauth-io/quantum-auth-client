package contractwallet

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	utilsEth "github.com/quantumauth-io/quantum-go-utils/ethrpc"

	"github.com/quantumauth-io/quantum-auth-client/internal/ethwallet/wtypes"
)

// TxOpts controls tx construction.
type TxOpts struct {
	To       *common.Address
	ValueWei *big.Int
	Data     []byte

	Nonce    *big.Int // if nil -> pending
	GasLimit uint64   // if 0 -> estimate (+margin)

	// If set, forces legacy tx.
	ForceLegacy bool

	// Optional overrides:
	GasPrice             *big.Int // legacy
	MaxFeePerGas         *big.Int // 1559
	MaxPriorityFeePerGas *big.Int // 1559
}

func (r *Runtime) SendLegacyFromUser(ctx context.Context, opts TxOpts) (common.Hash, string, error) {
	return r.SendLegacyTxFrom(ctx, r.User, opts)
}

func (r *Runtime) SendLegacyFromDevice(ctx context.Context, opts TxOpts) (common.Hash, string, error) {
	return r.SendLegacyTxFrom(ctx, r.Device, opts)
}

// ChainIDBig returns chain id as big.Int.
// Prefers configured chain id, otherwise asks RPC.
func (r *Runtime) ChainIDBig(ctx context.Context) (*big.Int, error) {
	if r == nil || r.Eth == nil {
		return nil, fmt.Errorf("contractwallet: Eth client not initialized")
	}
	if r.Contract != nil && r.Contract.ChainID != 0 {
		return new(big.Int).SetUint64(r.Contract.ChainID), nil
	}

	// go-utils: ChainID returns *big.Int
	return r.Eth.ChainID(ctx)
}

func (r *Runtime) estimateGasLimit(ctx context.Context, from common.Address, to *common.Address, value *big.Int, data []byte) uint64 {
	msg := utilsEth.CallMsg{
		From:  from.Hex(),
		To:    "",
		Value: utilsEth.BigToHexQuantity(value),
		Data:  "",
	}
	if to != nil {
		msg.To = to.Hex()
	}
	if len(data) > 0 {
		msg.Data = "0x" + hex.EncodeToString(data)
	}

	est, err := r.Eth.EstimateGas(ctx, msg)
	if err != nil {
		if to == nil {
			return 1_500_000
		}
		return 250_000
	}

	u := est.Uint64()
	u = u + (u / 10) // +10%
	if u < 21_000 {
		u = 21_000
	}
	return u
}

// Suggest1559Fees tries eth_feeHistory (best) then eth_maxPriorityFeePerGas, otherwise returns ok=false.
func (r *Runtime) Suggest1559Fees(ctx context.Context) (maxFee, maxPrio *big.Int, ok bool) {
	h, err := r.Eth.FeeHistory(ctx, "0x5", utilsEth.BlockLatest, []float64{10})
	if err == nil && len(h.BaseFeePerGas) > 0 {
		baseNext, e := utilsEth.HexQuantity(h.BaseFeePerGas[len(h.BaseFeePerGas)-1]).Big()
		if e == nil {
			prio := big.NewInt(0)
			if len(h.Reward) > 0 && len(h.Reward[len(h.Reward)-1]) > 0 {
				if p, e2 := utilsEth.HexQuantity(h.Reward[len(h.Reward)-1][0]).Big(); e2 == nil {
					prio = p
				}
			}
			mf := new(big.Int).Mul(baseNext, big.NewInt(2))
			mf.Add(mf, prio)
			return mf, prio, true
		}
	}

	pr, err := r.Eth.MaxPriorityFeePerGas(ctx)
	if err == nil {
		gp, e2 := r.Eth.GasPrice(ctx)
		if e2 == nil && gp.Sign() > 0 {
			return gp, pr, true
		}
	}

	return nil, nil, false
}

// SendTxFrom builds, signs, and broadcasts a tx.
// Prefers EIP-1559 when possible unless ForceLegacy is true.
func (r *Runtime) SendTxFrom(ctx context.Context, w wtypes.Wallet, opts TxOpts) (txHash common.Hash, rawTxHex string, err error) {
	if r == nil || r.Eth == nil {
		return common.Hash{}, "", fmt.Errorf("contractwallet: Eth client not initialized")
	}
	if w == nil {
		return common.Hash{}, "", fmt.Errorf("contractwallet: wallet is nil")
	}

	chainID, err := r.ChainIDBig(ctx)
	if err != nil {
		return common.Hash{}, "", fmt.Errorf("chain id: %w", err)
	}

	from := w.Address()

	nonce := opts.Nonce
	if nonce == nil {
		nonce, err = r.NonceOf(ctx, from, true)
		if err != nil {
			return common.Hash{}, "", fmt.Errorf("nonce: %w", err)
		}
	}

	value := opts.ValueWei
	if value == nil {
		value = big.NewInt(0)
	}

	gasLimit := opts.GasLimit
	if gasLimit == 0 {
		gasLimit = r.estimateGasLimit(ctx, from, opts.To, value, opts.Data)
	}

	// Build either 1559 or legacy
	var tx *gethtypes.Transaction

	use1559 := !opts.ForceLegacy
	var maxFee, maxPrio *big.Int
	if use1559 {
		maxFee = opts.MaxFeePerGas
		maxPrio = opts.MaxPriorityFeePerGas

		if maxFee == nil || maxPrio == nil {
			if mf, mp, ok := r.Suggest1559Fees(ctx); ok {
				if maxFee == nil {
					maxFee = mf
				}
				if maxPrio == nil {
					maxPrio = mp
				}
			} else {
				use1559 = false
			}
		}
	}

	if use1559 {
		tx = gethtypes.NewTx(&gethtypes.DynamicFeeTx{
			ChainID:   chainID,
			Nonce:     nonce.Uint64(),
			GasTipCap: maxPrio,
			GasFeeCap: maxFee,
			Gas:       gasLimit,
			To:        opts.To,
			Value:     value,
			Data:      opts.Data,
		})
	} else {
		gasPrice := opts.GasPrice
		if gasPrice == nil {
			gasPrice, err = r.Eth.GasPrice(ctx)
			if err != nil {
				return common.Hash{}, "", fmt.Errorf("gas price: %w", err)
			}
		}
		tx = gethtypes.NewTx(&gethtypes.LegacyTx{
			Nonce:    nonce.Uint64(),
			To:       opts.To,
			Value:    value,
			Gas:      gasLimit,
			GasPrice: gasPrice,
			Data:     opts.Data,
		})
	}

	// Sign digest produced by signer
	signer := gethtypes.LatestSignerForChainID(chainID)
	digest := signer.Hash(tx).Bytes()
	if len(digest) != 32 {
		return common.Hash{}, "", fmt.Errorf("unexpected signer hash length %d", len(digest))
	}

	sig, err := w.SignHash(ctx, digest) // 65 bytes R||S||V (V=0/1)
	if err != nil {
		return common.Hash{}, "", fmt.Errorf("sign: %w", err)
	}
	if len(sig) != 65 {
		return common.Hash{}, "", fmt.Errorf("signature must be 65 bytes, got %d", len(sig))
	}

	signedTx, err := tx.WithSignature(signer, sig)
	if err != nil {
		return common.Hash{}, "", fmt.Errorf("with signature: %w", err)
	}

	// Marshal binary (handles typed tx properly)
	bin, err := signedTx.MarshalBinary()
	if err != nil {
		return common.Hash{}, "", fmt.Errorf("marshal tx: %w", err)
	}
	rawTxHex = "0x" + hex.EncodeToString(bin)

	if err := utilsEth.ValidateRawTxHex(rawTxHex); err != nil {
		return common.Hash{}, "", fmt.Errorf("raw tx invalid: %w", err)
	}

	txHash, err = r.Eth.SendRawTransaction(ctx, rawTxHex)
	if err != nil {
		return common.Hash{}, rawTxHex, fmt.Errorf("send raw tx: %w", err)
	}
	return txHash, rawTxHex, nil
}

// WaitMined polls for a receipt until mined or timeout.
func (r *Runtime) WaitMined(ctx context.Context, txHash common.Hash, timeout time.Duration) (*utilsEth.TxReceipt, error) {
	if r == nil || r.Eth == nil {
		return nil, fmt.Errorf("contractwallet: Eth client not initialized")
	}
	deadline := time.Now().Add(timeout)
	delay := 750 * time.Millisecond

	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout waiting for tx %s", txHash.Hex())
		}

		receipt, err := r.Eth.GetTransactionReceiptRaw(ctx, txHash.Hex())
		if err != nil {
			return nil, err
		}
		if receipt != nil {
			return receipt, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
			if delay < 3*time.Second {
				delay += 250 * time.Millisecond
			}
		}
	}
}

// SendLegacyTxFrom builds, signs, and broadcasts a legacy (type 0) transaction.
func (r *Runtime) SendLegacyTxFrom(ctx context.Context, w wtypes.Wallet, opts TxOpts) (txHash common.Hash, rawTxHex string, err error) {
	if r == nil || r.Eth == nil {
		return common.Hash{}, "", fmt.Errorf("contractwallet: Eth client not initialized")
	}
	if w == nil {
		return common.Hash{}, "", fmt.Errorf("contractwallet: wallet is nil")
	}

	chainID, err := r.ChainIDBig(ctx)
	if err != nil {
		return common.Hash{}, "", fmt.Errorf("chain id: %w", err)
	}

	from := w.Address()

	// Nonce
	nonce := opts.Nonce
	if nonce == nil {
		nonce, err = r.NonceOf(ctx, from, true) // pending nonce for sending tx
		if err != nil {
			return common.Hash{}, "", fmt.Errorf("nonce: %w", err)
		}
	}

	// Value
	value := opts.ValueWei
	if value == nil {
		value = big.NewInt(0)
	}

	// Gas price
	gasPrice := opts.GasPrice
	if gasPrice == nil {
		gasPrice, err = r.Eth.GasPrice(ctx)
		if err != nil {
			return common.Hash{}, "", fmt.Errorf("gas price: %w", err)
		}
	}

	// Gas limit
	gasLimit := opts.GasLimit
	if gasLimit == 0 {
		msg := utilsEth.CallMsg{
			From:  from.Hex(),
			To:    "",
			Gas:   "", // let node estimate
			Value: utilsEth.BigToHexQuantity(value),
			Data:  "",
		}
		if opts.To != nil {
			msg.To = opts.To.Hex()
		}
		if len(opts.Data) > 0 {
			msg.Data = "0x" + hex.EncodeToString(opts.Data)
		}

		est, e := r.Eth.EstimateGas(ctx, msg)
		if e != nil {
			// Estimation can fail on some nodes; use a conservative fallback.
			// You can tighten this later.
			gasLimit = 250_000
		} else {
			// Add a small safety margin (10%)
			estU := est.Uint64()
			gasLimit = estU + (estU / 10)
			if gasLimit < 21_000 {
				gasLimit = 21_000
			}
		}
	}

	// Build tx
	var to *common.Address = opts.To
	tx := gethtypes.NewTx(&gethtypes.LegacyTx{
		Nonce:    nonce.Uint64(),
		To:       to,
		Value:    value,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     opts.Data,
	})

	// Sign
	signer := gethtypes.LatestSignerForChainID(chainID)

	digest := signer.Hash(tx).Bytes()
	if len(digest) != 32 {
		return common.Hash{}, "", fmt.Errorf("unexpected signer hash length %d", len(digest))
	}

	sig, err := w.SignHash(ctx, digest) // MUST be 65 bytes (R||S||V) with V=0/1
	if err != nil {
		return common.Hash{}, "", fmt.Errorf("sign: %w", err)
	}
	if len(sig) != 65 {
		return common.Hash{}, "", fmt.Errorf("signature must be 65 bytes, got %d", len(sig))
	}

	signedTx, err := tx.WithSignature(signer, sig)
	if err != nil {
		return common.Hash{}, "", fmt.Errorf("with signature: %w", err)
	}

	// RLP encode
	rlpBytes, err := rlp.EncodeToBytes(signedTx)
	if err != nil {
		return common.Hash{}, "", fmt.Errorf("rlp encode: %w", err)
	}
	rawTxHex = "0x" + hex.EncodeToString(rlpBytes)

	// Cheap sanity check
	if err := utilsEth.ValidateRawTxHex(rawTxHex); err != nil {
		return common.Hash{}, "", fmt.Errorf("raw tx invalid: %w", err)
	}

	// Broadcast

	// Normalize into common.Hash
	txHash, err = r.Eth.SendRawTransaction(ctx, rawTxHex)
	if err != nil {
		return common.Hash{}, rawTxHex, fmt.Errorf("send raw tx: %w", err)
	}
	return txHash, rawTxHex, nil
}

func (r *Runtime) BalanceOf(ctx context.Context, addr common.Address) (*big.Int, error) {
	if r == nil || r.Eth == nil {
		return nil, fmt.Errorf("contractwallet: Eth client not initialized")
	}
	return r.Eth.GetBalance(ctx, addr.Hex(), utilsEth.BlockLatest)
}

func (r *Runtime) Balance(ctx context.Context, w wtypes.Wallet) (*big.Int, error) {
	if w == nil {
		return nil, fmt.Errorf("contractwallet: wallet is nil")
	}
	return r.BalanceOf(ctx, w.Address())
}

func (r *Runtime) UserBalance(ctx context.Context) (*big.Int, error) {
	return r.BalanceOf(ctx, r.UserAddress())
}

func (r *Runtime) DeviceBalance(ctx context.Context) (*big.Int, error) {
	return r.BalanceOf(ctx, r.DeviceAddress())
}

func (r *Runtime) ContractBalance(ctx context.Context) (*big.Int, error) {
	addr, err := r.ContractAddress()
	if err != nil {
		return nil, err
	}
	return r.BalanceOf(ctx, addr)
}

func (r *Runtime) NonceOf(ctx context.Context, addr common.Address, pending bool) (*big.Int, error) {
	if r == nil || r.Eth == nil {
		return nil, fmt.Errorf("contractwallet: Eth client not initialized")
	}
	tag := utilsEth.BlockLatest
	if pending {
		tag = utilsEth.BlockPending
	}
	return r.Eth.GetTransactionCount(ctx, addr.Hex(), tag)
}

func (r *Runtime) Nonce(ctx context.Context, w wtypes.Wallet, pending bool) (*big.Int, error) {
	if w == nil {
		return nil, fmt.Errorf("contractwallet: wallet is nil")
	}
	return r.NonceOf(ctx, w.Address(), pending)
}

func (r *Runtime) UserNonce(ctx context.Context, pending bool) (*big.Int, error) {
	return r.NonceOf(ctx, r.UserAddress(), pending)
}

func (r *Runtime) DeviceNonce(ctx context.Context, pending bool) (*big.Int, error) {
	return r.NonceOf(ctx, r.DeviceAddress(), pending)
}
