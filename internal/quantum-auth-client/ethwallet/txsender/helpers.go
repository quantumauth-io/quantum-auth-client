package txsender

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/wtypes"
)

func SignEOATransaction(
	ctx context.Context,
	w wtypes.Wallet,
	tx *types.Transaction,
	chainID *big.Int,
) (*types.Transaction, error) {

	signer := types.LatestSignerForChainID(chainID)
	digest := signer.Hash(tx)
	sig, err := w.SignHash(ctx, digest.Bytes())
	if err != nil {

		return nil, err
	}

	return tx.WithSignature(signer, sig)
}

func PackU128Pair(low, high *big.Int) [32]byte {
	// packs two uint128 into 32 bytes: (high << 128) | low
	out := [32]byte{}
	x := new(big.Int).Set(high)
	x.Lsh(x, 128)
	x.Or(x, new(big.Int).Set(low))
	b := x.FillBytes(make([]byte, 32))
	copy(out[:], b)
	return out
}

func applyBpsBuffer(x uint64, bps uint64) uint64 {
	return x + (x*bps)/10_000
}

func fmtBytes32Hex(b [32]byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 64)
	for _, v := range b {
		out = append(out, hex[v>>4], hex[v&0x0f])
	}
	return string(out)
}

func u128be(x *big.Int) [16]byte {
	var out [16]byte
	if x == nil {
		return out
	}
	xb := x.Bytes()
	if len(xb) > 16 {
		// truncate to lowest 16 bytes (or you could panic / return error)
		xb = xb[len(xb)-16:]
	}
	copy(out[16-len(xb):], xb)
	return out
}
