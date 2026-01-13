package contractwallet

import (
	"context"

	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
)

func (r *Runtime) estimateGasLimit(ctx context.Context, from common.Address, to *common.Address, value *big.Int, data []byte) uint64 {

	client, err := r.activeHTTP(ctx)
	if err != nil {
		return 0
	}

	msg := ethereum.CallMsg{
		From:  from,
		To:    nil,
		Value: value,
		Data:  nil,
	}
	if to != nil {
		msg.To = to
	}
	if len(data) > 0 {
		msg.Data = data
	}

	est, err := client.EstimateGas(ctx, msg)
	if err != nil {
		if to == nil {
			return 1_500_000
		}
		return 250_000
	}

	u := est
	u = u + (u / 10) // +10%
	if u < 21_000 {
		u = 21_000
	}
	return u
}

func (r *Runtime) Suggest1559Fees(ctx context.Context) (maxFee, maxPrio *big.Int, ok bool) {
	client, err := r.activeHTTP(ctx)
	if err != nil {
		return nil, nil, false
	}
	history, err := client.FeeHistory(ctx, 5, nil, []float64{10})
	if err == nil && len(history.BaseFee) > 0 {

		baseNext := history.BaseFee[len(history.BaseFee)-1]

		priority := (*big.Int)(nil)

		if len(history.Reward) > 0 {
			last := history.Reward[len(history.Reward)-1]
			if len(last) > 0 && last[0] != nil && last[0].Sign() > 0 {
				priority = new(big.Int).Set(last[0])
			}
		}

		if priority == nil {
			if tip, tipErr := client.SuggestGasTipCap(ctx); tipErr == nil && tip != nil && tip.Sign() >= 0 {
				priority = tip
			}
		}

		if priority != nil && baseNext != nil {

			feeCap := new(big.Int).Mul(baseNext, big.NewInt(2))
			feeCap.Add(feeCap, priority)
			return feeCap, priority, true
		}
	}

	if header, err := client.HeaderByNumber(ctx, nil); err == nil && header != nil && header.BaseFee != nil {
		if tip, tipErr := client.SuggestGasTipCap(ctx); tipErr == nil && tip != nil {
			feeCap := new(big.Int).Mul(header.BaseFee, big.NewInt(2))
			feeCap.Add(feeCap, tip)
			return feeCap, tip, true
		}
	}

	if gasPrice, err := client.SuggestGasPrice(ctx); err == nil && gasPrice != nil && gasPrice.Sign() > 0 {
		return new(big.Int).Set(gasPrice), new(big.Int).Set(gasPrice), true
	}

	return nil, nil, false
}
