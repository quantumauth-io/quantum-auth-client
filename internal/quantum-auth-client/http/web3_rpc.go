package http

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"
	"github.com/quantumauth-io/quantum-go-utils/evm"
)

var errInvalidParams = errors.New("invalid params")

type Web3RPC struct {
	chains *chains.QAChainService
}

// NewWeb3RPC constructs a Web3RPC bound to chain service.
func NewWeb3RPC(chainsSvc *chains.QAChainService) *Web3RPC {
	return &Web3RPC{chains: chainsSvc}
}

// EthGetBalance implements eth_getBalance(params) and returns a hex quantity string.
func (r *Web3RPC) EthGetBalance(ctx context.Context, params any) (string, error) {
	client, err := r.activeHTTP()
	if err != nil {
		return "", err
	}

	rawSlice, err := asAnySlice(params)
	if err != nil {
		return "", err
	}

	if len(rawSlice) < 1 || len(rawSlice) > 2 {
		return "", fmt.Errorf("%w: expected [address, blockTag?]", errInvalidParams)
	}

	// address
	addrStr, ok := rawSlice[0].(string)
	if !ok {
		return "", fmt.Errorf("%w: address must be a string", errInvalidParams)
	}
	addrStr = strings.TrimSpace(addrStr)
	if !common.IsHexAddress(addrStr) {
		return "", fmt.Errorf("%w: invalid address %q", errInvalidParams, addrStr)
	}
	address := common.HexToAddress(addrStr)

	// block tag (optional)
	var blockNumber *big.Int // nil = latest
	if len(rawSlice) == 2 && rawSlice[1] != nil {
		tag, ok := rawSlice[1].(string)
		if !ok {
			return "", fmt.Errorf("%w: block tag must be a string", errInvalidParams)
		}
		tag = strings.TrimSpace(strings.ToLower(tag))

		switch tag {
		case "", "latest":
			blockNumber = nil
		case "pending":
			// BalanceAt doesn't support pending directly; treat as latest.
			blockNumber = nil
		case "earliest":
			blockNumber = big.NewInt(0)
		default:
			// hex quantity like "0x1234" (SetString base 0 accepts 0x)
			bn := new(big.Int)
			if _, ok := bn.SetString(tag, 0); !ok || bn.Sign() < 0 {
				return "", fmt.Errorf("%w: invalid block tag %q", errInvalidParams, tag)
			}
			blockNumber = bn
		}
	}

	balanceWei, err := client.BalanceAt(ctx, address, blockNumber)
	if err != nil {
		return "", fmt.Errorf("get balance: %w", err)
	}
	if balanceWei == nil {
		return "0x0", nil
	}

	return "0x" + balanceWei.Text(16), nil
}

func (r *Web3RPC) activeHTTP() (evm.BlockchainClient, error) {
	if r == nil || r.chains == nil {
		return nil, fmt.Errorf("chain service not initialized")
	}
	chainClients, err := r.chains.Active()
	if err != nil {
		return nil, fmt.Errorf("no active chain: %w", err)
	}
	if chainClients == nil || chainClients.HTTP == nil {
		return nil, fmt.Errorf("no http client")
	}
	return chainClients.HTTP, nil
}

func asAnySlice(params any) ([]any, error) {
	if params == nil {
		return nil, fmt.Errorf("%w: params must be an array", errInvalidParams)
	}
	if s, ok := params.([]any); ok {
		return s, nil
	}
	if s2, ok := params.([]interface{}); ok {
		out := make([]any, len(s2))
		for i := range s2 {
			out[i] = s2[i]
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: params must be an array", errInvalidParams)
}
