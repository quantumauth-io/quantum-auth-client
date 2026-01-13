package http

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

var errInvalidParams = errors.New("invalid params")

func (s *Server) handleEthGetBalance(ctx context.Context, params any) (string, error) {
	// Get active HTTP client
	chainClients, err := s.chainService.Active()
	if err != nil {
		return "", fmt.Errorf("no active chain: %w", err)
	}
	if chainClients == nil || chainClients.HTTP == nil {
		return "", fmt.Errorf("no http client")
	}
	client := chainClients.HTTP

	// Params must be array: [address, blockTag?]
	rawSlice, ok := params.([]any)
	if !ok {
		// Sometimes decoders use []interface{}; []any is alias but keep this for clarity.
		if s2, ok2 := params.([]interface{}); ok2 {
			rawSlice = s2
		} else {
			return "", fmt.Errorf("%w: params must be an array", errInvalidParams)
		}
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
	var blockNumber *big.Int = nil // nil = latest
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
			// BalanceAt doesn't support pending directly; treat as latest for now.
			blockNumber = nil
		case "earliest":
			blockNumber = big.NewInt(0)
		default:
			// hex quantity like "0x1234"
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

	// Return hex quantity string
	return "0x" + balanceWei.Text(16), nil
}
