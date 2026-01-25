package assets

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/constants"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/contracts/bindings/go/qaerc20"
)

func (m *Manager) BalanceOf(ctx context.Context, network string, token common.Address, owner common.Address) (*big.Int, error) {
	_ = normalizeNetworkKey(network) // keep for future multi-network backend routing

	client, err := m.chainsService.ActiveHTTP(ctx)
	if err != nil {
		return nil, fmt.Errorf("assets: eth client not initialized")
	}

	if owner == (common.Address{}) {
		return big.NewInt(0), nil
	}

	native := common.HexToAddress(constants.NativeAddr)
	if strings.EqualFold(token.Hex(), native.Hex()) {
		wei, err := client.BalanceAt(ctx, owner, nil)
		if err != nil {
			return nil, fmt.Errorf("assets: native balance: %w", err)
		}
		return wei, nil
	}

	erc, err := qaerc20.NewQAERC20(token, client)
	if err != nil {
		return nil, fmt.Errorf("assets: bind erc20: %w", err)
	}

	call := &bind.CallOpts{Context: ctx}
	bal, err := erc.BalanceOf(call, owner)
	if err != nil {
		return nil, fmt.Errorf("assets: erc20 balanceOf: %w", err)
	}

	return bal, nil
}
