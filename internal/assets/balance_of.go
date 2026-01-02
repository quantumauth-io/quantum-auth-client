package assets

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"

	"github.com/quantumauth-io/quantum-auth-client/internal/constants"
	"github.com/quantumauth-io/quantum-auth-client/internal/contracts/bindings/go/qaerc20"
	"github.com/quantumauth-io/quantum-go-utils/ethrpc"
)

// BalanceOf returns the balance for `owner`.
// - If token == NativeAddr (0x000..0): returns ETH balance (wei)
// - Else: returns ERC20 balance (raw units)
func (m *Manager) BalanceOf(ctx context.Context, network string, token common.Address, owner common.Address) (*big.Int, error) {
	_ = normalizeNetworkKey(network) // keep for future multi-network backend routing

	if m.clients == nil {
		return nil, fmt.Errorf("assets: eth client not initialized")
	}

	// ✅ ZERO ADDRESS → always zero, no RPC call
	if owner == (common.Address{}) {
		return big.NewInt(0), nil
	}

	// Native ETH sentinel
	native := common.HexToAddress(constants.NativeAddr)
	if strings.EqualFold(token.Hex(), native.Hex()) {
		wei, err := m.clients.GetBalance(ctx, owner.String(), ethrpc.BlockLatest) // latest
		if err != nil {
			return nil, fmt.Errorf("assets: native balance: %w", err)
		}
		return wei, nil
	}

	backend := m.backendForNetwork(network)
	if backend == nil {
		return nil, fmt.Errorf("assets: no backend for network %q", network)
	}

	erc, err := qaerc20.NewQAERC20(token, backend)
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
