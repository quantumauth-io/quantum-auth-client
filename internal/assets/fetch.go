package assets

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/quantumauth-io/quantum-auth-client/internal/constants"
	"github.com/quantumauth-io/quantum-auth-client/internal/contracts/bindings/go/qaerc20"
)

func (m *Manager) fetchAsset(ctx context.Context, network string, addr string) (Asset, error) {
	a := common.HexToAddress(addr).Hex() // normalize
	native := common.HexToAddress(constants.NativeAddr).Hex()

	// Native token special-case
	if strings.EqualFold(a, native) {
		return Asset{
			Address:  native,
			Symbol:   "ETH",
			Decimals: 18,
			Name:     "Ether",
		}, nil
	}

	backend := m.backendForNetwork(network) // <-- you implement; must return bind.ContractBackend
	if backend == nil {
		return Asset{}, fmt.Errorf("no backend for network %q", network)
	}

	contractAddr := common.HexToAddress(a)
	call := &bind.CallOpts{Context: ctx}

	token, err := qaerc20.NewQAERC20(contractAddr, backend)
	if err != nil {
		return Asset{}, fmt.Errorf("qaerc20 bind: %w", err)
	}

	sym, err := token.Symbol(call)
	if err != nil {
		return Asset{}, fmt.Errorf("symbol: %w", err)
	}

	dec, err := token.Decimals(call)
	if err != nil {
		return Asset{}, fmt.Errorf("decimals: %w", err)
	}

	name := ""
	if n, err := token.Name(call); err == nil {
		name = n
	}

	// (optional) sanity check for weird tokens
	if dec > 255 {
		return Asset{}, fmt.Errorf("decimals out of range: %d", dec)
	}

	return Asset{
		Address:  contractAddr.Hex(),
		Symbol:   sym,
		Decimals: uint8(dec),
		Name:     name,
	}, nil
}

// --- OPTIONAL: if you want balance too (ERC20) ---
// balance, err := token.BalanceOf(call, ownerAddr)
// returns *big.Int

func big0() *big.Int { return new(big.Int) }
