package assets

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/constants"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/contracts/bindings/go/qaerc20"
)

func (m *Manager) FetchAsset(ctx context.Context, network string, addr string) (Asset, error) {
	contractAddress := common.HexToAddress(addr).Hex()
	native := common.HexToAddress(constants.NativeAddr).Hex()

	// Native token special-case
	if strings.EqualFold(contractAddress, native) {
		return Asset{
			Address:  native,
			Symbol:   "ETH",
			Decimals: 18,
			Name:     "Ether",
		}, nil
	}

	if m.chainsService == nil {
		return Asset{}, fmt.Errorf("chainService not initialized")
	}

	chainClients, err := m.chainsService.ClientsForNetwork(ctx, network)
	if err != nil {
		return Asset{}, fmt.Errorf("get clients for network %q: %w", network, err)
	}
	if chainClients == nil || chainClients.HTTP == nil {
		return Asset{}, fmt.Errorf("no http client for network %q", network)
	}

	backend := chainClients.HTTP

	callOptions := &bind.CallOpts{Context: ctx}
	contract := common.HexToAddress(contractAddress)

	token, err := qaerc20.NewQAERC20(contract, backend)
	if err != nil {
		return Asset{}, fmt.Errorf("qaerc20 bind: %w", err)
	}

	symbol, err := token.Symbol(callOptions)
	if err != nil {
		return Asset{}, fmt.Errorf("symbol: %w", err)
	}

	decimals, err := token.Decimals(callOptions)
	if err != nil {
		return Asset{}, fmt.Errorf("decimals: %w", err)
	}

	name := ""
	if n, err := token.Name(callOptions); err == nil {
		name = n
	}

	// sanity check
	if decimals > 255 {
		return Asset{}, fmt.Errorf("decimals out of range: %d", decimals)
	}

	return Asset{
		Address:  contract.Hex(),
		Symbol:   symbol,
		Decimals: decimals,
		Name:     name,
	}, nil
}
