package assets

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/quantumauth-io/quantum-auth-client/internal/constants"
	"github.com/quantumauth-io/quantum-auth-client/internal/contracts/bindings/go/qaerc20"
)

func (m *Manager) FetchAsset(ctx context.Context, network string, addr string) (Asset, error) {
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

	if m.clients == nil {
		return Asset{}, fmt.Errorf("eth client is nil")
	}

	// --- STARTUP-SAFE NETWORK SWITCH ---
	// NOTE: This mutates the shared client's active network/backend,
	// so only do this during startup (single-threaded), not in concurrent handlers.
	prevNet := m.clients.ActiveNetwork()
	prevRPC := m.clients.ActiveRPC()

	restore := func() {
		// best-effort restore
		_ = m.clients.UseNetwork(prevNet)
		if prevRPC != "" {
			_ = m.clients.UseRPC(prevRPC)
		}
		_ = m.clients.EnsureBackend(ctx)
	}

	// switch to target network
	if err := m.clients.UseNetwork(network); err != nil {
		return Asset{}, fmt.Errorf("use network %q: %w", network, err)
	}
	// keep previous rpc name if possible (best effort); otherwise UseNetwork chose first available
	if prevRPC != "" {
		_ = m.clients.UseRPC(prevRPC)
	}
	if err := m.clients.EnsureBackend(ctx); err != nil {
		restore()
		return Asset{}, fmt.Errorf("ensure backend for %q: %w", network, err)
	}

	backend := m.clients.Backend()
	if backend == nil {
		restore()
		return Asset{}, fmt.Errorf("no backend for network %q", network)
	}

	contractAddr := common.HexToAddress(a)
	call := &bind.CallOpts{Context: ctx}

	token, err := qaerc20.NewQAERC20(contractAddr, backend)
	if err != nil {
		restore()
		return Asset{}, fmt.Errorf("qaerc20 bind: %w", err)
	}

	sym, err := token.Symbol(call)
	if err != nil {
		restore()
		return Asset{}, fmt.Errorf("symbol: %w", err)
	}

	dec, err := token.Decimals(call)
	if err != nil {
		restore()
		return Asset{}, fmt.Errorf("decimals: %w", err)
	}

	name := ""
	if n, err := token.Name(call); err == nil {
		name = n
	}

	// (optional) sanity check for weird tokens
	if dec > 255 {
		restore()
		return Asset{}, fmt.Errorf("decimals out of range: %d", dec)
	}

	out := Asset{
		Address:  contractAddr.Hex(),
		Symbol:   sym,
		Decimals: uint8(dec),
		Name:     name,
	}

	// restore original active network/rpc/backend
	restore()

	return out, nil
}
