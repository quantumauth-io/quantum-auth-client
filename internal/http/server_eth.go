package http

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/quantumauth-io/quantum-auth-client/internal/eth"
	"github.com/quantumauth-io/quantum-auth-client/internal/ethwallet/contractwallet"
	utilsEth "github.com/quantumauth-io/quantum-go-utils/ethrpc"
)

func (s *Server) AttachDeployer(d *contractwallet.ContractDeployer) {
	if d == nil {
		return
	}
	d.SetSwitchChainFunc(s.switchChain)
	d.SetEntryPointResolver(s.entryPointForNetwork)
	s.deployer = d
}

func (s *Server) entryPointForNetwork(networkName string) (common.Address, error) {
	netCfg, ok := s.cfg.EthNetworks.Networks[networkName]
	if !ok {
		return common.Address{}, fmt.Errorf("network %q not found", networkName)
	}
	if strings.TrimSpace(netCfg.EntryPoint) == "" {
		return common.Address{}, fmt.Errorf("missing entryPoint for %q", networkName)
	}
	if !common.IsHexAddress(netCfg.EntryPoint) {
		return common.Address{}, fmt.Errorf("invalid entryPoint %q for %q", netCfg.EntryPoint, networkName)
	}
	return common.HexToAddress(netCfg.EntryPoint), nil
}

func (s *Server) switchChain(ctx context.Context, chainIDHex string) (string, error) {
	want := utilsEth.NormalizeHex0x(strings.TrimSpace(chainIDHex))
	if want == "" {
		return "", fmt.Errorf("missing chainIdHex")
	}

	networkName, err := eth.NetworkNameForChainIDHex(s.cfg.EthNetworks, want)
	if err != nil {
		return "", err
	}

	if err := s.ethClient.UseNetwork(networkName); err != nil {
		return "", err
	}
	if err := s.ethClient.UseRPC("Infura"); err != nil {
		return "", err
	}
	if err := s.ethClient.EnsureBackend(ctx); err != nil {
		return "", err
	}

	// keep runtime aligned
	if s.onChain != nil && s.cwStore != nil {
		_ = s.onChain.LoadContractForCurrentChain(ctx, s.cwStore)
	}

	return networkName, nil
}

func (s *Server) getBalanceWeiDecimal(ctx context.Context, addr common.Address) (string, error) {
	if addr == (common.Address{}) {
		return "0", nil
	}
	if s == nil || s.ethClient == nil {
		return "", fmt.Errorf("eth client not initialized")
	}

	wei, err := s.ethClient.GetBalance(ctx, addr.String(), utilsEth.BlockLatest)
	if err != nil {

		return "", err
	}
	if wei == nil {
		return "0", nil
	}

	return new(big.Int).Set(wei).String(), nil
}
