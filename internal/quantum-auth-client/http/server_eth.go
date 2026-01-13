package http

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/contractwallet"
)

func (s *Server) AttachDeployer(deployer *contractwallet.ContractDeployer) {
	if deployer == nil {
		return
	}
	deployer.SetEntryPointResolver(s.entryPointForNetwork)
	s.deployer = deployer
}

func (s *Server) entryPointForNetwork(networkName string) (common.Address, error) {
	netCfg, ok := s.cfg.Networks.Networks[networkName]
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

func (s *Server) getBalanceWeiDecimal(ctx context.Context, addr common.Address) (string, error) {
	activeChain, err := s.activeHTTP(ctx)
	if err != nil {
		return "", err
	}

	if addr == (common.Address{}) {
		return "0", nil
	}
	if s == nil || activeChain == nil {
		return "", fmt.Errorf("eth client not initialized")
	}

	wei, err := activeChain.BalanceAt(ctx, addr, nil)
	if err != nil {

		return "", err
	}
	if wei == nil {
		return "0", nil
	}

	return new(big.Int).Set(wei).String(), nil
}
