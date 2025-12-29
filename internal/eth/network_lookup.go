package eth

import (
	"fmt"
	"math/big"
	"strings"

	utilsEth "github.com/quantumauth-io/quantum-go-utils/ethrpc"
)

// NetworkNameForChainIDHex finds a configured network by chain id.
func NetworkNameForChainIDHex(cfg *utilsEth.MultiConfig, chainIDHex string) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("eth: nil config")
	}

	want := strings.ToLower(utilsEth.NormalizeHex0x(strings.TrimSpace(chainIDHex)))
	if want == "" {
		return "", fmt.Errorf("eth: missing chain id")
	}

	for name, n := range cfg.Networks {
		if n.ChainIDHex != "" && strings.ToLower(utilsEth.NormalizeHex0x(n.ChainIDHex)) == want {
			return name, nil
		}
		if n.ChainID != 0 {
			if strings.ToLower(utilsEth.BigToHexQuantity(new(big.Int).SetUint64(n.ChainID))) == want {
				return name, nil
			}
		}
	}
	return "", fmt.Errorf("eth: chain %s not configured", want)
}
