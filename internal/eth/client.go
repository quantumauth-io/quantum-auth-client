package eth

import (
	"context"
	"fmt"

	utilsEth "github.com/quantumauth-io/quantum-go-utils/ethrpc"
)

func NewFromConfig(ctx context.Context, cfg *utilsEth.MultiConfig) (*utilsEth.Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("eth: nil config")
	}
	if len(cfg.Networks) == 0 {
		return nil, fmt.Errorf("eth: no networks configured")
	}
	return utilsEth.New(cfg)
}
