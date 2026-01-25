package chains

import (
	"context"
	"fmt"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/quantumauth-io/quantum-go-utils/evm"
	"github.com/quantumauth-io/quantum-go-utils/retry"
)

type BlockchainClientWithCache struct {
	latestHeader             atomic.Pointer[types.Header]
	timeReceivedLatestHeader atomic.Pointer[time.Time]
	evm.BlockchainClient
}

func NewBlockchainClientWithCache(ctx context.Context, url string,
	durationBetweenGetLatestHeaderRequestsMilliseconds int) (*BlockchainClientWithCache, error) {
	eclient, err := ethclient.DialContext(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to blockchain at %s", url)
	}

	cc := &BlockchainClientWithCache{
		BlockchainClient: eclient,
	}

	err = cc.getLatestHeaderFromChain(ctx)
	if err != nil {
		return nil, err
	}

	go maintainLatestHeaderFromChain(ctx, cc, durationBetweenGetLatestHeaderRequestsMilliseconds)

	return cc, nil
}

func maintainLatestHeaderFromChain(ctx context.Context, cc *BlockchainClientWithCache,
	durationBetweenGetLatestHeaderRequestsMilliseconds int) {
	duration := time.Duration(durationBetweenGetLatestHeaderRequestsMilliseconds) * time.Millisecond
	cfg := retry.DefaultConfig()
	cfg.MaxDelayBeforeRetrying = duration
	cfg.InitialDelayBeforeRetrying = duration / 10

	timer := time.NewTimer(duration)
	defer timer.Stop()
	numCallsToChain := 0
	for {
		timer.Reset(duration)
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			_, _ = retry.Retry(ctx, cfg,
				func(ctx context.Context) ([]interface{}, error) {
					numCallsToChain++
					return nil, cc.getLatestHeaderFromChain(ctx)
				},
				nil,
				"get latest header from chain")
		}
	}
}

func (b *BlockchainClientWithCache) getLatestHeaderFromChain(ctx context.Context) error {
	header, err := b.BlockchainClient.HeaderByNumber(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to get latest HeaderByNumber from chain %w", err)
	}
	end := time.Now().UTC()
	b.latestHeader.Store(header)
	b.timeReceivedLatestHeader.Store(&end)
	return nil
}

func (b *BlockchainClientWithCache) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	if number == nil {
		return b.latestHeader.Load(), nil
	} else {
		return b.BlockchainClient.HeaderByNumber(ctx, number)
	}

}
