package http

import (
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/txsender"
	"github.com/quantumauth-io/quantum-go-utils/evm"
)

type web3TxSenderFactory struct {
	snap Web3Snapshot
}

func (f web3TxSenderFactory) NewTxSender(httpEth evm.BlockchainClient) *txsender.Sender {
	// Auth must implement Pick + SignUserOpHash + RelayerAuth
	return &txsender.Sender{
		Eth:        httpEth,
		Networks:   chains.TxSenderNetworkResolver{Svc: f.snap.Chains},
		OnChain:    f.snap.OnChain,
		Pick:       f.snap.Auth,
		SignUserOp: f.snap.Auth,
		Relayer:    f.snap.Auth,
	}
}
