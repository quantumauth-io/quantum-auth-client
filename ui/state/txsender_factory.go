package state

import (
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/txsender"
	"github.com/quantumauth-io/quantum-go-utils/evm"
)

type txSenderFactory struct {
	wrt *walletRuntime
}

func (f *txSenderFactory) NewTxSender(httpEth evm.BlockchainClient) *txsender.Sender {
	return &txsender.Sender{
		Eth:        httpEth,
		Networks:   chains.TxSenderNetworkResolver{Svc: f.wrt.chains},
		OnChain:    f.wrt.onchain,
		Pick:       f.wrt,
		SignUserOp: f.wrt,
		Relayer:    f.wrt,
	}
}
