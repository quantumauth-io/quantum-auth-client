package http

import (
	"context"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/assets"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/contractwallet"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/txsender"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/walletsigner"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/networks"
	"github.com/quantumauth-io/quantum-go-utils/evm"
)

type Web3Snapshot struct {
	Chains       *chains.QAChainService
	OnChain      *contractwallet.Runtime
	CWStore      *contractwallet.Store
	Deployer     *contractwallet.ContractDeployer
	Assets       *assets.Manager
	Networks     *networks.Manager
	TxSender     TxSenderFactory
	WalletSigner *walletsigner.Service
	Auth         *Web3Auth
	RPC          *Web3RPC
}

type Web3Provider interface {
	SnapshotWeb3(ctx context.Context) (snap Web3Snapshot, ok bool, err error)
}

type TxSenderFactory interface {
	NewTxSender(httpEth evm.BlockchainClient) *txsender.Sender
}
