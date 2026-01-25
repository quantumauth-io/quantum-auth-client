package http

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/txsender"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/contractwallet"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/wtypes"
	"github.com/quantumauth-io/quantum-go-utils/evm"
)

var (
	_ txsender.WalletPicker        = (*Web3Auth)(nil)
	_ txsender.UserOpSigner        = (*Web3Auth)(nil)
	_ txsender.RelayerAuthProvider = (*Web3Auth)(nil)
)

const (
	ModeNormal uint8 = 0
)

// Web3Auth implements all Web3 signing & relayer concerns.
// It is intentionally NOT tied to Server.
type Web3Auth struct {
	chains  *chains.QAChainService
	onChain *contractwallet.Runtime
}

type OnChainView struct {
	User   wtypes.Wallet
	Device wtypes.TPMBackedWallet

	// ContractAddress is used by txsender to decide AA vs EOA
	ContractAddress func() (common.Address, error)
}

// NewWeb3Auth constructs a Web3Auth bound to a Web3 snapshot.
func NewWeb3Auth(
	chains *chains.QAChainService,
	onChain *contractwallet.Runtime,
) *Web3Auth {
	return &Web3Auth{
		chains:  chains,
		onChain: onChain,
	}
}

func (a *Web3Auth) PickWallet(from common.Address) (wtypes.Wallet, error) {
	if a == nil || a.onChain == nil || a.onChain.User == nil || a.onChain.Device == nil {
		return nil, fmt.Errorf("onchain runtime not initialized")
	}
	if from == a.onChain.User.Address() {
		return a.onChain.User, nil
	}
	if from == a.onChain.Device.Address() {
		return a.onChain.Device, nil
	}
	return nil, fmt.Errorf("from address not controlled by this wallet")
}

func (a *Web3Auth) RelayerAuth(ctx context.Context) (*bind.TransactOpts, common.Address, error) {
	if a == nil || a.onChain == nil || a.onChain.User == nil {
		return nil, common.Address{}, fmt.Errorf("onchain runtime not initialized")
	}
	if a.chains == nil {
		return nil, common.Address{}, fmt.Errorf("chain service not initialized")
	}

	privKey, err := a.onChain.User.ExportPrivateKey(ctx)
	if err != nil {
		return nil, common.Address{}, err
	}
	if privKey == nil {
		return nil, common.Address{}, fmt.Errorf("exported private key is nil")
	}

	from := crypto.PubkeyToAddress(privKey.PublicKey)

	clients, err := a.chains.Active()
	if err != nil {
		return nil, common.Address{}, err
	}
	if clients == nil || clients.HTTP == nil {
		return nil, common.Address{}, fmt.Errorf("no active http client")
	}

	chainID, err := clients.HTTP.ChainID(ctx)
	if err != nil {
		return nil, common.Address{}, err
	}
	if chainID == nil {
		return nil, common.Address{}, fmt.Errorf("missing chain id")
	}

	auth := &bind.TransactOpts{
		From:    from,
		Context: ctx,
		Signer: func(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if addr != from {
				return nil, fmt.Errorf("unauthorized signer: %s", addr.Hex())
			}
			return types.SignTx(tx, types.LatestSignerForChainID(chainID), privKey)
		},
	}

	return auth, from, nil
}

func (a *Web3Auth) SignUserOpHash(ctx context.Context, userOpHash []byte) ([]byte, error) {
	if len(userOpHash) != 32 {
		return nil, fmt.Errorf("userOpHash must be 32 bytes")
	}
	if a == nil || a.onChain == nil || a.onChain.User == nil || a.onChain.Device == nil {
		return nil, fmt.Errorf("onchain runtime not initialized")
	}

	// TPM signs RAW userOpHash
	sigTPM, err := a.onChain.Device.SignHash(ctx, userOpHash)
	if err != nil {
		return nil, fmt.Errorf("tpm sign failed: %w", err)
	}

	// User EOA signs ETH-SIGNED hash(userOpHash)
	ethHash := ethSignedHash(userOpHash)

	sigEOA1, err := a.onChain.User.SignHash(ctx, ethHash)
	if err != nil {
		return nil, fmt.Errorf("eoa sign failed: %w", err)
	}

	// Normalize V to 27/28 if needed
	if len(sigEOA1) == 65 && sigEOA1[64] < 27 {
		sigEOA1[64] += 27
	}

	return packQuantumAuthSignature(ModeNormal, sigEOA1, nil, sigTPM)
}

func (a *Web3Auth) GetBalanceWeiDecimal(
	ctx context.Context,
	eth evm.BlockchainClient,
	addr common.Address,
) (string, error) {
	if addr == (common.Address{}) {
		return "0", nil
	}
	if eth == nil {
		return "", fmt.Errorf("eth client not initialized")
	}

	wei, err := eth.BalanceAt(ctx, addr, nil)
	if err != nil {
		return "", err
	}
	if wei == nil {
		return "0", nil
	}

	return new(big.Int).Set(wei).String(), nil
}

func ethSignedHash(h []byte) []byte {
	prefix := []byte("\x19Ethereum Signed Message:\n32")
	return crypto.Keccak256(prefix, h)
}

func packQuantumAuthSignature(
	mode uint8,
	sigEOA1 []byte,
	sigEOA2 []byte,
	sigTPM []byte,
) ([]byte, error) {

	args := abi.Arguments{
		{Type: abi.Type{T: abi.UintTy, Size: 8}}, // uint8 mode
		{Type: abi.Type{T: abi.BytesTy}},         // eoa1
		{Type: abi.Type{T: abi.BytesTy}},         // eoa2
		{Type: abi.Type{T: abi.BytesTy}},         // tpm
	}

	if sigEOA2 == nil {
		sigEOA2 = []byte{}
	}

	return args.Pack(
		mode,
		sigEOA1,
		sigEOA2,
		sigTPM,
	)
}
