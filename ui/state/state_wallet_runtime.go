package state

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/quantumauth-io/quantum-auth-client/cmd/quantum-auth-client/config"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/assets"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/contractwallet"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/wtypes"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/helpers"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/networks"
)

type ErrWalletRuntimeIncomplete string

type walletRuntime struct {
	chains       *chains.QAChainService
	contracts    *contractwallet.Store
	userWallet   wtypes.Wallet
	deviceWallet wtypes.TPMBackedWallet
	onchain      *contractwallet.Runtime

	assetsOnce sync.Once
	assets     *assets.Manager
	assetsErr  error

	networksOnce sync.Once
	networks     *networks.Manager
	networksErr  error

	deployer  *contractwallet.ContractDeployer
	closeOnce sync.Once
}

func (r *walletRuntime) Close(ctx context.Context) {
	_ = ctx
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		if r.chains != nil {
			_ = r.chains.Close()
			r.chains = nil
		}

		// nil everything
		r.contracts = nil
		r.userWallet = nil
		r.deviceWallet = nil
		r.onchain = nil
		r.deployer = nil

		r.assets = nil
		r.assetsErr = nil

		r.networks = nil
		r.networksErr = nil
	})
}

func (s *AppState) WalletSnapshot() (user wtypes.Wallet, device wtypes.TPMBackedWallet, aa *contractwallet.Runtime,
	deployer *contractwallet.ContractDeployer, store *contractwallet.Store, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.wrt == nil {
		return nil, nil, nil, nil, nil, false
	}

	return s.wrt.userWallet, s.wrt.deviceWallet, s.wrt.onchain, s.wrt.deployer, s.wrt.contracts, true
}

func (r *walletRuntime) assetsManager() (*assets.Manager, error) {
	r.assetsOnce.Do(func() {
		if r.chains == nil {
			r.assetsErr = ErrWalletRuntimeIncomplete("chains missing")
			return
		}
		am, err := assets.NewManager(r.chains)
		if err != nil {
			r.assetsErr = err
			return
		}
		r.assets = am
	})
	return r.assets, r.assetsErr
}

func (r *walletRuntime) networksManager(ctx context.Context, cfg *config.Config) (*networks.Manager, error) {
	r.networksOnce.Do(func() {
		nm, err := networks.NewManager()
		if err != nil {
			r.networksErr = err
			return
		}

		// Bootstrap defaults from config without overwriting user edits.
		// This only writes file if needed.
		if cfg != nil {
			defaultNetworks := helpers.NetworksMapFromConfig(cfg)
			if err := nm.EnsureFromConfig(ctx, defaultNetworks); err != nil {
				r.networksErr = err
				return
			}
		}

		r.networks = nm
	})
	return r.networks, r.networksErr
}

func (r *walletRuntime) PickWallet(from common.Address) (wtypes.Wallet, error) {
	if r == nil || r.userWallet == nil || r.deviceWallet == nil {
		return nil, errors.New("wallet runtime not initialized")
	}

	if addr := r.userWallet.Address(); addr == from {
		return r.userWallet, nil
	}

	if addr := r.deviceWallet.Address(); addr == from {
		return r.deviceWallet, nil
	}

	return nil, fmt.Errorf("unauthorized wallet address: %s", from.Hex())
}

func (r *walletRuntime) SignUserOpHash(ctx context.Context, userOpHash32 []byte) ([]byte, error) {
	if r == nil || r.deviceWallet == nil {
		return nil, errors.New("wallet runtime not initialized")
	}
	if len(userOpHash32) != 32 {
		return nil, fmt.Errorf("invalid userOpHash length: got %d want 32", len(userOpHash32))
	}

	sig, err := r.deviceWallet.SignHash(ctx, userOpHash32)
	if err != nil {
		return nil, err
	}

	return normalizeSigV(sig), nil
}

func (r *walletRuntime) RelayerAuth(ctx context.Context) (*bind.TransactOpts, common.Address, error) {
	if r == nil || r.chains == nil || r.deviceWallet == nil {
		return nil, common.Address{}, errors.New("wallet runtime not initialized")
	}

	clients, err := r.chains.Active()
	if err != nil || clients == nil || clients.HTTP == nil {
		return nil, common.Address{}, fmt.Errorf("no active http client: %w", err)
	}

	chainID, err := clients.HTTP.ChainID(ctx)
	if err != nil {
		return nil, common.Address{}, fmt.Errorf("chain id: %w", err)
	}
	if chainID == nil {
		return nil, common.Address{}, errors.New("missing chain id")
	}

	relayer := r.deviceWallet
	from := relayer.Address()

	signer := types.LatestSignerForChainID(chainID)

	auth := &bind.TransactOpts{
		From: from,
		Signer: func(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if addr != from {
				return nil, fmt.Errorf("signer mismatch: want %s got %s", from.Hex(), addr.Hex())
			}

			h := signer.Hash(tx)
			sig, err := relayer.SignHash(ctx, h.Bytes())
			if err != nil {
				return nil, err
			}
			sig = normalizeSigV(sig)

			return tx.WithSignature(signer, sig)
		},
	}

	beneficiary := from

	return auth, beneficiary, nil
}

func (e ErrWalletRuntimeIncomplete) Error() string { return "wallet runtime incomplete: " + string(e) }

func normalizeSigV(sig []byte) []byte {
	if len(sig) != 65 {
		return sig
	}
	v := sig[64]
	if v == 27 || v == 28 {
		out := make([]byte, 65)
		copy(out, sig)
		out[64] = v - 27
		return out
	}
	return sig
}
