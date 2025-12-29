package setup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"

	clientconfig "github.com/quantumauth-io/quantum-auth-client/cmd/quantum-auth-client/config"
	"github.com/quantumauth-io/quantum-auth-client/internal/eth"
	"github.com/quantumauth-io/quantum-auth-client/internal/ethwallet/contractwallet"
	"github.com/quantumauth-io/quantum-auth-client/internal/ethwallet/ethdevice"
	"github.com/quantumauth-io/quantum-auth-client/internal/ethwallet/userwallet"
	"github.com/quantumauth-io/quantum-auth-client/internal/ethwallet/wtypes"
	clienthttp "github.com/quantumauth-io/quantum-auth-client/internal/http"
	"github.com/quantumauth-io/quantum-auth-client/internal/login"
	"github.com/quantumauth-io/quantum-auth-client/internal/qa"
	clienttpm "github.com/quantumauth-io/quantum-auth-client/internal/tpm"

	utilsEth "github.com/quantumauth-io/quantum-go-utils/ethrpc"
	"github.com/quantumauth-io/quantum-go-utils/log"
	"github.com/quantumauth-io/quantum-go-utils/tpmdevice"
)

var allowedOrigins = []string{
	"http://127.0.0.1:6137",
	"http://localhost:6137",
}

type BuildInfo struct {
	Version   string
	Commit    string
	BuildDate string
}

func Run(ctx context.Context, build BuildInfo) error {
	log.Info("quantum-auth-client",
		"version", build.Version,
		"commit", build.Commit,
		"build_date", build.BuildDate,
	)

	// ---- Config
	cfg, err := clientconfig.Load()
	if err != nil {
		return err
	}
	cfg.EthNetworks.Normalize()

	if err := cfg.InjectInfuraKeyFromEnv(); err != nil {
		return err
	}
	if err := cfg.ApplyServerURLFromEnv(); err != nil {
		return err
	}

	// ---- TPM runtime
	tpmClient, err := clienttpm.NewRuntimeTPM(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := tpmClient.Close(); cerr != nil {
			log.Error("TPM close failed", "error", cerr)
		}
	}()

	// ---- QA client
	qaClient, err := qa.NewClient(cfg.ClientSettings.ServerURL, tpmClient)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := qaClient.Close(); cerr != nil {
			log.Error("failed to close QA client", "error", cerr)
		}
	}()

	// ---- Auth service
	authClient := login.NewQAClientLoginService(ctx, qaClient, cfg.ClientSettings.Email, cfg.ClientSettings.DeviceLabel)
	defer authClient.Clear()

	_, pwd, err := authClient.EnsureLogin()
	if err != nil {
		return err
	}
	defer login.Zero(pwd)

	// ---- ETH RPC client + select network/rpc
	ethClient, err := eth.NewFromConfig(ctx, cfg.EthNetworks)
	if err != nil {
		return err
	}
	if err := ethClient.UseNetwork("sepolia"); err != nil {
		return err
	}
	if err := ethClient.UseRPC("Infura"); err != nil {
		return err
	}
	// UseNetwork/UseRPC do not dial in go-utils; EnsureBackend does.
	if err := ethClient.EnsureBackend(ctx); err != nil {
		return err
	}

	// ---- Validate EntryPoint from config (once)
	activeNetName := cfg.EthNetworks.ActiveNetwork
	netCfg, ok := cfg.EthNetworks.Networks[activeNetName]
	if !ok {
		return fmt.Errorf("active network %q not found in config", activeNetName)
	}
	if netCfg.EntryPoint == "" {
		return fmt.Errorf("missing entryPoint for network %q", activeNetName)
	}
	if !common.IsHexAddress(netCfg.EntryPoint) {
		return fmt.Errorf("invalid entryPoint %q for network %q", netCfg.EntryPoint, activeNetName)
	}
	entryPoint := common.HexToAddress(netCfg.EntryPoint)

	log.Info("quantum-auth-client", "entryPoint", entryPoint)

	code, err := ethClient.GetCode(ctx, entryPoint.Hex(), utilsEth.BlockLatest)
	if err != nil {
		return err
	}
	if code == "0x" {
		return fmt.Errorf("entryPoint not deployed on this chain: %s", entryPoint.Hex())
	}

	// ---- Wallets
	uwStore, err := userwallet.NewStore()
	if err != nil {
		return err
	}
	userW, err := uwStore.Ensure(pwd)
	if err != nil {
		return err
	}

	log.Info("user wallet", "address", userW.Address())

	sealer := tpmdevice.NewSealer("") // owner auth usually ""
	dwStore, err := ethdevice.NewStore(sealer)
	if err != nil {
		return err
	}
	deviceW, err := dwStore.Ensure(ctx)
	if err != nil {
		return err
	}

	log.Info("device wallet", "address", deviceW.Address())

	// ---- Contract store + chain id
	cwStore, err := contractwallet.NewStore()
	if err != nil {
		return err
	}

	chainIDBig, err := ethClient.ChainID(ctx)
	if err != nil {
		return err
	}
	chainID := chainIDBig.Uint64()

	contractCfg, err := cwStore.LoadForChain(chainID)
	if errors.Is(err, contractwallet.ErrContractNotConfigured) {
		log.Warn("contract not configured", "path", cwStore.Path, "chain_id", chainID)

		deploy, perr := promptYesNo("No AA wallet contract found for this chain. Deploy TPMVerifier + QuantumAuthAccount now? (fund your wallet first) (y/N): ")
		if perr != nil {
			return perr
		}

		if deploy {
			// ---- Deploy TPMVerifier
			tpmVerifierAddr, tpmTx, derr := contractwallet.DeployTPMVerifierSecp256k1(ctx, ethClient, userW)
			if derr != nil {
				return derr
			}
			log.Info("TPMVerifier deployed", "address", tpmVerifierAddr.Hex(), "tx", tpmTx.Hex())

			// ---- TPM Key ID (must be [32]byte)
			// NOTE: this requires your device wallet type to implement wtypes.TPMBackedWallet.
			// If you can add TPMKeyID() directly on *ethdevice.DeviceWallet, then you can call deviceW.TPMKeyID() here.
			var deviceWalletIface wtypes.Wallet = deviceW
			tpmWallet, ok := deviceWalletIface.(wtypes.TPMBackedWallet)
			if !ok {
				return fmt.Errorf("device wallet is not TPM-backed (missing TPMKeyID())")
			}
			tpmKeyID := tpmWallet.TPMKeyID()

			// ---- Deploy QuantumAuthAccount
			// IMPORTANT: EOA2 should be a real recovery EOA (not the TPM device wallet) if you want recovery mode to work.
			params := contractwallet.AccountDeployParams{
				EntryPoint:  entryPoint,
				EOA1:        userW.Address(),
				EOA2:        deviceW.Address(),
				TPMVerifier: tpmVerifierAddr,
				TPMKeyID:    tpmKeyID,
			}

			accountAddr, deployTxHash, derr := contractwallet.DeployQuantumAuthAccount(ctx, ethClient, userW, params)
			if derr != nil {
				return derr
			}

			if err := cwStore.SaveForChain(contractwallet.Config{
				ChainID:     chainID,
				Address:     accountAddr.Hex(),
				EntryPoint:  entryPoint.Hex(),
				TPMVerifier: tpmVerifierAddr.Hex(),
			}); err != nil {
				return err
			}

			log.Info("QuantumAuthAccount deployed",
				"address", accountAddr.Hex(),
				"tx", deployTxHash.Hex(),
				"chain_id", chainID,
				"path", cwStore.Path,
			)

			contractCfg = &contractwallet.Config{ChainID: chainID, Address: accountAddr.Hex()}
		} else {
			contractCfg = nil
		}
	} else if err != nil {
		return err
	}

	onchain := &contractwallet.Runtime{
		Eth:      ethClient,
		User:     userW,
		Device:   deviceW,
		Contract: contractCfg,
	}

	ubalance, err := onchain.BalanceOf(ctx, userW.Address())
	if err != nil {
		return err
	}
	dbalance, err := onchain.BalanceOf(ctx, deviceW.Address())
	if err != nil {
		return err
	}
	log.Info("User wallet", "address", userW.Address().Hex(), "balance", ubalance.String())
	log.Info("Device wallet", "address", deviceW.Address().Hex(), "balance", dbalance.String())

	// ---- HTTP server
	handler, err := clienthttp.NewServer(ctx, qaClient, authClient, allowedOrigins, ethClient, onchain, cfg.EthNetworks)
	if err != nil {
		return err
	}

	listenAddr := net.JoinHostPort(cfg.ClientSettings.LocalHost, cfg.ClientSettings.Port)
	server := &http.Server{Addr: listenAddr, Handler: handler}

	go func() {
		if serr := server.ListenAndServe(); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			log.Error("HTTP server error", "error", serr)
		}
	}()

	// ---- graceful shutdown
	<-ctx.Done()
	log.Info("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if serr := server.Shutdown(shutdownCtx); serr != nil {
		log.Error("HTTP server shutdown failed", "error", serr)
	} else {
		log.Info("HTTP server gracefully stopped")
	}
	return nil
}
