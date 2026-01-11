package setup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/quantumauth-io/quantum-auth-client/internal/assets"
	"github.com/quantumauth-io/quantum-auth-client/internal/networks"

	clientconfig "github.com/quantumauth-io/quantum-auth-client/cmd/quantum-auth-client/config"
	"github.com/quantumauth-io/quantum-auth-client/internal/eth"
	"github.com/quantumauth-io/quantum-auth-client/internal/ethwallet/contractwallet"
	"github.com/quantumauth-io/quantum-auth-client/internal/ethwallet/ethdevice"
	"github.com/quantumauth-io/quantum-auth-client/internal/ethwallet/userwallet"
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

type TPMKeyRef struct {
	HandleHex string `json:"handle_hex"`
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
	err = cfg.NormalizeDefaultAssets()
	if err != nil {
		log.Error("normailze default assets", "error", err)
		return err
	}

	if err := cfg.InjectInfuraKeyFromEnv(); err != nil {
		return err
	}
	if err := cfg.ApplyServerURLFromEnv(); err != nil {
		return err
	}

	// ---- TPM runtime (handles read/pick/persist internally)
	tpmClient, err := clienttpm.NewRuntimeTPM(ctx)
	if err != nil {
		log.Error("TPM init failed", "error", err)
		return err
	}
	defer func() {
		if cerr := tpmClient.Close(); cerr != nil {
			log.Error("TPM close failed", "error", cerr)
		}
	}()

	log.Info("TPM ready", "handle", fmt.Sprintf("0x%x", uint32(tpmClient.Handle())))
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

	// ---- Assets Manager
	assetsManager, err := assets.NewManager(ethClient)
	if err != nil {
		return err
	}

	for netKey, addrs := range cfg.DefaultAssets.Network {
		if err := assetsManager.EnsureStoreForNetwork(ctx, netKey, addrs); err != nil {
			return err
		}
	}

	// ---- Networks Manager
	networksManager, err := networks.NewManager()
	if err != nil {
		return err
	}

	defaults := networksFromConfig(cfg)

	// This will create networks.json on first run and merge-add new config networks later.
	if err := networksManager.EnsureFromConfig(ctx, defaults); err != nil {
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

	sealer := tpmdevice.NewSealer("")
	dwStore, err := ethdevice.NewStore(sealer)
	if err != nil {
		return err
	}
	deviceW, err := dwStore.Ensure(ctx)
	if err != nil {
		return err
	}

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
		contractCfg = nil
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
	_, err = onchain.BalanceOf(ctx, deviceW.Address())
	if err != nil {
		return err
	}
	log.Info("User wallet", "address", userW.Address().Hex(), "balance", ubalance.String())

	// ---- HTTP server
	srv, err := clienthttp.NewServer(ctx, qaClient, authClient, allowedOrigins, ethClient, onchain, cfg, assetsManager, cwStore, networksManager)
	if err != nil {
		return err
	}

	// contract deployer service
	deployer, err := contractwallet.NewContractDeployer(contractwallet.DeployerConfig{
		EthClient: ethClient,
		Store:     cwStore,
		Wallets:   clienthttp.StaticWalletProvider{User: userW, Device: deviceW},
		// leave nil; server will attach
	})
	if err != nil {
		return err
	}

	srv.AttachDeployer(deployer)

	listenAddr := net.JoinHostPort(cfg.ClientSettings.LocalHost, cfg.ClientSettings.Port)
	server := &http.Server{Addr: listenAddr, Handler: srv}

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
