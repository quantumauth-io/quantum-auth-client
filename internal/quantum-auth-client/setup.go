// setup.go
package quantum_auth_client

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/quantumauth-io/quantum-auth-client/cmd/quantum-auth-client/config"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/assets"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/contractwallet"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/ethdevice"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/userwallet"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/helpers"
	clienthttp "github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/http"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/login"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/networks"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/services"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/tpm"
	"github.com/quantumauth-io/quantum-go-utils/log"
	"github.com/quantumauth-io/quantum-go-utils/qa_evm"
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

// evmHTTPClient is the minimal surface we need from the HTTP client.
type evmHTTPClient interface {
	ChainID(ctx context.Context) (*big.Int, error)
	CodeAt(ctx context.Context, contract common.Address, blockNumber *big.Int) ([]byte, error)
}

func Run(ctx context.Context, build BuildInfo) error {
	log.Info("quantum-auth-client",
		"version", build.Version,
		"commit", build.Commit,
		"build_date", build.BuildDate,
	)

	// ---- Config
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	cfg.Networks.Normalize()
	if err := cfg.NormalizeDefaultAssets(); err != nil {
		log.Error("normalize default assets", "error", err)
		return err
	}
	if err := cfg.ApplyServerURLFromEnv(); err != nil {
		return err
	}

	// ---- TPM runtime
	tpmClient, err := tpm.NewRuntimeTPM(ctx)
	if err != nil {
		log.Error("TPM init failed", "error", err)
		return err
	}
	defer func() {
		if closeErr := tpmClient.Close(); closeErr != nil {
			log.Error("TPM close failed", "error", closeErr)
		}
	}()

	// ---- QA client
	qaClient, err := services.NewClient(cfg.ClientSettings.ServerURL, tpmClient)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := qaClient.Close(); closeErr != nil {
			log.Error("failed to close QA client", "error", closeErr)
		}
	}()

	// ---- Auth service
	authClient := login.NewQAClientLoginService(ctx, qaClient, cfg.ClientSettings.Email, cfg.ClientSettings.DeviceLabel)
	defer authClient.Clear()

	// ---- Preflight hook (runs before first-time register)
	authClient.SetPreflight(func(ctx context.Context, in login.PreflightInputs) error {
		// 0) Ensure we can bind the HTTP port
		listenAddr := net.JoinHostPort(cfg.ClientSettings.LocalHost, cfg.ClientSettings.Port)
		listener, err := net.Listen("tcp", listenAddr)
		if err != nil {
			return fmt.Errorf("cannot bind %s: %w", listenAddr, err)
		}
		_ = listener.Close()

		// 1) Inject Infura key into config (fills RPC URLs/WSS)
		if err := cfg.InjectInfuraKey(in.InfuraKey); err != nil {
			return err
		}

		// 2) Create chain service and dial default chain
		chainService, err := newChainServiceFromConfig(cfg)
		if err != nil {
			return err
		}

		// 3) Validate EntryPoint is deployed on active network
		entryPointHex, err := activeEntryPointFromConfig(cfg)
		if err != nil {
			return err
		}
		if err := verifyEntryPointDeployed(ctx, chainService, entryPointHex); err != nil {
			return err
		}

		// 4) Validate wallet stores can initialize with chosen password
		userWalletStore, err := userwallet.NewStore()
		if err != nil {
			return err
		}
		if _, err := userWalletStore.Ensure(in.Password); err != nil {
			return err
		}

		sealer := tpmdevice.NewSealer("")
		deviceWalletStore, err := ethdevice.NewStore(sealer)
		if err != nil {
			return err
		}
		if _, err := deviceWalletStore.Ensure(ctx); err != nil {
			return err
		}

		return nil
	})

	// ---- Ensure login (first-time path will preflight)
	state, password, err := authClient.EnsureLogin()
	if err != nil {
		return err
	}
	defer helpers.ZeroBytes(password)

	// Inject Infura key (again is fine; keeps main path consistent)
	if err := cfg.InjectInfuraKey(state.InfuraAPIKey); err != nil {
		return err
	}

	// ---- Chain service (dial once and reuse)
	chainService, err := newChainServiceFromConfig(cfg)
	if err != nil {
		return err
	}

	setupOK := false
	defer func() {
		if !setupOK {
			_ = chainService.Close()
		}
	}()

	chainClients, err := chainService.Active()
	if err != nil {
		return err
	}

	httpEVMClient, err := asEVMHTTPClient(chainClients.HTTP)
	if err != nil {
		return err
	}

	// ---- Validate EntryPoint (once)
	entryPointHex, err := activeEntryPointFromConfig(cfg)
	if err != nil {
		return err
	}
	if err := verifyEntryPointDeployed(ctx, chainService, entryPointHex); err != nil {
		return err
	}

	// ---- Assets Manager
	//
	// NOTE: This assumes your assets manager can work with qa_evm.BlockchainClient (HTTP).
	// If it currently expects a custom eth wrapper, update it to accept qa_evm.BlockchainClient
	// (or add an adapter that implements the needed calls).
	assetsManager, err := assets.NewManager(chainService)
	if err != nil {
		return err
	}

	for networkKey, addresses := range cfg.DefaultAssets.Network {
		if err := assetsManager.EnsureStoreForNetwork(ctx, networkKey, addresses); err != nil {
			return err
		}
	}

	// ---- Networks Manager
	networksManager, err := networks.NewManager()
	if err != nil {
		return err
	}
	defaultNetworks := helpers.NetworksMapFromConfig(cfg)
	if err := networksManager.EnsureFromConfig(ctx, defaultNetworks); err != nil {
		return err
	}

	// ---- Wallets
	userWalletStore, err := userwallet.NewStore()
	if err != nil {
		return err
	}
	userWallet, err := userWalletStore.Ensure(password)
	if err != nil {
		return err
	}

	sealer := tpmdevice.NewSealer("")
	deviceWalletStore, err := ethdevice.NewStore(sealer)
	if err != nil {
		return err
	}
	deviceWallet, err := deviceWalletStore.Ensure(ctx)
	if err != nil {
		return err
	}

	// ---- Contract store + chain id
	contractWalletStore, err := contractwallet.NewStore()
	if err != nil {
		return err
	}

	chainIDBig, err := httpEVMClient.ChainID(ctx)
	if err != nil {
		return err
	}
	chainID := chainIDBig.Uint64()

	contractCfg, err := contractWalletStore.LoadForChain(chainID)
	if errors.Is(err, contractwallet.ErrContractNotConfigured) {
		contractCfg = nil
	} else if err != nil {
		return err
	}

	onchainRuntime := &contractwallet.Runtime{
		// NOTE: Update Runtime.Eth type to qa_evm.BlockchainClient if it isn't already.
		ChainService: chainService,
		User:         userWallet,
		Device:       deviceWallet,
		Contract:     contractCfg,
	}

	// ---- HTTP server
	serverHandler, err := clienthttp.NewServer(
		ctx,
		qaClient,
		authClient,
		allowedOrigins,
		chainService,
		onchainRuntime,
		cfg,
		assetsManager,
		contractWalletStore,
		networksManager,
	)
	if err != nil {
		return err
	}

	// ---- Contract deployer service
	deployer, err := contractwallet.NewContractDeployer(contractwallet.DeployerConfig{
		Chains:  chainService,
		Store:   contractWalletStore,
		Wallets: clienthttp.StaticWalletProvider{User: userWallet, Device: deviceWallet},
	})
	if err != nil {
		return err
	}
	serverHandler.AttachDeployer(deployer)

	listenAddr := net.JoinHostPort(cfg.ClientSettings.LocalHost, cfg.ClientSettings.Port)
	httpServer := &http.Server{Addr: listenAddr, Handler: serverHandler}

	go func() {
		if serveErr := httpServer.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			log.Error("HTTP server error", "error", serveErr)
		}
	}()

	setupOK = true

	// ---- graceful shutdown
	<-ctx.Done()
	log.Info("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
		log.Error("QA Client shutdown failed", "error", shutdownErr)
	} else {
		log.Info("QA Client gracefully stopped")
	}

	return nil
}

func newChainServiceFromConfig(cfg *config.Config) (*chains.QAChainService, error) {
	return chains.NewQAChainService(chains.ChainConfig{
		Chains:               cfg.Networks,
		DefaultActiveNetwork: cfg.Networks.ActiveNetwork,
		PreferredRPCName:     cfg.Networks.ActiveRPC,
	})
}

func activeEntryPointFromConfig(cfg *config.Config) (string, error) {
	activeNetworkName := cfg.Networks.ActiveNetwork
	networkCfg, ok := cfg.Networks.Networks[activeNetworkName]
	if !ok {
		return "", fmt.Errorf("active network %q not found in config", activeNetworkName)
	}
	if networkCfg.EntryPoint == "" {
		return "", fmt.Errorf("missing entryPoint for network %q", activeNetworkName)
	}
	if !common.IsHexAddress(networkCfg.EntryPoint) {
		return "", fmt.Errorf("invalid entryPoint %q for network %q", networkCfg.EntryPoint, activeNetworkName)
	}
	return networkCfg.EntryPoint, nil
}

func verifyEntryPointDeployed(ctx context.Context, chainService *chains.QAChainService, entryPointHex string) error {
	chainClients, err := chainService.Active()
	if err != nil {
		return err
	}

	httpEVMClient, err := asEVMHTTPClient(chainClients.HTTP)
	if err != nil {
		return err
	}

	entryPoint := common.HexToAddress(entryPointHex)
	code, err := httpEVMClient.CodeAt(ctx, entryPoint, nil) // latest
	if err != nil {
		return err
	}
	if len(code) == 0 {
		return fmt.Errorf("entryPoint not deployed on this chain: %s", entryPoint.Hex())
	}
	return nil
}

func asEVMHTTPClient(client qa_evm.BlockchainClient) (evmHTTPClient, error) {
	httpClient, ok := client.(evmHTTPClient)
	if !ok {
		return nil, fmt.Errorf("http client does not support ChainID/CodeAt (got %T)", client)
	}
	return httpClient, nil
}
