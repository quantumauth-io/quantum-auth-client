package state

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/contractwallet"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/devicewallet"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/userwallet"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/wtypes"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/helpers"
	clienthttp "github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/http"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/runtime"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/services"
	"github.com/quantumauth-io/quantum-auth-client/ui/i18n"
	"github.com/quantumauth-io/quantum-go-utils/cryptoctx"
	"github.com/quantumauth-io/quantum-go-utils/tpmdevice"
)

var _ = time.Now

type AppStateConfig struct {
	Now func() time.Time
}

type AppState struct {
	mu        sync.Mutex
	wrtInitMu sync.Mutex
	Log       *UILogger
	password  string

	// Long-lived runtime objects
	crypto cryptoctx.Runtime

	// split runtimes
	wrt *walletRuntime
	srt *serverRuntime
	drt *devKeysRuntime

	// i18n
	tr *i18n.Translator

	now func() time.Time

	// Persisted (vault-backed)
	GUISettings GUISettings
	payload     *VaultPayload
}

func NewAppState(cfg AppStateConfig) *AppState {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &AppState{
		Log: NewUILogger(700),
		now: now,
	}
}

func (s *AppState) SnapshotWeb3(ctx context.Context) (clienthttp.Web3Snapshot, bool, error) {
	s.mu.Lock()
	wrt := s.wrt
	settings := NormalizeGUISettings(s.GUISettings)
	s.mu.Unlock()

	if wrt == nil || wrt.chains == nil || wrt.onchain == nil || wrt.contracts == nil || wrt.deployer == nil {
		return clienthttp.Web3Snapshot{}, false, nil
	}

	// Config shim is needed for default networks
	cfg, err := buildConfigShim(settings)
	if err != nil {
		return clienthttp.Web3Snapshot{}, false, err
	}

	// Lazily build Assets Manager once (tied to chains)
	am, err := wrt.assetsManager()
	if err != nil {
		return clienthttp.Web3Snapshot{}, false, err
	}

	nm, err := wrt.networksManager(ctx, cfg)
	if err != nil {
		return clienthttp.Web3Snapshot{}, false, err
	}

	defaultNetworks := helpers.NetworksMapFromConfig(cfg)
	if err := nm.EnsureFromConfig(ctx, defaultNetworks); err != nil {
		return clienthttp.Web3Snapshot{}, false, err
	}

	auth := clienthttp.NewWeb3Auth(wrt.chains, wrt.onchain)
	rpc := clienthttp.NewWeb3RPC(wrt.chains)

	return clienthttp.Web3Snapshot{
		Chains:   wrt.chains,
		OnChain:  wrt.onchain,
		CWStore:  wrt.contracts,
		Deployer: wrt.deployer,
		Assets:   am,
		Networks: nm,
		TxSender: &txSenderFactory{wrt: wrt},
		Auth:     auth,
		RPC:      rpc,
	}, true, nil
}

func (s *AppState) IdentitySnapshot() (runtime.Identity, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.payload == nil || s.payload.Identity == nil {
		return runtime.Identity{}, false
	}
	return runtime.Identity{
		UserID:   s.payload.Identity.UserID,
		DeviceID: s.payload.Identity.DeviceID,
	}, true
}

func (s *AppState) SetTranslator(tr *i18n.Translator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tr = tr
}

func (s *AppState) ApplyLanguage(lang string) error {
	lang = NormalizeGUISettings(GUISettings{Language: lang}).Language
	tr, err := i18n.NewTranslator(lang)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.tr = tr
	// Keep GUISettings in sync (vault is source of truth, but this helps instantly)
	s.GUISettings.Language = lang
	s.mu.Unlock()

	return nil
}

func (s *AppState) T(id string, data ...map[string]any) string {
	s.mu.Lock()
	tr := s.tr
	s.mu.Unlock()

	if tr == nil {
		return id
	}
	return tr.T(id, data...)
}

func (s *AppState) Close() error {
	// Close server + wallet first (they may rely on crypto)
	err := s.CloseAll(context.Background())
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.crypto != nil {
		err = s.crypto.Close()
		s.crypto = nil
	}
	return err
}

func (s *AppState) CloseServerOnly(ctx context.Context) {
	if s == nil {
		return
	}

	s.mu.Lock()
	srt := s.srt
	s.srt = nil
	s.mu.Unlock()

	if srt == nil {
		return
	}
	srt.Close(ctx)
}

func (s *AppState) CloseWalletOnly(ctx context.Context) {
	if s == nil {
		return
	}

	s.CloseServerOnly(ctx)

	s.mu.Lock()
	wrt := s.wrt
	s.wrt = nil
	s.mu.Unlock()

	if wrt == nil {
		return
	}
	wrt.CloseAll(ctx) // or wrt.Close(ctx) if you rename it
}

func (s *AppState) CloseAll(ctx context.Context) error {
	if s == nil {
		return nil
	}

	s.CloseWalletOnly(ctx)

	s.mu.Lock()
	crypto := s.crypto
	s.crypto = nil
	s.mu.Unlock()

	if s.drt != nil {
		s.drt.Close(ctx)
		s.drt = nil
	}

	if crypto != nil {
		return crypto.Close()
	}
	return nil
}

func (s *AppState) Password() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.password
}

func (s *AppState) PasswordBytes() []byte {
	return []byte(s.Password())
}

func (s *AppState) SetPassword(pw string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.password = pw
}

func (s *AppState) PasswordSet() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.password != ""
}

func (s *AppState) SetVaultPayload(p *VaultPayload) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.payload = p
	s.GUISettings = NormalizeGUISettings(p.Settings)

	s.payload.Settings = s.GUISettings
}

func (s *AppState) VaultPayloadCopy() (VaultPayload, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.payload == nil {
		return VaultPayload{}, false
	}
	return *s.payload, true
}

func (s *AppState) UpdateVault(mutator func(p *VaultPayload)) error {
	s.mu.Lock()
	if s.payload == nil {
		s.mu.Unlock()
		return errors.New("vault not loaded")
	}

	pw := s.password

	mutator(s.payload)

	s.payload.Settings = NormalizeGUISettings(s.payload.Settings)
	s.GUISettings = s.payload.Settings

	payloadCopy := *s.payload
	s.mu.Unlock()

	return SaveVaultPayload(pw, payloadCopy)
}

func (s *AppState) Lock() {
	err := s.CloseAll(context.Background())
	if err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.password = ""

	if s.crypto != nil {
		_ = s.crypto.Close()
		s.crypto = nil
	}
}

func (s *AppState) InitRuntime(ctx context.Context) error {
	// Fast path
	s.mu.Lock()
	if s.crypto != nil {
		s.mu.Unlock()
		return nil
	}
	settings := s.GUISettings
	s.mu.Unlock()

	settings = NormalizeGUISettings(settings)

	rt, err := cryptoctx.New(ctx, cryptoctx.Config{
		TPM:       tpmdevice.Config{},
		OwnerAuth: settings.TPMOwnerAuth,
		PQLabel:   settings.PQLabel,
	})
	if err != nil {
		return fmt.Errorf("init cryptoctx: %w", err)
	}

	// Store (race-safe)
	s.mu.Lock()
	if s.crypto == nil {
		s.crypto = rt
		rt = nil
	}

	s.mu.Unlock()

	if rt != nil {
		_ = rt.Close()
	}

	return nil
}

func (s *AppState) RegisterNewAccount(ctx context.Context, email, userName, deviceLabel string) (string, string, error) {
	qa, cleanup, err := s.newQAClient(ctx)
	if err != nil {
		return "", "", err
	}
	defer cleanup()

	pw := []byte(s.Password())
	username := userName
	if username == "" {
		username = email
	}

	devicelabel := deviceLabel
	if devicelabel == "" {
		devicelabel = "default-device"
	}

	userId, err := qa.RegisterUser(ctx, email, pw, username)
	if err != nil {
		return "", "", err
	}
	s.Log.Addf("register user_id %s ", userId)

	deviceId, userIdReturned, err := qa.RegisterDevice(ctx, email, pw, devicelabel)
	if err != nil {
		return "", "", err
	}

	s.Log.Addf("register device_id %s ", deviceId)

	if userIdReturned != "" && userIdReturned != userId {
		s.Log.Addf("warning: registerDevice returned different user_id (%s != %s)", userIdReturned, userId)
	}

	if err := qa.FullLogin(ctx, userId, deviceId, pw); err != nil {
		s.Log.Addf("backend login unavailable (offline ok): %v", err)
	}
	return userId, deviceId, nil
}

func (s *AppState) AddDeviceToAccount(ctx context.Context, email, deviceLabel string) (string, string, error) {
	qa, cleanup, err := s.newQAClient(ctx)
	if err != nil {
		return "", "", err
	}
	defer cleanup()

	pw := []byte(s.Password())

	uid, did, err := qa.RegisterDevice(ctx, email, pw, deviceLabel)
	if err != nil {
		return "", "", err
	}

	if err := qa.FullLogin(ctx, uid, did, pw); err != nil {
		s.Log.Addf("backend login unavailable (offline ok): %v", err)
	}
	return uid, did, nil
}

func (s *AppState) newQAClient(ctx context.Context) (*services.Client, func(), error) {
	s.mu.Lock()
	serverURL := strings.TrimSpace(s.GUISettings.ServerURL)
	qaEnv := s.GUISettings.QAEnv
	rt := s.crypto
	s.mu.Unlock()

	if serverURL == "" {
		var err error
		serverURL, err = ResolveServerURL(qaEnv)
		if err != nil {
			return nil, nil, err
		}
	}

	// ensure crypto runtime exists (no lock held)
	if rt == nil {
		if err := s.InitRuntime(ctx); err != nil {
			return nil, nil, err
		}
		s.mu.Lock()
		rt = s.crypto
		s.mu.Unlock()
		if rt == nil {
			return nil, nil, errors.New("crypto runtime not initialized")
		}
	}

	c, err := services.NewClient(services.ClientConfig{
		BaseURL:     serverURL,
		HTTPTimeout: 10 * time.Second,
		Crypto:      rt,
	})
	if err != nil {
		return nil, nil, err
	}

	cleanup := func() { _ = c.Close() }
	return c, cleanup, nil
}

func (s *AppState) CryptoPublicKeys(ctx context.Context) (tpmPub, pqPub string, err error) {
	s.mu.Lock()
	rt := s.crypto
	s.mu.Unlock()

	if rt == nil {
		return "", "", errors.New("runtime not initialized")
	}

	tpmPub = rt.TPMPublicKeyB64()
	pqPub, err = rt.PQPublicKeyB64(ctx)
	return tpmPub, pqPub, err
}

func (s *AppState) EnsureWalletRuntime(ctx context.Context) error {
	s.wrtInitMu.Lock()
	defer s.wrtInitMu.Unlock()

	// Must be unlocked (you need pw + TPM auth)
	if !s.PasswordSet() {
		return errors.New("unlock required")
	}

	s.mu.Lock()
	already := s.wrt != nil && s.wrt.userWallet != nil && s.wrt.deviceWallet != nil
	pw := s.password
	cryptoRT := s.crypto
	settings := NormalizeGUISettings(s.GUISettings)
	s.mu.Unlock()

	if already {
		exists, err := s.walletsExistOnDisk()
		if err != nil {
			return err
		}
		if !exists {
			// wallets vanished; clear runtime + flag
			s.CloseWalletOnly(ctx)
			_ = s.UpdateVault(func(p *VaultPayload) { p.Flags.WalletCreated = false })
			return ErrWalletsNotCreated
		}
		return nil
	}

	// Need crypto runtime for other parts; keep consistent with existing behavior
	if cryptoRT == nil {
		if err := s.InitRuntime(ctx); err != nil {
			return err
		}
	}

	// --- wallets (local, offline) ---
	userStore, err := userwallet.NewStore()
	if err != nil {
		return err
	}
	userExists, err := userStore.Exists()
	if err != nil {
		return err
	}

	sealer := tpmdevice.NewSealer(settings.TPMOwnerAuth)
	deviceStore, err := devicewallet.NewStore(sealer)
	if err != nil {
		return err
	}
	deviceExists, err := deviceStore.Exists()
	if err != nil {
		return err
	}

	// Require BOTH to exist.
	if !userExists || !deviceExists {
		// Do not create here. UI should prompt the user to create wallets.
		// Persist flag in vault
		if err := s.UpdateVault(func(p *VaultPayload) {
			p.Flags.WalletCreated = false
		}); err != nil {
			return err
		}

		return ErrWalletsNotCreated
	}

	// Load-only (no creation)
	userW, err := userStore.Load([]byte(pw))
	if err != nil {
		// If file disappeared between Exists and Load, treat as not created
		if errors.Is(err, os.ErrNotExist) {
			return ErrWalletsNotCreated
		}
		return err
	}

	deviceW, err := deviceStore.Load(ctx)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrWalletsNotCreated
		}
		return err
	}

	var tpmW wtypes.TPMBackedWallet = deviceW

	// --- chain service + contract store (needed for AA deploy + config load) ---
	chainService, err := buildChainServiceFromGUI(settings)
	if err != nil {
		return err
	}

	contractStore, err := contractwallet.NewStore()
	if err != nil {
		_ = chainService.Close()
		return err
	}

	// Try load contract for active chain (best effort)
	var contractCfg *contractwallet.Config
	if chainClients, err := chainService.Active(); err == nil {
		if cidClient, ok := chainClients.HTTP.(chainIDer); ok {
			if chainIDBig, err := cidClient.ChainID(ctx); err == nil {
				if cfg, lerr := contractStore.LoadForChain(chainIDBig.Uint64()); lerr == nil {
					contractCfg = cfg
				} else if !errors.Is(lerr, contractwallet.ErrContractNotConfigured) {
					s.Log.Addf("contract config load failed: %v", lerr)
				}
			}
		}
	}

	onchain := &contractwallet.Runtime{
		ChainService: chainService,
		User:         userW,
		Device:       tpmW,
		Contract:     contractCfg,
	}

	// Config shim is needed to resolve EntryPoint by network name for deployer
	cfg, err := buildConfigShim(settings)
	if err != nil {
		_ = chainService.Close()
		return err
	}

	deployer, err := contractwallet.NewContractDeployer(contractwallet.DeployerConfig{
		Chains:  chainService,
		Store:   contractStore,
		Wallets: clienthttp.StaticWalletProvider{User: userW, Device: tpmW},
	})
	if err != nil {
		_ = chainService.Close()
		return err
	}
	// Attach entry point resolver (same idea as server.AttachDeployer)
	deployer.SetEntryPointResolver(func(networkName string) (common.Address, error) {
		netCfg, ok := cfg.Networks.Networks[networkName]
		if !ok {
			return common.Address{}, fmt.Errorf("network %q not found", networkName)
		}
		if strings.TrimSpace(netCfg.EntryPoint) == "" {
			return common.Address{}, fmt.Errorf("missing entryPoint for %q", networkName)
		}
		if !common.IsHexAddress(netCfg.EntryPoint) {
			return common.Address{}, fmt.Errorf("invalid entryPoint %q for %q", netCfg.EntryPoint, networkName)
		}
		return common.HexToAddress(netCfg.EntryPoint), nil
	})

	wrt := &walletRuntime{
		chains:       chainService,
		contracts:    contractStore,
		userWallet:   userW,
		deviceWallet: tpmW,
		onchain:      onchain,
		deployer:     deployer,
	}

	// install runtime (swap without holding lock during IO)
	s.mu.Lock()
	old := s.wrt
	s.wrt = wrt
	s.mu.Unlock()

	if old != nil {
		old.CloseAll(context.Background())
	}

	return nil
}

func (s *AppState) walletsExistOnDisk() (bool, error) {
	s.mu.Lock()
	settings := NormalizeGUISettings(s.GUISettings)
	s.mu.Unlock()

	userStore, err := userwallet.NewStore()
	if err != nil {
		return false, err
	}
	userExists, err := userStore.Exists()
	if err != nil {
		return false, err
	}

	sealer := tpmdevice.NewSealer(settings.TPMOwnerAuth)
	deviceStore, err := devicewallet.NewStore(sealer)
	if err != nil {
		return false, err
	}
	deviceExists, err := deviceStore.Exists()
	if err != nil {
		return false, err
	}

	return userExists && deviceExists, nil
}

func (s *AppState) ReconcileWalletState(ctx context.Context) {
	exists, err := s.walletsExistOnDisk()
	if err != nil {
		s.Log.Addf("wallet reconcile error: %v", err)
		return
	}

	// If wallets were deleted, nuke runtime so UI and server can’t keep using stale in-memory wallets.
	if !exists {
		s.CloseWalletOnly(ctx) // closes server too via your CloseWalletOnly
	}

	_ = s.UpdateVault(func(p *VaultPayload) {
		p.Flags.WalletCreated = exists
	})
}

func (s *AppState) CreateWallets(ctx context.Context) error {
	// Must be unlocked (need password + TPM auth)
	if !s.PasswordSet() {
		return errors.New("unlock required")
	}

	s.mu.Lock()
	settings := NormalizeGUISettings(s.GUISettings)
	pw := s.password
	s.mu.Unlock()

	// Create user wallet
	userStore, err := userwallet.NewStore()
	if err != nil {
		return err
	}
	_, err = userStore.Create([]byte(pw))
	if err != nil {
		return err
	}

	// Create device wallet
	sealer := tpmdevice.NewSealer(settings.TPMOwnerAuth)
	deviceStore, err := devicewallet.NewStore(sealer)
	if err != nil {
		return err
	}
	_, err = deviceStore.Create(ctx)
	if err != nil {
		return err
	}

	// Persist flag in vault
	if err := s.UpdateVault(func(p *VaultPayload) {
		p.Flags.WalletCreated = true
	}); err != nil {
		return err
	}

	// Now install runtime using load-only path
	return s.EnsureWalletRuntime(ctx)
}

func ResolveServerURL(qaEnv string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(qaEnv)) {
	case "", "prod", "production":
		return "https://api.quantumauth.io/quantum-auth/v1", nil
	case "local":
		return "http://localhost:1042/quantum-auth/v1", nil
	case "dev", "develop", "development":
		return "https://dev.api.quantumauth.io/quantum-auth/v1", nil
	default:
		return "", fmt.Errorf("invalid QA environment %q", qaEnv)
	}
}
