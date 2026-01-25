package http

import (
	"context"
	"net/http"
	"sync"

	"github.com/quantumauth-io/quantum-auth-client/cmd/quantum-auth-client/config"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/devkeys"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/wtypes"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/runtime"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/services"
)

const extensionPairHeader = "X-QA-Extension"
const agentSessionHeader = "X-QA-Session"

type Server struct {
	qaClient          *services.Client
	mux               *http.ServeMux
	identity          runtime.Identity
	agentSessionToken string
	perms             *PermissionStore
	pairingTokenPath  string
	pairings          map[string]*Pairing
	pairingsMu        sync.Mutex
	ctx               context.Context
	cfg               *config.Config
	devKeysManager    devkeys.Manager
	pairTokenProvider PairTokenProvider
	web3              Web3Provider
	devKeys           DevKeysProvider
}

func (p StaticWalletProvider) UserWallet(ctx context.Context) (wtypes.Wallet, error) {
	return p.User, nil
}
func (p StaticWalletProvider) DeviceWallet(ctx context.Context) (wtypes.Wallet, error) {
	return p.Device, nil
}

func NewServer(ctx context.Context, qaClient *services.Client,
	cfg *config.Config, identity runtime.Identity, pairTokenProvider PairTokenProvider, web3 Web3Provider,
	devKeys DevKeysProvider) (*Server, error) {

	s := &Server{
		ctx:               ctx,
		qaClient:          qaClient,
		mux:               http.NewServeMux(),
		pairings:          make(map[string]*Pairing),
		cfg:               cfg,
		identity:          identity,
		pairTokenProvider: pairTokenProvider,
		web3:              web3,
		devKeys:           devKeys,
	}

	// ---- init allowlist storage ----
	permPath, err := permissionsFilePath()
	if err != nil {
		return nil, err
	}
	s.perms = NewPermissionStore(permPath)
	if err := s.perms.Load(); err != nil {
		return nil, err
	}

	// agent pairing and status
	s.mux.HandleFunc("/agent/extension/pair", s.withAgentGuards(s.handleAgentExtensionPairHTTP))
	s.mux.HandleFunc("/agent/extension/status", s.withAgentGuards(s.handleAgentExtensionStatusHTTP))
	s.mux.HandleFunc("/agent/session/validate", s.withAgentGuards(s.handleAgentSessionValidateHTTP))

	// Challenge endpoint to authenticate on third party apps
	s.mux.HandleFunc("/extension/auth", s.withExtensionPairedGuards(s.handleExtensionAuthHTTP))

	// Extension management (paired extension only)
	s.mux.HandleFunc("/extension/permissions", s.withExtensionPairedGuards(s.handleGetPermissionsHTTP))
	s.mux.HandleFunc("/extension/permissions/status", s.withExtensionPairedGuards(s.handleGetPermissionStatusHTTP))
	s.mux.HandleFunc("/extension/permissions/set", s.withExtensionPairedGuards(s.handleSetPermissionHTTP))

	// extension ethwallet endpoint (paired extension only)
	s.mux.HandleFunc("/wallet/chainId", s.withExtensionPairedGuards(s.handleWalletChainIdHTTP))
	s.mux.HandleFunc("/wallet/accounts", s.withExtensionPairedGuards(s.handleWalletAccountsHTTP))
	s.mux.HandleFunc("/wallet/switchChain", s.withExtensionPairedGuards(s.handleWalletSwitchChainHTTP))
	s.mux.HandleFunc("/wallet/sendTransaction", s.withExtensionPairedGuards(s.handleWalletSendTransactionHTTP))
	s.mux.HandleFunc("/wallet/transactionReceipt", s.withExtensionPairedGuards(s.handleTransactionReceiptHTTP))
	s.mux.HandleFunc("/wallet/estimateSendTransaction", s.withExtensionPairedGuards(s.handleWalletEstimateSendTransactionHTTP))
	s.mux.HandleFunc("/wallet/personalSign", s.withExtensionPairedGuards(s.handleWalletPersonalSignHTTP))
	s.mux.HandleFunc("/wallet/signTypedDataV4", s.withExtensionPairedGuards(s.handleWalletSignTypedDataV4HTTP))
	s.mux.HandleFunc("/wallet/rpc", s.withExtensionPairedGuards(s.handleWalletRPCHTTP))

	s.mux.HandleFunc("/wallet/accounts/summary", s.withExtensionPairedGuards(s.handleWalletAccountsSummaryHTTP))
	s.mux.HandleFunc("/wallet/networks", s.withExtensionPairedGuards(s.handleWalletNetworksHTTP))
	s.mux.HandleFunc("/wallet/network", s.withExtensionPairedGuards(s.handleWalletSetNetworkHTTP))

	s.mux.HandleFunc("/wallet/networks/add", s.withExtensionPairedGuards(s.handleWalletAddNetworkHTTP))
	s.mux.HandleFunc("/wallet/networks/remove", s.withExtensionPairedGuards(s.handleWalletRemoveNetworkHTTP))
	s.mux.HandleFunc("/wallet/networks/update", s.withExtensionPairedGuards(s.handleWalletUpdateNetworkHTTP))
	s.mux.HandleFunc("/wallet/networks/metadata", s.withExtensionPairedGuards(s.handleWalletNetworkMetadataHTTP))

	s.mux.HandleFunc("/wallet/assets/list", s.withExtensionPairedGuards(s.handleWalletListAssetsHTTP))
	s.mux.HandleFunc("/wallet/assets/add", s.withExtensionPairedGuards(s.handleWalletAddAssetHTTP))
	s.mux.HandleFunc("/wallet/assets/remove", s.withExtensionPairedGuards(s.handleWalletRemoveAssetHTTP))
	s.mux.HandleFunc("/wallet/assets/metadata", s.withExtensionPairedGuards(s.handleWalletAssetMetadataHTTP))

	s.mux.HandleFunc("/wallet/deployAA", s.withExtensionPairedGuards(s.handleDeployContractOnChainHTTP))

	// Developer PQ keys (extension)
	s.mux.HandleFunc("/extension/developer/key/list", s.withExtensionPairedGuards(s.handleDevKeyListHTTP))
	s.mux.HandleFunc("/extension/developer/key/create", s.withExtensionPairedGuards(s.handleDevKeyCreateHTTP))
	s.mux.HandleFunc("/extension/developer/key/update", s.withExtensionPairedGuards(s.handleDevKeyUpdateHTTP))
	s.mux.HandleFunc("/extension/developer/key/delete", s.withExtensionPairedGuards(s.handleDevKeyDeleteHTTP))
	s.mux.HandleFunc("/extension/developer/key/export", s.withExtensionPairedGuards(s.handleDeveloperKeyExportHTTP))

	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// require providers
func (s *Server) requireWeb3(w http.ResponseWriter, r *http.Request) (Web3Snapshot, bool) {
	if s.web3 == nil {
		writeRPCError(w, http.StatusServiceUnavailable, JSONRPCErrorCodeInternalError, WalletRuntimeNotInitializedText, nil)
		return Web3Snapshot{}, false
	}

	snap, ok, err := s.web3.SnapshotWeb3(r.Context())
	if err != nil {
		writeRPCError(w, http.StatusInternalServerError, JSONRPCErrorCodeInternalError, "web3 provider error", err.Error())
		return Web3Snapshot{}, false
	}
	if !ok {
		// not created / not unlocked / missing runtime
		writeRPCError(w, http.StatusServiceUnavailable, JSONRPCErrorCodeInternalError, WalletRuntimeNotInitializedText, nil)
		return Web3Snapshot{}, false
	}

	// extra sanity checks (optional but recommended)
	if snap.Chains == nil {
		writeRPCError(w, http.StatusServiceUnavailable, JSONRPCErrorCodeInternalError, "chains not initialized", nil)
		return Web3Snapshot{}, false
	}
	if snap.Networks == nil {
		writeRPCError(w, http.StatusServiceUnavailable, JSONRPCErrorCodeInternalError, "networks manager not initialized", nil)
		return Web3Snapshot{}, false
	}
	return snap, true
}

func (s *Server) requireDevKeys(w http.ResponseWriter, r *http.Request) (DevKeysSnapshot, bool) {
	if s.devKeys == nil {
		writeRPCError(
			w,
			http.StatusServiceUnavailable,
			JSONRPCErrorCodeInternalError,
			DevKeysRuntimeNotInitializedText,
			nil,
		)
		return DevKeysSnapshot{}, false
	}

	snap, ok, err := s.devKeys.SnapshotDevKeys(r.Context())
	if err != nil {
		writeRPCError(
			w,
			http.StatusInternalServerError,
			JSONRPCErrorCodeInternalError,
			"devkeys provider error",
			err.Error(),
		)
		return DevKeysSnapshot{}, false
	}
	if !ok {
		// locked / not setup / missing runtime
		writeRPCError(
			w,
			http.StatusServiceUnavailable,
			JSONRPCErrorCodeInternalError,
			DevKeysRuntimeNotInitializedText,
			nil,
		)
		return DevKeysSnapshot{}, false
	}

	// extra sanity checks
	if snap.Manager == nil {
		writeRPCError(
			w,
			http.StatusServiceUnavailable,
			JSONRPCErrorCodeInternalError,
			"devkeys manager not initialized",
			nil,
		)
		return DevKeysSnapshot{}, false
	}

	return snap, true
}

// handlers
func (s *Server) handleAgentExtensionStatusHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodGet, s.handleAgentExtensionStatus)(w, r)
}

func (s *Server) handleWalletChainIdHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleWalletChainId)(w, r)
}

func (s *Server) handleAgentSessionValidateHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodGet, s.handleAgentSessionValidate)(w, r)
}

func (s *Server) handleAgentExtensionPairHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleAgentExtensionPair)(w, r)
}

func (s *Server) handleExtensionAuthHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleExtensionAuth)(w, r)
}

func (s *Server) handleGetPermissionsHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodGet, s.handleGetPermissions)(w, r)
}

func (s *Server) handleGetPermissionStatusHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodGet, s.handleGetPermissionStatus)(w, r)
}

func (s *Server) handleSetPermissionHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleSetPermission)(w, r)
}

func (s *Server) handleTokenPairHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleTokenPair)(w, r)
}

func (s *Server) handleTransactionReceiptHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleTransactionReceipt)(w, r)
}

func (s *Server) handleWalletAccountsHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethodRPC(http.MethodPost, s.handleWalletAccounts)(w, r)
}

func (s *Server) handleWalletSwitchChainHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethodRPC(http.MethodPost, s.handleWalletSwitchChain)(w, r)
}

func (s *Server) handleWalletSendTransactionHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethodRPC(http.MethodPost, s.handleWalletSendTransaction)(w, r)
}

func (s *Server) handleWalletEstimateSendTransactionHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethodRPC(http.MethodPost, s.handleWalletEstimateSendTransaction)(w, r)
}

func (s *Server) handleWalletPersonalSignHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethodRPC(http.MethodPost, s.handleWalletPersonalSign)(w, r)
}

func (s *Server) handleWalletSignTypedDataV4HTTP(w http.ResponseWriter, r *http.Request) {
	requireMethodRPC(http.MethodPost, s.handleWalletSignTypedDataV4)(w, r)
}

func (s *Server) handleWalletRPCHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethodRPC(http.MethodPost, s.handleWalletRPC)(w, r)
}

func (s *Server) handleWalletAccountsSummaryHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethodRPC(http.MethodGet, s.handleWalletAccountsSummary)(w, r)
}
func (s *Server) handleWalletNetworksHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodGet, s.handleWalletNetworks)(w, r)
}

func (s *Server) handleWalletSetNetworkHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleWalletSetNetwork)(w, r)
}

func (s *Server) handleDeployContractOnChainHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethodRPC(http.MethodPost, s.handleDeployContractOnChain)(w, r)
}

func (s *Server) handleWalletAddNetworkHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleWalletAddNetwork)(w, r)
}

func (s *Server) handleWalletRemoveNetworkHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleWalletRemoveNetwork)(w, r)
}

func (s *Server) handleWalletUpdateNetworkHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleWalletUpdateNetwork)(w, r)
}

func (s *Server) handleWalletNetworkMetadataHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleWalletNetworkMetadata)(w, r)
}

func (s *Server) handleWalletListAssetsHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleWalletListAssets)(w, r)
}

func (s *Server) handleWalletAddAssetHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleWalletAddAsset)(w, r)
}

func (s *Server) handleWalletRemoveAssetHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleWalletRemoveAsset)(w, r)
}

func (s *Server) handleWalletAssetMetadataHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleWalletAssetMetadata)(w, r)
}

func (s *Server) handleDevKeyListHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodGet, s.handleDevKeyList)(w, r)
}

func (s *Server) handleDevKeyCreateHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleDevKeyCreate)(w, r)
}

func (s *Server) handleDevKeyUpdateHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleDevKeyUpdate)(w, r)
}

func (s *Server) handleDevKeyDeleteHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleDevKeyDelete)(w, r)
}

func (s *Server) handleDeveloperKeyExportHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleDeveloperKeyExport)(w, r)
}
