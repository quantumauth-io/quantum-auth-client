package http

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/quantumauth-io/quantum-auth-client/cmd/quantum-auth-client/config"
	"github.com/quantumauth-io/quantum-auth-client/internal/assets"
	"github.com/quantumauth-io/quantum-auth-client/internal/ethwallet/contractwallet"
	"github.com/quantumauth-io/quantum-auth-client/internal/ethwallet/wtypes"
	"github.com/quantumauth-io/quantum-auth-client/internal/login"
	"github.com/quantumauth-io/quantum-auth-client/internal/pairing"
	"github.com/quantumauth-io/quantum-auth-client/internal/qa"
	utilsEth "github.com/quantumauth-io/quantum-go-utils/ethrpc"
	"github.com/quantumauth-io/quantum-go-utils/log"
)

const extensionPairHeader = "X-QA-Extension"
const agentSessionHeader = "X-QA-Session"

const (
	ModeNormal   uint8 = 0
	ModeRecovery uint8 = 1
)

func (p StaticWalletProvider) UserWallet(ctx context.Context) (wtypes.Wallet, error) {
	return p.User, nil
}
func (p StaticWalletProvider) DeviceWallet(ctx context.Context) (wtypes.Wallet, error) {
	return p.Device, nil
}

func NewServer(ctx context.Context, qaClient *qa.Client, authState *login.QAClientLoginService, uiAllowedOrigins []string,
	ethClient *utilsEth.Client, onChain *contractwallet.Runtime, cfg *config.Config, assetsManager *assets.Manager, cwStore *contractwallet.Store) (*Server, error) {
	s := &Server{
		ctx:           ctx,
		qaClient:      qaClient,
		authClient:    authState,
		mux:           http.NewServeMux(),
		pairings:      make(map[string]*Pairing),
		ethClient:     ethClient,
		onChain:       onChain,
		cfg:           cfg,
		assetsManager: assetsManager,
		cwStore:       cwStore,
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

	// ---- init pairing token path ----
	ptPath, err := pairingTokenFilePath()
	if err != nil {
		return nil, err
	}
	s.pairingTokenPath = ptPath

	// Agent Token and Allowed Origin
	token, err := newSessionToken()
	if err != nil {
		return nil, err
	}
	s.agentSessionToken = token
	s.uiAllowedOrigins = make(map[string]struct{}, len(uiAllowedOrigins))
	for _, o := range uiAllowedOrigins {
		o = normalizeOrigin(o)
		if o == "" {
			continue
		}
		s.uiAllowedOrigins[o] = struct{}{}
	}
	// CORS for local UI (Vite) but no token required
	localUICors := corsPolicy{
		allowedOrigins: s.uiAllowedOrigins,
		allowMethods:   "GET,OPTIONS",
		allowHeaders:   "", // echo requested
		maxAge:         600,
	}

	pairCors := corsPolicy{
		allowedOrigins: s.uiAllowedOrigins,
		allowMethods:   "POST,OPTIONS",
		allowHeaders:   "", // echo
		maxAge:         600,
	}

	// Agent UI Endpoint
	s.mux.HandleFunc("/healthz", s.withCORS(localUICors, s.withLoopbackOnly(s.handleHealthHTTP)))
	s.mux.HandleFunc("/status", s.withCORS(localUICors, s.withLoopbackOnly(s.handleStatusHTTP)))

	// initial load of agent UI
	s.mux.HandleFunc("/pair/exchange", s.withCORS(pairCors, s.withLoopbackOnly(s.handleTokenPairHTTP)))

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

	s.mux.HandleFunc("/wallet/deployAA", s.withExtensionPairedGuards(s.handleDeployContractOnChainHTTP))

	// agent-only endpoints (UI)
	s.mux.HandleFunc("/agent/status", s.withAgentGuards(s.handleAgentStatusHTTP))
	s.mux.HandleFunc("/agent/guardian/sign-register", s.withAgentGuards(s.handleAgentSignRegisterHTTP))
	s.mux.HandleFunc("/agent/guardian/sign-withdraw", s.withAgentGuards(s.handleAgentSignWithdrawHTTP))

	// generate a pair code for the extension
	pairID := uuid.NewString()
	pairCode, err := pairing.GeneratePairCode()
	if err != nil {
		return nil, err
	}

	s.pairingsMu.Lock()
	s.pairings[pairID] = &Pairing{
		CodeHash:  pairing.HashCode(pairCode),
		ExpiresAt: time.Now().Add(60 * time.Second),
		Token:     s.agentSessionToken,
	}
	s.pairingsMu.Unlock()

	pairURL := fmt.Sprintf(
		"http://127.0.0.1:6137/#/?server=%s&pair_id=%s&code=%s",
		url.QueryEscape("http://127.0.0.1:6137"),
		url.QueryEscape(pairID),
		url.QueryEscape(pairCode),
	)

	log.Info("pair with agent UI", "url", pairURL)
	// attach UI LAST
	if err = s.AttachUI(); err != nil {
		return nil, err
	}
	return s, nil
}

// ServeHTTP implements http.Handler
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) relayerAuth(ctx context.Context) (*bind.TransactOpts, common.Address, error) {
	privKey, err := s.onChain.User.ExportPrivateKey(ctx)
	if err != nil {
		return nil, common.Address{}, err
	}
	if privKey == nil {
		return nil, common.Address{}, fmt.Errorf("exported private key is nil")
	}

	from := crypto.PubkeyToAddress(privKey.PublicKey)

	chainID, err := s.ethClient.ChainID(ctx)
	if err != nil {
		return nil, common.Address{}, err
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

func (s *Server) signUserOpHash(ctx context.Context, userOpHash []byte) ([]byte, error) {
	if len(userOpHash) != 32 {
		return nil, fmt.Errorf("userOpHash must be 32 bytes")
	}

	// --- TPM signs RAW userOpHash ---
	sigTPM, err := s.onChain.Device.SignHash(ctx, userOpHash)
	if err != nil {
		return nil, fmt.Errorf("tpm sign failed: %w", err)
	}

	// --- EOAs sign ETH-SIGNED hash ---
	ethHash := ethSignedHash(userOpHash)

	var sigEOA1, sigEOA2 []byte

	// You decide which EOA is active; example uses EOA1
	sigEOA1, err = s.onChain.User.SignHash(ctx, ethHash)
	if err != nil {
		return nil, fmt.Errorf("eoa1 sign failed: %w", err)
	}

	// Not used in MODE_NORMAL
	sigEOA2 = []byte{}

	// Normalize V if needed (OpenZeppelin expects 27/28)
	if sigEOA1[64] < 27 {
		sigEOA1[64] += 27
	}

	return packQuantumAuthSignature(
		ModeNormal,
		sigEOA1,
		sigEOA2,
		sigTPM,
	)
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
		{Type: abi.Type{T: abi.UintTy, Size: 8}}, // uint8
		{Type: abi.Type{T: abi.BytesTy}},         // bytes
		{Type: abi.Type{T: abi.BytesTy}},         // bytes
		{Type: abi.Type{T: abi.BytesTy}},         // bytes
	}

	return args.Pack(
		mode,
		sigEOA1,
		sigEOA2,
		sigTPM,
	)
}

func (s *Server) handleAgentExtensionStatusHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodGet, s.handleAgentExtensionStatus)(w, r)
}

func (s *Server) handleWalletChainIdHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleWalletChainId)(w, r)
}

func (s *Server) handleStatusHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodGet, s.handleStatus)(w, r)
}
func (s *Server) handleAgentSessionValidateHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodGet, s.handleAgentSessionValidate)(w, r)
}
func (s *Server) handleAgentExtensionPairHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleAgentExtensionPair)(w, r)
}
func (s *Server) handleAgentStatusHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodGet, s.handleAgentStatus)(w, r)
}
func (s *Server) handleAgentSignRegisterHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleAgentSignRegister)(w, r)
}
func (s *Server) handleAgentSignWithdrawHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodPost, s.handleAgentSignWithdraw)(w, r)
}
func (s *Server) handleHealthHTTP(w http.ResponseWriter, r *http.Request) {
	requireMethod(http.MethodGet, s.handleHealth)(w, r)
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

// RPC-style endpoints (JSON-RPC errors on method mismatch)
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
