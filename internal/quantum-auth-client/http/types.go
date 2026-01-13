package http

import (
	"encoding/json"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/contractwallet"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/wtypes"
)

type corsPolicy struct {
	allowedOrigins map[string]struct{}
	allowMethods   string

	allowHeaders string
	maxAge       int
}

type extensionRequest struct {
	Action string          `json:"action"`
	Data   json.RawMessage `json:"data,omitempty"`
}

type qaChallengeRequest struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	BackendHost string `json:"backendHost"`
	AppID       string `json:"appId,omitempty"`
	Origin      string `json:"origin"` // NEW: required for allowlist enforcement
}

type setPermissionRequest struct {
	Origin  string `json:"origin"`
	Allowed bool   `json:"allowed"`
}

type extensionResponse struct {
	OK    bool        `json:"ok"`
	Error string      `json:"error,omitempty"`
	Data  interface{} `json:"data,omitempty"`
}

type pairResp struct {
	OK               bool   `json:"ok"`
	PairingToken     string `json:"pairingToken"`
	PairingTokenPath string `json:"pairingTokenPath,omitempty"`
}

type signResp struct {
	Signature string `json:"signature"` // TODO: 0x...
}

type Pairing struct {
	CodeHash  []byte
	ExpiresAt time.Time
	Used      bool
	Token     string
}

type pairExchangeReq struct {
	PairID string `json:"pair_id"`
	Code   string `json:"code"`
}

type pairExchangeResp struct {
	OK     bool   `json:"ok"`
	Token  string `json:"token"`
	Header string `json:"header"`
}

type walletRPCReq struct {
	Origin string `json:"origin"`
	Method string `json:"method"`
	Params any    `json:"params"`
}

type walletSwitchChainReq struct {
	ChainIDHex string `json:"chainIdHex"` // "0x..."
}

type walletPersonalSignReq struct {
	Origin  string `json:"origin"`
	Address string `json:"address"` // signer address
	Message string `json:"message"` // usually hex or utf8; we support both
}

type walletSignTypedDataReq struct {
	Origin        string `json:"origin"`
	Address       string `json:"address"`
	TypedDataJson string `json:"typedDataJson"`
}

type walletSetNetworkReq struct {
	ChainIDHex string `json:"chainIdHex"`
}

type SendTxRequest struct {
	Origin string       `json:"origin"`
	Tx     DappTxParams `json:"tx"`
}

type DappTxParams struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Value string `json:"value"` // hex string, may be "0x0" or missing
	Data  string `json:"data"`  // hex string, may be "0x"
	// optional fields from dapps:
	Gas      string `json:"gas,omitempty"`
	GasPrice string `json:"gasPrice,omitempty"`
	Nonce    string `json:"nonce,omitempty"`

	MaxFeePerGas         string `json:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas,omitempty"`
}

type UserOperation struct {
	Sender               common.Address `json:"sender"`
	Nonce                *big.Int       `json:"nonce"`
	InitCode             []byte         `json:"initCode"`
	CallData             []byte         `json:"callData"`
	CallGasLimit         *big.Int       `json:"callGasLimit"`
	VerificationGasLimit *big.Int       `json:"verificationGasLimit"`
	PreVerificationGas   *big.Int       `json:"preVerificationGas"`
	MaxFeePerGas         *big.Int       `json:"maxFeePerGas"`
	MaxPriorityFeePerGas *big.Int       `json:"maxPriorityFeePerGas"`
	PaymasterAndData     []byte         `json:"paymasterAndData"`
	Signature            []byte         `json:"signature"`
}

type assetOut struct {
	Address      string `json:"address"` // 0x... or native addr
	Symbol       string `json:"symbol"`
	Decimals     uint8  `json:"decimals"`
	Name         string `json:"name,omitempty"`
	BalanceWei   string `json:"balanceWei"`   // ERC20 raw units, or wei for native
	BalanceHuman string `json:"balanceHuman"` // trimmed string for UI
	LogoURI      string `json:"logoUri,omitempty"`
}
type EstimateSendTxResponse struct {
	// EIP-1559
	BaseFeeWei         string `json:"baseFeeWei"`
	BaseFeeGwei        string `json:"baseFeeGwei"`
	MaxPriorityFeeWei  string `json:"maxPriorityFeePerGasWei"`
	MaxPriorityFeeGwei string `json:"maxPriorityFeePerGasGwei"`
	MaxFeeWei          string `json:"maxFeePerGasWei"`
	MaxFeeGwei         string `json:"maxFeeGwei"`

	// AA gas fields (4337)
	CallGasLimit         string `json:"callGasLimit"`         // decimal
	VerificationGasLimit string `json:"verificationGasLimit"` // decimal
	PreVerificationGas   string `json:"preVerificationGas"`   // decimal

	// Packed fields (what you already use)
	AccountGasLimitsHex string `json:"accountGasLimitsHex"`
	GasFeesHex          string `json:"gasFeesHex"`

	// Optional convenience
	EstimatedTotalGas string `json:"estimatedTotalGas"` // call + verification + pre
}

type txReceiptRequest struct {
	TxHash   string   `json:"txHash,omitempty"`
	TxHashes []string `json:"txHashes,omitempty"`
}

type txReceiptResult struct {
	TxHash         string `json:"txHash"`
	Found          bool   `json:"found"`                   // true when mined (receipt exists)
	Status         string `json:"status"`                  // "pending" | "confirmed" | "failed"
	ReceiptStatus  uint64 `json:"receiptStatus,omitempty"` // 0 or 1 when Found
	BlockNumberHex string `json:"blockNumberHex,omitempty"`
	Error          string `json:"error,omitempty"`
}

type txReceiptResponse struct {
	OK    bool                       `json:"ok"`
	Error string                     `json:"error,omitempty"`
	Data  map[string]txReceiptResult `json:"data,omitempty"` // keyed by txHash
}

type StaticWalletProvider struct {
	User   wtypes.Wallet
	Device wtypes.Wallet
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type acctOut struct {
	Address    string `json:"address"`
	Role       string `json:"role"`
	BalanceWei string `json:"balanceWei"`
	BalanceEth string `json:"balanceEth"`
	Symbol     string `json:"symbol"`
}

type acctIn struct {
	Addr common.Address
	Role string
}

type agentStatusResponse struct {
	OK       bool   `json:"ok"`
	LoggedIn bool   `json:"loggedIn"`
	UserID   string `json:"userId,omitempty"`
	DeviceID string `json:"deviceId,omitempty"`
}

type deployAARequest struct {
	ChainIDHex      string `json:"chainIdHex"`
	RecoveryAddress string `json:"recoveryAddress"`
}

// Response shape (wraps your deployer result).
type deployAAResponse struct {
	OK   bool                           `json:"ok"`
	Data *contractwallet.AADeployResult `json:"data,omitempty"`
	Err  string                         `json:"error,omitempty"`
}

type removeNetworkReq struct {
	ChainIdHex string `json:"chainIdHex"`
}

type listAssetsReq struct {
	NetworkName string `json:"networkName"`
}

type addAssetReq struct {
	NetworkName string `json:"networkName"`
	Address     string `json:"address"`
}

type removeAssetReq struct {
	NetworkName string `json:"networkName"`
	Address     string `json:"address"`
}

type assetMetadataReq struct {
	ChainIdHex  string `json:"chainIdHex"`
	Address     string `json:"address"`
	NetworkName string `json:"networkName"`
}
