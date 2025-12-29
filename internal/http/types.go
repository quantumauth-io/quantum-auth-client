package http

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
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

type rpcErr struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type walletRPCReq struct {
	Origin string `json:"origin"`
	Method string `json:"method"`
	Params any    `json:"params"`
}

type walletAccountsReq struct {
	Silent bool `json:"silent"`
	Prompt bool `json:"prompt"`
}

type walletSwitchChainReq struct {
	ChainIDHex string `json:"chainIdHex"` // "0x..."
}

type walletSendTxReq struct {
	Tx walletTxParams `json:"tx"`
}

type walletTxParams struct {
	From                 string `json:"from"`
	To                   string `json:"to,omitempty"`
	Gas                  string `json:"gas,omitempty"`                  // hex qty
	GasPrice             string `json:"gasPrice,omitempty"`             // hex qty
	MaxFeePerGas         string `json:"maxFeePerGas,omitempty"`         // hex qty
	MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas,omitempty"` // hex qty
	Value                string `json:"value,omitempty"`                // hex qty
	Data                 string `json:"data,omitempty"`                 // 0x...
	Nonce                string `json:"nonce,omitempty"`                // hex qty
}

type walletPersonalSignReq struct {
	Address string `json:"address"` // signer address
	Message string `json:"message"` // usually hex or utf8; we support both
}

type walletSignTypedDataReq struct {
	Address   string `json:"address"`
	TypedData string `json:"typedData"` // JSON string (EIP-712 typed data)
}

// --- Network list response types ---

type networkItem struct {
	ChainIDHex string `json:"chainIdHex"`
	Name       string `json:"name"`
}

type walletNetworksResp struct {
	OK   bool `json:"ok"`
	Data struct {
		CurrentChainIDHex string        `json:"currentChainIdHex"`
		Networks          []networkItem `json:"networks"`
	} `json:"data"`
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

func parseHexQuantity(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if s == "" {
		return big.NewInt(0), nil
	}
	n := new(big.Int)
	_, ok := n.SetString(s, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex quantity: %q", s)
	}
	return n, nil
}

func parseAddr(s string) (common.Address, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return common.Address{}, fmt.Errorf("missing address")
	}
	if !common.IsHexAddress(s) {
		return common.Address{}, fmt.Errorf("invalid address: %q", s)
	}
	return common.HexToAddress(s), nil
}

func parseHexData(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("invalid hex data length")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex data: %w", err)
	}
	return b, nil
}

// personal_sign often sends message as hex bytes. If it isn't hex, treat as utf8.
func parsePersonalSignMessage(msg string) ([]byte, error) {
	m := strings.TrimSpace(msg)
	if strings.HasPrefix(m, "0x") || strings.HasPrefix(m, "0X") {
		return parseHexData(m)
	}
	return []byte(m), nil
}

func mustHexBytes(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return []byte{}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustHexBig(s string) *big.Int {
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return big.NewInt(0)
	}
	n := new(big.Int)
	n.SetString(s, 16)
	return n
}

func packExecuteCall(accountABI abi.ABI, to common.Address, value *big.Int, data []byte) ([]byte, error) {
	return accountABI.Pack("execute", to, value, data)
}

func packU128Pair(low, high *big.Int) [32]byte {
	// packs two uint128 into 32 bytes: (high << 128) | low
	out := [32]byte{}
	x := new(big.Int).Set(high)
	x.Lsh(x, 128)
	x.Or(x, new(big.Int).Set(low))
	b := x.FillBytes(make([]byte, 32))
	copy(out[:], b)
	return out
}
