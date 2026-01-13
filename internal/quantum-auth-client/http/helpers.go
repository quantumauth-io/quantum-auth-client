package http

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/wtypes"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/shared"
)

func isLoopbackRequest(r *http.Request) bool {
	ra := r.RemoteAddr

	h, _, err := net.SplitHostPort(ra)
	if err != nil {
		ip := net.ParseIP(ra)
		return ip != nil && ip.IsLoopback()
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func isSafeLocalHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func normalizeOrigin(in string) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return ""
	}
	u, err := url.Parse(in)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return fmt.Sprintf("%s://%s", strings.ToLower(u.Scheme), strings.ToLower(u.Host))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSONBody(r *http.Request, out any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func writeRPCError(w http.ResponseWriter, status int, code int, msg string, data any) {
	writeJSON(w, status, map[string]any{
		"error": rpcErr{Code: code, Message: msg, Data: data},
	})
}

func writePairingTokenFile(path string, token string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return fmt.Errorf("write pairing token file: %w", err)
	}
	return nil
}

func newSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		ss := strings.TrimSpace(s)
		if ss == "" {
			continue
		}
		if _, ok := seen[ss]; ok {
			continue
		}
		seen[ss] = struct{}{}
		out = append(out, ss)
	}
	return out
}

func isTxHash(s string) bool {
	if len(s) != 66 || !strings.HasPrefix(s, "0x") {
		return false
	}
	for _, c := range s[2:] {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func applyBpsBuffer(gas uint64, bps uint64) uint64 {
	return (gas * bps) / 10000
}

func weiToGweiString(wei *big.Int) string {
	if wei == nil {
		return "0"
	}
	div := big.NewInt(1_000_000_000)
	q := new(big.Int).Quo(wei, div)
	r := new(big.Int).Mod(wei, div)

	r3 := new(big.Int).Mul(r, big.NewInt(1000))
	r3.Quo(r3, div)

	if r3.Sign() == 0 {
		return q.String()
	}
	return fmt.Sprintf("%s.%03d", q.String(), r3.Int64())
}

// Converts a decimal-string wei amount into an ETH string, trimming to maxDecimals.
func weiDecimalToEthString(weiDec string, maxDecimals int) string {
	weiDec = strings.TrimSpace(weiDec)
	if weiDec == "" {
		return ""
	}

	weiDec = strings.TrimLeft(weiDec, "0")
	if weiDec == "" {
		return "0.0"
	}

	const ethDecimals = 18

	if len(weiDec) <= ethDecimals {
		pad := strings.Repeat("0", ethDecimals-len(weiDec))
		frac := pad + weiDec
		frac = trimFrac(frac, maxDecimals)
		if frac == "" {
			return "0.0"
		}
		return "0." + frac
	}

	intPart := weiDec[:len(weiDec)-ethDecimals]
	frac := weiDec[len(weiDec)-ethDecimals:]
	frac = trimFrac(frac, maxDecimals)
	if frac == "" {
		return intPart
	}
	return intPart + "." + frac
}

func trimFrac(frac string, maxDecimals int) string {
	if maxDecimals < 0 {
		maxDecimals = 0
	}
	if maxDecimals == 0 {
		return ""
	}
	if len(frac) > maxDecimals {
		frac = frac[:maxDecimals]
	}
	frac = strings.TrimRight(frac, "0")
	return frac
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

// personal_sign often sends message as hex bytes. If it isn't hex, treat as utf8.
func parsePersonalSignMessage(msg string) ([]byte, error) {
	m := strings.TrimSpace(msg)
	if strings.HasPrefix(m, "0x") || strings.HasPrefix(m, "0X") {
		return parseHexData(m)
	}
	return []byte(m), nil
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

func (s *Server) isAAAccount(addr common.Address) bool {
	// pick the source of truth you already have
	if s.onChain != nil {

		AAAddress, err := s.onChain.ContractAddress()
		if err != nil {
			return false
		}
		return addr == AAAddress
	}
	// OR: from config
	// if s.cfg.EthNetworks != nil { ... netCfg.AccountAddress ... }
	return false
}

func (s *Server) resolveEIP1559Fees(ctx context.Context, req SendTxRequest) (*big.Int, *big.Int, error) {
	// 🚨 GUARD: do NOT allow mixing legacy + EIP-1559
	if req.Tx.GasPrice != "" &&
		(req.Tx.MaxFeePerGas != "" || req.Tx.MaxPriorityFeePerGas != "") {
		return nil, nil, fmt.Errorf(
			"cannot mix gasPrice with maxFeePerGas/maxPriorityFeePerGas",
		)
	}

	var (
		maxFee = new(big.Int)
		tip    = new(big.Int)
	)

	if req.Tx.MaxFeePerGas != "" && req.Tx.MaxFeePerGas != HexPrefix0x {
		v, ok := new(big.Int).SetString(strings.TrimPrefix(req.Tx.MaxFeePerGas, HexPrefix0x), 16)
		if !ok {
			return nil, nil, fmt.Errorf("invalid maxFeePerGas")
		}
		maxFee = v
	}
	if req.Tx.MaxPriorityFeePerGas != "" && req.Tx.MaxPriorityFeePerGas != HexPrefix0x {
		v, ok := new(big.Int).SetString(strings.TrimPrefix(req.Tx.MaxPriorityFeePerGas, HexPrefix0x), 16)
		if !ok {
			return nil, nil, fmt.Errorf("invalid maxPriorityFeePerGas")
		}
		tip = v
	}

	// If either missing, fill in from SuggestGasTipCap + Header.BaseFee
	if tip.Sign() == 0 {
		suggestedTip, err := s.httpChainClient.SuggestGasTipCap(ctx)
		if err != nil {
			return nil, nil, err
		}
		tip = suggestedTip
	}

	if maxFee.Sign() == 0 {
		hdr, err := s.httpChainClient.HeaderByNumber(ctx, nil)
		if err != nil {
			return nil, nil, err
		}
		baseFee := hdr.BaseFee
		if baseFee == nil {
			// fallback if baseFee missing
			baseFee = big.NewInt(0)
		}
		// common heuristic: maxFee = 2*baseFee + tip
		maxFee = new(big.Int).Add(new(big.Int).Mul(baseFee, big.NewInt(2)), tip)
	}

	return maxFee, tip, nil
}

func signEOATransaction(
	ctx context.Context,
	w wtypes.Wallet,
	tx *types.Transaction,
	chainID *big.Int,
) (*types.Transaction, error) {

	signer := types.LatestSignerForChainID(chainID)

	// 1) Compute digest
	digest := signer.Hash(tx)

	// 2) Wallet signs digest
	sig, err := w.SignHash(ctx, digest.Bytes())
	if err != nil {
		return nil, err
	}

	// 3) Inject signature
	return tx.WithSignature(signer, sig)
}

func parseHexChainID(chainIDHex string) (*big.Int, error) {
	chainIDHex = strings.TrimSpace(chainIDHex)
	if chainIDHex == "" {
		return nil, fmt.Errorf("empty chainId")
	}

	id := new(big.Int)
	if _, ok := id.SetString(chainIDHex, 0); !ok {
		return nil, fmt.Errorf("invalid hex chainId %q", chainIDHex)
	}
	return id, nil
}

func parseHexBigInt(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return big.NewInt(0), nil
	}
	i := new(big.Int)
	if _, ok := i.SetString(s, 0); !ok {
		return nil, fmt.Errorf("invalid hex integer %q", s)
	}
	return i, nil
}

func parseHexData(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0x" {
		return nil, nil
	}
	return hexutil.Decode(s)
}

func parseAddressPtr(s string) (*common.Address, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if !common.IsHexAddress(s) {
		return nil, fmt.Errorf("invalid address %q", s)
	}
	addr := common.HexToAddress(s)
	return &addr, nil
}

func bigIntToHexQuantity(v *big.Int) string {
	if v == nil || v.Sign() == 0 {
		return "0x0"
	}
	return "0x" + v.Text(16)
}

func toChainsNetworkConfig(n shared.Network) (chains.NetworkConfig, error) {
	name := strings.ToLower(strings.TrimSpace(n.Name))
	chainHex := strings.ToLower(strings.TrimSpace(n.ChainIdHex))
	explorer := strings.TrimSpace(n.Explorer)
	entryPoint := strings.TrimSpace(n.EntryPoint)

	if name == "" {
		return chains.NetworkConfig{}, fmt.Errorf("network.name is required")
	}
	if chainHex == "" {
		return chains.NetworkConfig{}, fmt.Errorf("network.chainIdHex is required")
	}
	if !strings.HasPrefix(chainHex, "0x") {
		chainHex = "0x" + chainHex
	}

	// Convert RPC list
	rpcs := make([]chains.RPC, 0, len(n.Rpcs))
	for _, r := range n.Rpcs {
		rpcUrl := strings.TrimSpace(r.Url)
		wss := strings.TrimSpace(r.Wss)
		rpcs = append(rpcs, chains.RPC{
			Name: strings.TrimSpace(r.Name),
			URL:  rpcUrl,
			WSS:  wss,
		})
	}

	// Legacy fallback: rpcUrl -> first RPC entry
	if len(rpcs) == 0 {
		legacyURL := strings.TrimSpace(n.RpcUrl)
		if legacyURL != "" {
			rpcs = []chains.RPC{
				{Name: "Custom", URL: legacyURL},
			}
		}
	}

	if len(rpcs) == 0 {
		return chains.NetworkConfig{}, fmt.Errorf("network.rpcs is required")
	}

	chainID := uint64(0)
	if n.ChainId > 0 {
		chainID = uint64(n.ChainId)
	}

	return chains.NetworkConfig{
		Name:       name,
		ChainID:    chainID,
		ChainIDHex: chainHex,
		Explorer:   explorer,
		EntryPoint: entryPoint,
		RPCs:       rpcs,
	}, nil
}

func debugQuantumAuthSig(userOpHash [32]byte, sigBlob []byte) (uint8, []byte, []byte, []byte, common.Address, error) {
	// Unpack abi.encode(uint8, bytes, bytes, bytes)
	args := abi.Arguments{
		{Type: abi.Type{T: abi.UintTy, Size: 8}}, // uint8
		{Type: abi.Type{T: abi.BytesTy}},         // bytes
		{Type: abi.Type{T: abi.BytesTy}},         // bytes
		{Type: abi.Type{T: abi.BytesTy}},         // bytes
	}

	out, err := args.Unpack(sigBlob)
	if err != nil {
		return 0, nil, nil, nil, common.Address{}, fmt.Errorf("unpack sigBlob: %w", err)
	}

	mode := out[0].(uint8)
	sig1 := out[1].([]byte)
	sig2 := out[2].([]byte)
	tpmSig := out[3].([]byte)

	// Contract uses ethHash = toEthSignedMessageHash(userOpHash)
	ethHash := ethSignedHash(userOpHash[:]) // 32 bytes

	// Recover signer of sig1 (go-ethereum expects v=0/1 for SigToPub)
	recovered := common.Address{}
	if len(sig1) == 65 {
		s := make([]byte, 65)
		copy(s, sig1)
		if s[64] >= 27 { // convert 27/28 -> 0/1 for SigToPub
			s[64] -= 27
		}
		pub, err := crypto.SigToPub(ethHash, s)
		if err != nil {
			return mode, sig1, sig2, tpmSig, common.Address{}, fmt.Errorf("SigToPub(sig1): %w", err)
		}
		recovered = crypto.PubkeyToAddress(*pub)
	}

	return mode, sig1, sig2, tpmSig, recovered, nil
}
