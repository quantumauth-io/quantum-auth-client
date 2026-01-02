package http

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
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
	"github.com/ethereum/go-ethereum/crypto"
	utilsEth "github.com/quantumauth-io/quantum-go-utils/ethrpc"
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

func parseChainIDHexToUint64(chainIDHex string) (uint64, string, error) {
	s := strings.TrimSpace(chainIDHex)
	if s == "" {
		return 0, "", fmt.Errorf("missing chainIdHex")
	}

	// normalize 0x + lowercase
	s = strings.ToLower(s)
	if !strings.HasPrefix(s, "0x") {
		// allow user passing "1"
		s = "0x" + s
	}
	s = utilsEth.NormalizeHex0x(s)

	// reject just "0x"
	if s == "0x" {
		return 0, "", fmt.Errorf("invalid chainIdHex")
	}

	// parse base16
	n := new(big.Int)
	_, ok := n.SetString(strings.TrimPrefix(s, "0x"), 16)
	if !ok {
		return 0, "", fmt.Errorf("invalid chainIdHex")
	}
	if n.Sign() <= 0 {
		return 0, "", fmt.Errorf("invalid chainIdHex")
	}
	if n.BitLen() > 64 {
		return 0, "", fmt.Errorf("chainIdHex too large")
	}

	return n.Uint64(), s, nil
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
