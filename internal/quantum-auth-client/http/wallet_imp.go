package http

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/ethwallet/wtypes"
)

// pickWallet chooses user/device by "from" address.
func (s *Server) pickWallet(from common.Address) (wtypes.Wallet, error) {
	if s.onChain == nil || s.onChain.User == nil || s.onChain.Device == nil {
		return nil, fmt.Errorf("onchain runtime not initialized")
	}
	if from == s.onChain.User.Address() {
		return s.onChain.User, nil
	}
	if from == s.onChain.Device.Address() {
		return s.onChain.Device, nil
	}
	return nil, fmt.Errorf("from address not controlled by this wallet")
}

// ---- EIP-191 personal_sign ----

func eip191HashPersonalMessage(msg []byte) []byte {
	// keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg)
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(msg))
	return crypto.Keccak256([]byte(prefix), msg)
}

// ---- EIP-712 v4 ----

func eip712DigestV4(typedDataJSON string) ([]byte, error) {
	var td apitypes.TypedData
	if err := json.Unmarshal([]byte(typedDataJSON), &td); err != nil {
		return nil, fmt.Errorf("invalid typed data json: %w", err)
	}

	domainSeparator, err := td.HashStruct("EIP712Domain", td.Domain.Map())
	if err != nil {
		return nil, fmt.Errorf("domain hash: %w", err)
	}

	msgHash, err := td.HashStruct(td.PrimaryType, td.Message)
	if err != nil {
		return nil, fmt.Errorf("message hash: %w", err)
	}

	// EIP-712 digest: keccak256("\x19\x01" || domainSeparator || msgHash)
	d := crypto.Keccak256(
		[]byte{0x19, 0x01},
		domainSeparator,
		msgHash,
	)
	if len(d) != 32 {
		return nil, fmt.Errorf("unexpected digest length %d", len(d))
	}
	return d, nil
}

// optional: normalize signature to 0x hex
func sigToHex(sig []byte) string {
	return "0x" + hex.EncodeToString(sig)
}

// optional: if your extension expects 0x + 65 bytes with v=27/28, convert here.
// For now we keep V=0/1 which geth crypto.Sign outputs.
// If needed later:
//   sig, _ = wtypes.SigToV27(sig)
