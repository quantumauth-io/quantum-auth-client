package walletsigner

import (
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

func EIP712DigestV4(typedDataJSON string) ([]byte, error) {
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
