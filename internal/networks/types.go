package networks

import "github.com/quantumauth-io/quantum-auth-client/internal/constants"

type Network struct {
	Name       string `json:"name"`
	ChainId    int64  `json:"chainId,omitempty"`
	ChainIdHex string `json:"chainIdHex"`
	Explorer   string `json:"explorer,omitempty"`

	// This is what the UI edits today.
	RpcUrl string `json:"rpcUrl,omitempty"`

	// Optional future-proofing (not required by UI yet)
	EntryPoint string `json:"entryPoint,omitempty"`
}

type Store struct {
	Schema   int                `json:"schema"`
	Networks map[string]Network `json:"networks"` // key = normalized name
}

func NewEmptyStore() Store {
	return Store{
		Schema:   constants.SchemaV1,
		Networks: map[string]Network{},
	}
}
