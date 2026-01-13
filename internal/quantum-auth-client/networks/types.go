package networks

import (
	"encoding/json"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"
	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/constants"
)

type Store struct {
	Schema   int                             `json:"schema"`
	Networks map[string]chains.NetworkConfig `json:"networks"` // key = normalized name
}

type rpcReq struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func NewEmptyStore() Store {
	return Store{
		Schema:   constants.SchemaV1,
		Networks: map[string]chains.NetworkConfig{},
	}
}
