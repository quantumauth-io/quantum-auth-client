package shared

import "github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/chains"

type Network struct {
	Name       string `json:"name"`
	ChainId    int64  `json:"chainId,omitempty"`
	ChainIdHex string `json:"chainIdHex"`
	Explorer   string `json:"explorer,omitempty"`
	EntryPoint string `json:"entryPoint,omitempty"`
	Rpcs       []RPC  `json:"rpcs,omitempty"`
	RpcUrl     string `json:"rpcUrl,omitempty"`
}

type RPC struct {
	Name string `json:"name"`
	Url  string `json:"url"`
	Wss  string `json:"wss"`
}

type RemoveNetworkReq struct {
	ChainIdHex string `json:"chainIdHex"`
}

type UpdateNetworkReq struct {
	ChainIdHex string             `json:"chainIdHex"`
	Patch      UpdateNetworkPatch `json:"patch"`
}

type UpdateNetworkPatch struct {
	Explorer   *string `json:"explorer,omitempty"`
	EntryPoint *string `json:"entryPoint,omitempty"`

	// New model
	Rpcs *[]chains.RPC `json:"rpcs,omitempty"`

	// Backward compat (temporary)
	RpcUrl *string `json:"rpcUrl,omitempty"`
}

type AddNetworkReq struct {
	Network Network `json:"network"`
}

type NetworkMetadataReq struct {
	RpcUrl string `json:"rpcUrl"`
}

type NetworkMetadataOut struct {
	RpcUrl         string `json:"rpcUrl"`
	ChainIdHex     string `json:"chainIdHex"`
	ChainId        int64  `json:"chainId"`
	Name           string `json:"name,omitempty"`
	Explorer       string `json:"explorer,omitempty"`
	EntryPoint     string `json:"entryPoint,omitempty"`
	ClientVersion  string `json:"clientVersion,omitempty"`
	LatestBlockHex string `json:"latestBlockHex,omitempty"`
}
