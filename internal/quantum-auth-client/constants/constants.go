package constants

const (
	AppName            = "quantumauth"
	ContractFile       = "contract.json"
	DeviceFileName     = "device_wallet.json"
	WalletFile         = "wallet.json"
	ClientIdentityFile = "client_identity.json"
	AssetsFile         = "assets.json"

	SchemaV1      = 1
	FilePerm      = 0o600
	DirectoryPerm = 0o700

	NativeAddr = "0x0000000000000000000000000000000000000000"

	// AAD const for user wallet
	AADConstant = "quantumauth:ethwallet:v1"

	// Scope the sealed DEK so it can’t be mixed with other sealed blobs.
	SealerLabel = "quantumauth:ethdevice:dek:v1"

	// AAD for payload encryption (must match on decrypt).
	PayloadAAD = "quantumauth:ethdevice:payload:v1"

	NetworksFile = "networks.json"
)
