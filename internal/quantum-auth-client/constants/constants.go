package constants

const (
	AppName        = "io.quantumauth.client"
	ContractFile   = "contract.qa"
	DeviceFileName = "device_wallet.qa"
	WalletFile     = "wallet.qa"
	AssetsFile     = "assets.qa"
	NetworksFile   = "networks.json"
	SchemaV1       = 1
	FilePerm       = 0o600
	DirectoryPerm  = 0o700

	NativeAddr = "0x0000000000000000000000000000000000000000"

	// AAD const for user wallet
	AADConstant = "quantumauth:ethwallet:v1"

	// Scope the sealed DEK so it can’t be mixed with other sealed blobs.
	SealerLabel = "quantumauth:ethdevice:dek:v1"

	// AAD for payload encryption (must match on decrypt).
	PayloadAAD = "quantumauth:ethdevice:payload:v1"

	QAHeaderSigVersion = "1"
)
