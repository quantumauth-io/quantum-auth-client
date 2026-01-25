package txsender

const (
	HexPrefix0x = "0x"
)

// EIP-4337 / AA defaults (sendTransaction)
const (
	UserOpDefaultCallGasLimitUint64         = 250_000
	UserOpDefaultVerificationGasLimitUint64 = 700_000
	UserOpDefaultPreVerificationGasUint64   = 60_000

	EIP1559DefaultMaxPriorityFeeWeiInt64 = 1_500_000_000  // 1.5 gwei
	EIP1559DefaultMaxFeeWeiInt64         = 30_000_000_000 // 30 gwei

	UserOpDefaultMissingFundsWeiInt64 = 0
	UserOpDefaultNonceKeyInt64        = 0
)

// EIP-4337 / AA estimation defaults (estimateSendTransaction)
const (
	UserOpEstimateTmpCallGasLimitUint64         = 1_500_000
	UserOpEstimateTmpVerificationGasLimitUint64 = 1_500_000

	GasEstimateCallGasFallbackUint64         = 250_000
	GasEstimateVerificationGasFallbackUint64 = 700_000

	GasBufferBpsCallGasLimit         = 12_000 // +20%
	GasBufferBpsVerificationGasLimit = 12_500 // +25%
)

// EIP-1559 fee logic constants
const (
	EIP1559MaxFeeBaseFeeMultiplierInt64 = 2
)
