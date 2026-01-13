package http

import "time"

// Generic HTTP / JSON strings
const (
	HTTPErrorMethodNotAllowedText = "method not allowed"
	HTTPErrorInvalidJSONText      = "invalid JSON"
	HTTPErrorBadRequestText       = "bad request"
)

// Common JSON keys
const (
	JSONKeyOK                = "ok"
	JSONKeyData              = "data"
	JSONKeyError             = "error"
	JSONKeyResult            = "result"
	JSONKeyValid             = "valid"
	JSONKeyPaired            = "paired"
	JSONKeyAllowed           = "allowed"
	JSONKeyOrigin            = "origin"
	JSONKeyHeader            = "header"
	JSONKeyToken             = "token"
	JSONKeyChainIDHex        = "chainIdHex"
	JSONKeyCurrentChainIDHex = "currentChainIdHex"
	JSONKeyNetworks          = "networks"
	JSONKeyNotAdded          = "notAdded"
	JSONKeyUnauthorized      = "unauthorized"
)

// Agent + Extension action names / statuses
const (
	ExtensionActionPing             = "ping"
	ExtensionActionRequestChallenge = "request_challenge"

	ExtensionPingResponseMessageKey   = "message"
	ExtensionPingResponseMessageValue = "pong"

	ExtensionApprovalRequiredError = "approval_required"
	ExtensionUnknownActionError    = "unknown action"
)

// Pairing flow constants
const (
	PairingRequestFieldPairID = "pair_id"
	PairingRequestFieldCode   = "code"

	PairingErrorMissingPairIDOrCodeText = "missing pair_id or code"
	PairingErrorPairExpiredText         = "pair expired"
	PairingErrorInvalidCodeText         = "invalid code"

	PairingCodeSHA256SizeBytes = 32
	PairingExchangeTTL         = 60 * time.Second
)

// Transaction receipt constants
const (
	TxReceiptRequestMaxTxHashes = 50

	TxReceiptStatusPendingText   = "pending"
	TxReceiptStatusConfirmedText = "confirmed"
	TxReceiptStatusFailedText    = "failed"

	TxReceiptErrorMissingTxHashText       = "missing txHash/txHashes"
	TxReceiptErrorTooManyTxHashesText     = "too many txHashes (max 50)"
	TxReceiptErrorInvalidTxHashFieldText  = "invalid txHash"
	TxReceiptResponseBlockHexPrefix       = "0x"
	TxReceiptResponseMinedFailureStatus64 = 0 // receipt.Status == 0 => failed
)

// JSON-RPC error codes (EIP-1474 style)
const (
	JSONRPCErrorCodeInvalidRequest = -32600
	JSONRPCErrorCodeMethodNotFound = -32601
	JSONRPCErrorCodeInvalidParams  = -32602
	JSONRPCErrorCodeInternalError  = -32603
)

// Wallet / RPC messages
const (
	WalletRuntimeNotInitializedText     = "wallet runtime not initialized"
	WalletActiveNetworkNotFoundText     = "active network not found"
	WalletEntryPointNotConfiguredText   = "entryPoint not configured"
	WalletBindEntryPointFailedText      = "bind entrypoint failed"
	WalletPackExecuteFailedText         = "pack execute failed"
	WalletGetNonceFailedText            = "getNonce failed"
	WalletGetUserOpHashFailedText       = "getUserOpHash failed"
	WalletUserOpSigningFailedText       = "signing failed"
	WalletTxAuthFailedText              = "tx auth failed"
	WalletHandleOpsFailedText           = "handleOps failed"
	WalletChainIDFetchFailedText        = "failed to get chainId"
	WalletAssetsLoadFailedText          = "failed to load assets"
	WalletNativeBalanceFetchFailedText  = "failed to fetch native balance"
	WalletBalanceFetchFailedText        = "failed to fetch balance"
	WalletInvalidAddressText            = "invalid address"
	WalletInvalidMessageText            = "invalid message"
	WalletInvalidTypedDataText          = "invalid typed data"
	WalletSignFailedText                = "sign failed"
	WalletMissingMethodText             = "missing method"
	WalletMissingChainIDHexText         = "missing chainIdHex"
	WalletSwitchNetworkFailedText       = "failed to switch network"
	WalletLoadContractWalletStoreFailed = "failed to load contract wallet store"
	WalletEthClientNotInitializedText   = "eth client not initialized"
	WalletFailedToLoadAssetsText        = "failed to load assets"
)

// RPC provider names
const (
	EthRPCProviderInfuraName = "Infura"
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

// Encodings / prefixes
const (
	HexPrefix0x = "0x"
)

// Assets / formatting
const (
	NativeAssetSymbolETH   = "ETH"
	NativeAssetNameEther   = "Ether"
	NativeAssetDecimalsETH = 18

	BalanceHumanMaxDecimalsDefault = 6
)

// Placeholder signatures (agent endpoints)
const (
	AgentSignaturePlaceholderHex = "0xTODO"
)
