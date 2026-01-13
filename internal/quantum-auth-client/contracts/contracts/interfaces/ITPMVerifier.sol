// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Verifies TPM-originated signatures for a given key.
/// The verifier can be implemented in different ways:
/// - pure Solidity (if feasible)
/// - precompile wrapper (best on chains that support it)
/// - zk/verifier-based proof (advanced)
interface ITPMVerifier {
    /// @param keyId A unique identifier for the TPM key (could be a hash of the public key, or a handle agreed by your system)
    /// @param messageHash The digest that was signed (we’ll use the ERC-4337 userOpHash)
    /// @param signature TPM signature bytes (format depends on your TPM signing scheme: DER/ECDSA, RSASSA, etc.)
    /// @return ok True if signature is valid for keyId over messageHash
    function verify(
        bytes32 keyId,
        bytes32 messageHash,
        bytes calldata signature
    ) external view returns (bool ok);
}