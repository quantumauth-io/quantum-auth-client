// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ITPMVerifier } from "./interfaces/ITPMVerifier.sol";

/// @notice Stateless secp256k1 verifier.
/// keyId is interpreted as the expected signer address (low 20 bytes).
/// signature must be 65 bytes: r(32) || s(32) || v(1).
contract TPMVerifierSecp256k1 is ITPMVerifier {
    error BadSigLength();
    error InvalidSig();
    error InvalidKeyId();

    function verify(
        bytes32 keyId,
        bytes32 messageHash,
        bytes calldata signature
    ) external pure override returns (bool ok) {
        address expected = address(uint160(uint256(keyId)));
        if (expected == address(0)) return false;

        if (signature.length != 65) return false;

        (bytes32 r, bytes32 s, uint8 v) = _splitSig(signature);
        address recovered = ecrecover(messageHash, v, r, s);
        if (recovered == address(0)) return false;
        return recovered == expected;
    }

    function _splitSig(bytes calldata sig)
    internal
    pure
    returns (bytes32 r, bytes32 s, uint8 v)
    {
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        // don’t revert; normalize caller already checked length
        if (v != 27 && v != 28) v = 0;
    }

    function _keyIdToAddress(bytes32 keyId) internal pure returns (address) {
        return address(uint160(uint256(keyId)));
    }

}
