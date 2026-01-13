// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { TPMVerifierSecp256k1 } from "../contracts/TPMVerifierSecp256k1.sol";

contract TPMVerifierSecp256k1Test is Test {
    TPMVerifierSecp256k1 v;

    uint256 constant SK1 = 0xA11CE;
    address a1;

    function setUp() public {
        v = new TPMVerifierSecp256k1();
        a1 = vm.addr(SK1);
    }

    function keyIdFromAddress(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function sigRaw(uint256 sk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(sk, digest);
        return abi.encodePacked(r, s, vv);
    }

    function test_verify_returnsFalse_onBadSigLength() public view {
        bytes32 keyId = keyIdFromAddress(a1);
        bytes32 h = keccak256("x");
        bytes memory sig = hex"1234"; // too short

        bool ok = v.verify(keyId, h, sig);
        assertFalse(ok);
    }

    function test_verify_returnsFalse_onInvalidKeyId() public view {
        bytes32 h = keccak256("x");
        bytes memory sig = sigRaw(SK1, h);

        bool ok = v.verify(bytes32(0), h, sig);
        assertFalse(ok);
    }

    function test_verify_returnsFalse_onInvalidSig() public view {
        bytes32 keyId = keyIdFromAddress(a1);
        bytes32 h = keccak256("x");

        // Signed by a different key, but keyId expects a1
        bytes memory sigWrong = sigRaw(0xB0B, h);

        bool ok = v.verify(keyId, h, sigWrong);
        assertFalse(ok);
    }

    function test_verify_ok_trueOnValidSig() public view {
        bytes32 keyId = keyIdFromAddress(a1);
        bytes32 h = keccak256("x");
        bytes memory sig = sigRaw(SK1, h);

        bool ok = v.verify(keyId, h, sig);
        assertTrue(ok);
    }

    function test_verify_returnsFalse_onBadV() public view {
        bytes32 keyId = keyIdFromAddress(a1);
        bytes32 h = keccak256("badv");

        bytes memory sig = sigRaw(SK1, h);

        // Set v to an invalid value (not 0/1 or 27/28)
        sig[64] = bytes1(uint8(5));

        bool ok = v.verify(keyId, h, sig);
        assertFalse(ok);
    }

    function test_verify_returnsFalse_onZeroRecover() public view {
        bytes32 keyId = keyIdFromAddress(a1);
        bytes32 h = keccak256("zerorecover");

        // r=0, s=0, v=27 → ecrecover should return address(0)
        bytes memory sig = new bytes(65);
        sig[64] = bytes1(uint8(27));

        bool ok = v.verify(keyId, h, sig);
        assertFalse(ok);
    }

    function test_verify_returnsFalse_onHighS() public view {
        bytes32 keyId = keyIdFromAddress(a1);
        bytes32 h = keccak256("highs");

        bytes memory sig = sigRaw(SK1, h);

        // Set s to max value to trigger high-s / malleability check if present
        // bytes 32..63 are s
        for (uint256 i = 32; i < 64; i++) sig[i] = 0xFF;

        bool ok = v.verify(keyId, h, sig);
        assertFalse(ok);
    }
}
