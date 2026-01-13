// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { TPMVerifierSecp256k1 } from "../contracts/TPMVerifierSecp256k1.sol";
import { QuantumAuthAccountHarness } from "./QuantumAuthAccountHarness.sol";

import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { ITPMVerifier } from "../contracts/interfaces/ITPMVerifier.sol";

contract QuantumAuthAccountPolicyTest is Test {
    using MessageHashUtils for bytes32;

    uint8 internal constant MODE_NORMAL = 0;
    uint8 internal constant MODE_RECOVERY = 1;

    uint256 internal constant EOA1_SK = 0xA11CE;
    uint256 internal constant EOA2_SK = 0xB0B;

    address internal eoa1;
    address internal eoa2;
    address internal dummyEntryPoint;

    function setUp() public {
        eoa1 = vm.addr(EOA1_SK);
        eoa2 = vm.addr(EOA2_SK);
        dummyEntryPoint = address(0x1);
    }

    function keyIdFromAddress(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function sigRaw(uint256 sk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, digest);
        return abi.encodePacked(r, s, v);
    }

    function sigEthSigned(uint256 sk, bytes32 userOpHash) internal pure returns (bytes memory) {
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function emptyUserOp(address sender, bytes memory signature) internal pure returns (PackedUserOperation memory op) {
        op.sender = sender;
        op.nonce = 0;
        op.initCode = hex"";
        op.callData = hex"";
        op.accountGasLimits = bytes32(0);
        op.preVerificationGas = 0;
        op.gasFees = bytes32(0);
        op.paymasterAndData = hex"";
        op.signature = signature;
    }

    /// @dev Deployer helper for policy tests (uses Harness to expose _validateSignature).
    function deployAccount(uint256 tpmIndex)
    internal
    returns (
        QuantumAuthAccountHarness account,
        TPMVerifierSecp256k1 verifier,
        bytes32 tpmKeyId
    )
    {
        verifier = new TPMVerifierSecp256k1();

        address tpmAddr = (tpmIndex == 0) ? eoa1 : eoa2;
        tpmKeyId = keyIdFromAddress(tpmAddr);

        account = new QuantumAuthAccountHarness(
            IEntryPoint(dummyEntryPoint),
            eoa1,
            eoa2,
            ITPMVerifier(address(verifier)),
            tpmKeyId
        );
    }

    function test_MODE_NORMAL_passesWithEOA1AndTPM() public {
        (QuantumAuthAccountHarness account, ,) = deployAccount(0);

        bytes32 userOpHash = keccak256(bytes("op:normal:eoa1"));

        bytes memory tpmSig = sigRaw(EOA1_SK, userOpHash);
        bytes memory eoa1Sig = sigEthSigned(EOA1_SK, userOpHash);

        bytes memory bundle = abi.encode(MODE_NORMAL, eoa1Sig, bytes(""), tpmSig);
        PackedUserOperation memory op = emptyUserOp(address(account), bundle);

        uint256 res = account.exposedValidateSignature(op, userOpHash);
        assertEq(res, 0);
    }

    function test_MODE_NORMAL_passesWithEOA2AndTPM() public {
        (QuantumAuthAccountHarness account, ,) = deployAccount(1);

        bytes32 userOpHash = keccak256(bytes("op:normal:eoa2"));

        bytes memory tpmSig = sigRaw(EOA2_SK, userOpHash);
        bytes memory eoa2Sig = sigEthSigned(EOA2_SK, userOpHash);

        bytes memory bundle = abi.encode(MODE_NORMAL, bytes(""), eoa2Sig, tpmSig);
        PackedUserOperation memory op = emptyUserOp(address(account), bundle);

        uint256 res = account.exposedValidateSignature(op, userOpHash);
        assertEq(res, 0);
    }

    function test_MODE_NORMAL_failsWithEOA1Only_noTPM() public {
        (QuantumAuthAccountHarness account, ,) = deployAccount(0);

        bytes32 userOpHash = keccak256(bytes("op:normal:no-tpm"));

        bytes memory eoa1Sig = sigEthSigned(EOA1_SK, userOpHash);

        bytes memory bundle = abi.encode(MODE_NORMAL, eoa1Sig, bytes(""), bytes(""));
        PackedUserOperation memory op = emptyUserOp(address(account), bundle);

        uint256 res = account.exposedValidateSignature(op, userOpHash);
        assertEq(res, 1);
    }

    function test_MODE_RECOVERY_passesWithEOA1AndEOA2_noTPM() public {
        (QuantumAuthAccountHarness account, ,) = deployAccount(0);

        bytes32 userOpHash = keccak256(bytes("op:recovery:2eoa"));

        bytes memory sig1 = sigEthSigned(EOA1_SK, userOpHash);
        bytes memory sig2 = sigEthSigned(EOA2_SK, userOpHash);

        bytes memory bundle = abi.encode(MODE_RECOVERY, sig1, sig2, bytes(""));
        PackedUserOperation memory op = emptyUserOp(address(account), bundle);

        uint256 res = account.exposedValidateSignature(op, userOpHash);
        assertEq(res, 0);
    }

    function test_MODE_RECOVERY_failsWithOnlyOneEOA() public {
        (QuantumAuthAccountHarness account, ,) = deployAccount(0);

        bytes32 userOpHash = keccak256(bytes("op:recovery:1eoa"));

        bytes memory sig1 = sigEthSigned(EOA1_SK, userOpHash);

        bytes memory bundle = abi.encode(MODE_RECOVERY, sig1, bytes(""), bytes(""));
        PackedUserOperation memory op = emptyUserOp(address(account), bundle);

        uint256 res = account.exposedValidateSignature(op, userOpHash);
        assertEq(res, 1);
    }

    function test_MODE_NORMAL_fails_whenBothEOASigsEmpty_evenIfTPMPresent() public {
        (QuantumAuthAccountHarness account, ,) = deployAccount(0);

        bytes32 userOpHash = keccak256(bytes("op:normal:both-empty"));

        bytes memory tpmSig = sigRaw(EOA1_SK, userOpHash);
        bytes memory bundle = abi.encode(MODE_NORMAL, bytes(""), bytes(""), tpmSig);

        PackedUserOperation memory op = emptyUserOp(address(account), bundle);

        uint256 res = account.exposedValidateSignature(op, userOpHash);
        assertEq(res, 1);
    }

    function test_MODE_RECOVERY_fails_whenSig1Empty() public {
        (QuantumAuthAccountHarness account, ,) = deployAccount(0);

        bytes32 userOpHash = keccak256(bytes("op:recovery:sig1-empty"));

        bytes memory sig2 = sigEthSigned(EOA2_SK, userOpHash);
        bytes memory bundle = abi.encode(MODE_RECOVERY, bytes(""), sig2, bytes(""));

        PackedUserOperation memory op = emptyUserOp(address(account), bundle);

        uint256 res = account.exposedValidateSignature(op, userOpHash);
        assertEq(res, 1);
    }
}
