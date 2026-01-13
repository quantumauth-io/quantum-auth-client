// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { QuantumAuthAccount } from "../contracts/account/QuantumAuthAccount.sol";
import { TPMVerifierSecp256k1 } from "../contracts/TPMVerifierSecp256k1.sol";

import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { ITPMVerifier } from "../contracts/interfaces/ITPMVerifier.sol";

import { Receiver } from "./Receiver.sol";
import { Reverter, Boom } from "./Reverter.sol";

import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract QuantumAuthAccountHarness is QuantumAuthAccount {
    constructor(
        IEntryPoint entryPoint_,
        address eoa1_,
        address eoa2_,
        ITPMVerifier tpmVerifier_,
        bytes32 tpmKeyId_
    ) QuantumAuthAccount(entryPoint_, eoa1_, eoa2_, tpmVerifier_, tpmKeyId_) {}

    function exposedValidateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external view returns (uint256) {
        return _validateSignature(userOp, userOpHash);
    }
}

contract QuantumAuthAccountExecuteTest is Test {
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

    function deployAccount(uint256 tpmIndex) internal returns (
        QuantumAuthAccountHarness account,
        TPMVerifierSecp256k1 verifier,
        bytes32 tpmKeyId
    ) {
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

    function test_execute_reverts_ifCallerNotEntryPoint() public {
        (QuantumAuthAccountHarness account,,) = deployAccount(0);

        vm.expectRevert(QuantumAuthAccount.OnlyEntryPoint.selector);
        account.execute(eoa1, 0, hex"");
    }

    function test_execute_works_whenCalledByEntryPoint() public {
        (QuantumAuthAccountHarness account,,) = deployAccount(0);

        Receiver recv = new Receiver();

        bytes memory data = abi.encodeCall(Receiver.ping, (123));

        vm.prank(dummyEntryPoint);
        account.execute(address(recv), 0, data);

        assertEq(recv.last(), 123);
    }

    function test_execute_bubblesRevertDataFromTarget() public {
        (QuantumAuthAccountHarness account,,) = deployAccount(0);

        Reverter rev = new Reverter();
        bytes memory data = abi.encodeCall(Reverter.boom, ());

        vm.prank(dummyEntryPoint);
        vm.expectRevert(Boom.selector);
        account.execute(address(rev), 0, data);
    }

    function test_validateSignature_revertsOnInvalidMode() public {
        (QuantumAuthAccountHarness account,,) = deployAccount(0);

        bytes32 userOpHash = keccak256(bytes("op:badmode"));
        bytes memory bundle = abi.encode(uint8(9), bytes(""), bytes(""), bytes(""));

        PackedUserOperation memory op = emptyUserOp(address(account), bundle);

        vm.expectRevert(QuantumAuthAccount.InvalidMode.selector);
        account.exposedValidateSignature(op, userOpHash);
    }

    function test_MODE_NORMAL_fails_whenTPMSignatureWrong() public {
        (QuantumAuthAccountHarness account, , ) = deployAccount(0);

        bytes32 userOpHash = keccak256(bytes("op:normal:bad-tpm"));

        // Valid EOA1 signature (prefixed)
        bytes memory eoa1Sig = sigEthSigned(EOA1_SK, userOpHash);

        // Wrong TPM signature: signed by EOA2 key, but keyId expects eoa1
        bytes memory badTpmSig = sigRaw(EOA2_SK, userOpHash);

        bytes memory bundle = abi.encode(MODE_NORMAL, eoa1Sig, bytes(""), badTpmSig);
        PackedUserOperation memory op = emptyUserOp(address(account), bundle);

        uint256 res = account.exposedValidateSignature(op, userOpHash);
        assertEq(res, 1);
    }

    function test_MODE_RECOVERY_fails_whenSig2Empty() public {
        (QuantumAuthAccountHarness account,,) = deployAccount(0);

        bytes32 userOpHash = keccak256(bytes("op:recovery:empty-sig2"));

        bytes memory sig1 = sigEthSigned(EOA1_SK, userOpHash);

        bytes memory bundle = abi.encode(MODE_RECOVERY, sig1, bytes(""), bytes(""));
        PackedUserOperation memory op = emptyUserOp(address(account), bundle);

        uint256 res = account.exposedValidateSignature(op, userOpHash);
        assertEq(res, 1);
    }

    function test_MODE_NORMAL_fails_whenNoEOASigs() public {
        (QuantumAuthAccountHarness account,,) = deployAccount(0);

        bytes32 userOpHash = keccak256(bytes("op:normal:no-eoa"));
        bytes memory bundle = abi.encode(uint8(0), bytes(""), bytes(""), bytes("deadbeef")); // TPM garbage
        PackedUserOperation memory op = emptyUserOp(address(account), bundle);

        uint256 res = account.exposedValidateSignature(op, userOpHash);
        assertEq(res, 1);
    }

    function test_MODE_RECOVERY_fails_whenSig1Empty() public {
        (QuantumAuthAccountHarness account,,) = deployAccount(0);

        bytes32 userOpHash = keccak256(bytes("op:recovery:empty-sig1"));
        bytes memory sig2 = sigEthSigned(EOA2_SK, userOpHash);

        bytes memory bundle = abi.encode(uint8(1), bytes(""), sig2, bytes(""));
        PackedUserOperation memory op = emptyUserOp(address(account), bundle);

        uint256 res = account.exposedValidateSignature(op, userOpHash);
        assertEq(res, 1);
    }

    function test_MODE_NORMAL_fails_whenEOASigWrongSigner() public {
        (QuantumAuthAccountHarness account,,) = deployAccount(0);

        bytes32 userOpHash = keccak256(bytes("op:normal:wrong-eoa"));

        // Put an EOA1 slot signature signed by EOA2 -> should fail EOA check
        bytes memory wrongSig = sigEthSigned(EOA2_SK, userOpHash);

        // TPM also wrong/empty to ensure overall fail
        bytes memory bundle = abi.encode(uint8(0), wrongSig, bytes(""), bytes(""));
        PackedUserOperation memory op = emptyUserOp(address(account), bundle);

        uint256 res = account.exposedValidateSignature(op, userOpHash);
        assertEq(res, 1);
    }


}
