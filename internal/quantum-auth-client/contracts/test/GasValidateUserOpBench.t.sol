// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { EntryPoint } from "@account-abstraction/contracts/core/EntryPoint.sol";
import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import { QuantumAuthAccount } from "../contracts/account/QuantumAuthAccount.sol";
import { TPMVerifierSecp256k1 } from "../contracts/TPMVerifierSecp256k1.sol";
import { ITPMVerifier } from "../contracts/interfaces/ITPMVerifier.sol";

contract GasValidateUserOpBench is Test {
    using MessageHashUtils for bytes32;

    // Keep these aligned with your contract
    uint8 internal constant MODE_NORMAL = 0;   // TPM + (EOA1 OR EOA2)
    uint8 internal constant MODE_RECOVERY = 1; // EOA1 + EOA2

    // deterministic keys for reproducibility
    uint256 internal constant EOA1_SK = 0xA11CE;
    uint256 internal constant EOA2_SK = 0xB0B;

    address internal eoa1;
    address internal eoa2;

    EntryPoint internal ep;
    TPMVerifierSecp256k1 internal verifier;
    QuantumAuthAccount internal account;

    function setUp() public {
        eoa1 = vm.addr(EOA1_SK);
        eoa2 = vm.addr(EOA2_SK);

        ep = new EntryPoint();
        verifier = new TPMVerifierSecp256k1();

        // Your TPM key id encoding: low 20 bytes = address
        bytes32 tpmKeyId = bytes32(uint256(uint160(eoa1)));

        account = new QuantumAuthAccount(
            IEntryPoint(address(ep)),
            eoa1,
            eoa2,
            ITPMVerifier(address(verifier)),
            tpmKeyId
        );
    }

    function _emptyUserOp(bytes memory signature) internal view returns (PackedUserOperation memory op) {
        op.sender = address(account);
        op.nonce = 0;
        op.initCode = hex"";
        op.callData = hex"";
        op.accountGasLimits = bytes32(0);
        op.preVerificationGas = 0;
        op.gasFees = bytes32(0);
        op.paymasterAndData = hex"";
        op.signature = signature;
    }

    function _sigEthSigned(uint256 sk, bytes32 userOpHash) internal pure returns (bytes memory) {
        bytes32 ethHash = userOpHash.toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function _sigRaw(uint256 sk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// Benchmark “pq” path placeholder:
    /// Today: TPMVerifierSecp256k1.verify(...) acts as your expensive verifier.
    /// Later: swap TPMVerifier to your PQ verifier and keep the same surface.
    function test_gas_validateUserOp_pq() public {
        // MODE_NORMAL: TPM + (EOA1 OR EOA2) — we use EOA1
        // userOpHash must come from EntryPoint for comparability
        bytes memory eoa1Sig;
        bytes memory tpmSig;

        // Build op with a temporary signature (will overwrite after we know userOpHash)
        PackedUserOperation memory op = _emptyUserOp(abi.encode(MODE_NORMAL, bytes(""), bytes(""), bytes("")));
        bytes32 userOpHash = ep.getUserOpHash(op);

        eoa1Sig = _sigEthSigned(EOA1_SK, userOpHash);
        tpmSig  = _sigRaw(EOA1_SK, userOpHash);

        op.signature = abi.encode(MODE_NORMAL, eoa1Sig, bytes(""), tpmSig);

        // Measure validateUserOp (EntryPoint calls this)
        vm.prank(address(ep));
        account.validateUserOp(op, userOpHash, 0);
    }

    /// Benchmark “hybrid” placeholder:
    /// Today: MODE_RECOVERY (EOA1+EOA2) is your multi-sig path.
    /// Later: interpret “hybrid” as PQ + ECDSA in your signature decoding.
    function test_gas_validateUserOp_hybrid() public {
        PackedUserOperation memory op = _emptyUserOp(abi.encode(MODE_RECOVERY, bytes(""), bytes(""), bytes("")));
        bytes32 userOpHash = ep.getUserOpHash(op);

        bytes memory sig1 = _sigEthSigned(EOA1_SK, userOpHash);
        bytes memory sig2 = _sigEthSigned(EOA2_SK, userOpHash);

        op.signature = abi.encode(MODE_RECOVERY, sig1, sig2, bytes(""));

        vm.prank(address(ep));
        account.validateUserOp(op, userOpHash, 0);
    }
}
