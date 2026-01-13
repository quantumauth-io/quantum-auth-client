// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { QuantumAuthAccount } from "../contracts/account/QuantumAuthAccount.sol";
import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { ITPMVerifier } from "../contracts/interfaces/ITPMVerifier.sol";

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