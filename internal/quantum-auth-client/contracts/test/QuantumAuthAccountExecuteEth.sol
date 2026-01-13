// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";


import { QuantumAuthAccount } from "../contracts/account/QuantumAuthAccount.sol";
import { TPMVerifierSecp256k1 } from "../contracts/TPMVerifierSecp256k1.sol";

import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { ITPMVerifier } from "../contracts/interfaces/ITPMVerifier.sol";

// Simple receiver to accept ETH
contract EthReceiver {
    event Got(address indexed from, uint256 amount);
    receive() external payable {
        emit Got(msg.sender, msg.value);
    }
}

contract QuantumAuthAccountExecuteEthTest is Test {
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

    function deployAccount(uint256 tpmIndex) internal returns (QuantumAuthAccount account) {
        TPMVerifierSecp256k1 verifier = new TPMVerifierSecp256k1();

        address tpmAddr = (tpmIndex == 0) ? eoa1 : eoa2;
        bytes32 tpmKeyId = keyIdFromAddress(tpmAddr);

        account = new QuantumAuthAccount(
            IEntryPoint(dummyEntryPoint),
            eoa1,
            eoa2,
            ITPMVerifier(address(verifier)),
            tpmKeyId
        );
    }

    function test_execute_canSendETH_whenCalledByEntryPoint() public {
        QuantumAuthAccount account = deployAccount(0);
        EthReceiver recv = new EthReceiver();

        vm.deal(address(account), 1 ether);

        uint256 beforeRecv = address(recv).balance;
        uint256 beforeAcct = address(account).balance;

        vm.prank(dummyEntryPoint);
        account.execute(address(recv), 0.2 ether, "");

        assertEq(address(recv).balance, beforeRecv + 0.2 ether);
        assertEq(address(account).balance, beforeAcct - 0.2 ether);
    }

    function test_execute_reverts_ifNotEntryPoint() public {
        QuantumAuthAccount account = deployAccount(0);
        EthReceiver recv = new EthReceiver();

        vm.deal(address(account), 1 ether);

        vm.expectRevert(QuantumAuthAccount.OnlyEntryPoint.selector);
        account.execute(address(recv), 0.1 ether, "");
    }

    function test_receive_allowsFunding() public {
        QuantumAuthAccount account = deployAccount(0);

        vm.deal(address(this), 1 ether);

        uint256 beforeAcct = address(account).balance;

        (bool ok,) = payable(address(account)).call{ value: 0.3 ether }("");
        assertTrue(ok);

        assertEq(address(account).balance, beforeAcct + 0.3 ether);
    }
}
