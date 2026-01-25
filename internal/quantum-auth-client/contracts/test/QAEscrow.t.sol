// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

import {QAEscrow} from "../contracts/QAEscrow.sol";
import {MockUSDC} from "./MockUSDC.sol";

contract QAEscrowTest is Test {
    MockUSDC usdc;
    QAEscrow escrow;

    // actors
    address merchant = address(0xBEEF);
    address buyer    = address(0xCAFE);

    // backend signer keypair (Foundry controlled)
    uint256 signerPk;
    address signerAddr;

    // app/order IDs (bytes32) using UUID->bytes32 style:
    // 16 zero bytes + 16 UUID bytes
    bytes32 appId;
    bytes32 orderId;

    function setUp() public {
        // Deterministic backend signer
        signerPk = 0xA11CE;
        signerAddr = vm.addr(signerPk);

        usdc = new MockUSDC();
        escrow = new QAEscrow(address(usdc), signerAddr);

        // Grant roles: deployer is msg.sender (this test contract)
        // In your finalized contract, deployer should have admin roles already.

        // Register app owner
        appId = bytes32(0); // will set below
        appId = uuidToBytes32(hex"00112233445566778899aabbccddeeff"); // fake "UUID bytes"

        vm.prank(address(this));
        escrow.setAppOwner(appId, merchant);

        // Fund merchant & buyer with USDC
        usdc.mint(merchant, 1_000_000e6);
        usdc.mint(buyer, 1_000_000e6);
    }

    // ----------------------------
    // Helpers
    // ----------------------------

    // Converts 16 bytes "uuid bytes" into bytes32 = 0x00..00 || uuid16
    function uuidToBytes32(bytes16 u) internal pure returns (bytes32 out) {
        out = bytes32(0);
        assembly {
            // place 16 bytes into the low 16 bytes of bytes32
            out := or(out, u)
        }
        // BUT: u is bytes16 already in low 16 bytes; bytes32(out) is 0..0 || u.
        // That's what we want.
    }

    // EIP-712 digest that matches the Solidity contract:
    // _hashTypedDataV4(keccak256(abi.encode(TYPEHASH, ...)))
    function termsDigest(
        bytes32 _appId,
        bytes32 _orderId,
        address _buyer,
        uint256 amount,
        uint64 delaySeconds,
        uint64 expiresAt
    ) internal view returns (bytes32) {
        bytes32 typeHash = escrow.ESCROW_TERMS_TYPEHASH();

        bytes32 structHash = keccak256(
            abi.encode(
                typeHash,
                _appId,
                _orderId,
                _buyer,
                amount,
                delaySeconds,
                expiresAt
            )
        );

        // Domain separator is internal in OZ EIP712, but exposed via _domainSeparatorV4().
        // Your contract doesn't expose it, so we replicate domain hashing using the same parameters:
        // name="QAEscrow", version="1", chainId, verifyingContract
        bytes32 domainTypeHash = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
        bytes32 domainSeparator = keccak256(
            abi.encode(
                domainTypeHash,
                keccak256(bytes("QAEscrow")),
                keccak256(bytes("1")),
                block.chainid,
                address(escrow)
            )
        );

        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    // ----------------------------
    // Tests
    // ----------------------------

    function testStakeDepositClaimHappyPath() public {
        // Merchant stakes 100 USDC
        uint256 stakeAmt = 100e6;

        vm.startPrank(merchant);
        usdc.approve(address(escrow), stakeAmt);
        escrow.stake(appId, stakeAmt);
        vm.stopPrank();

        // Build terms
        orderId = uuidToBytes32(hex"ffeeddccbbaa99887766554433221100");
        uint256 amount = 10e6;
        uint64 delay = 7 days;
        uint64 expiresAt = uint64(block.timestamp + 10 minutes);

        // Backend signs digest
        bytes32 digest = termsDigest(appId, orderId, buyer, amount, delay, expiresAt);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Buyer deposits
        vm.startPrank(buyer);
        usdc.approve(address(escrow), amount);

        QAEscrow.EscrowTerms memory t = QAEscrow.EscrowTerms({
            appId: appId,
            orderId: orderId,
            buyer: buyer,
            amount: amount,
            delaySeconds: delay,
            expiresAt: expiresAt
        });

        escrow.depositUsdc(t, sig);
        vm.stopPrank();

        // Too early to claim
        vm.prank(merchant);
        vm.expectRevert(bytes("too early"));
        escrow.claim(appId, orderId);

        // Warp past delay and claim
        vm.warp(block.timestamp + 7 days + 1);

        uint256 beforeBal = usdc.balanceOf(merchant);

        vm.prank(merchant);
        escrow.claim(appId, orderId);

        uint256 afterBal = usdc.balanceOf(merchant);
        assertEq(afterBal - beforeBal, amount);
    }

    function testCapacityEnforced() public {
        // stake only 5 USDC
        vm.startPrank(merchant);
        usdc.approve(address(escrow), 5e6);
        escrow.stake(appId, 5e6);
        vm.stopPrank();

        // try deposit 10 USDC -> should revert over capacity
        orderId = uuidToBytes32(hex"11111111111111111111111111111111");
        uint256 amount = 10e6;
        uint64 delay = 7 days;
        uint64 expiresAt = uint64(block.timestamp + 10 minutes);

        bytes32 digest = termsDigest(appId, orderId, buyer, amount, delay, expiresAt);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.startPrank(buyer);
        usdc.approve(address(escrow), amount);

        QAEscrow.EscrowTerms memory t = QAEscrow.EscrowTerms({
            appId: appId,
            orderId: orderId,
            buyer: buyer,
            amount: amount,
            delaySeconds: delay,
            expiresAt: expiresAt
        });

        vm.expectRevert(bytes("over capacity"));
        escrow.depositUsdc(t, sig);

        vm.stopPrank();
    }

    function testDisputeAndSplitResolve() public {
        // stake 100, deposit 10
        vm.startPrank(merchant);
        usdc.approve(address(escrow), 100e6);
        escrow.stake(appId, 100e6);
        vm.stopPrank();

        orderId = uuidToBytes32(hex"22222222222222222222222222222222");
        uint256 amount = 10e6;
        uint64 delay = 7 days;
        uint64 expiresAt = uint64(block.timestamp + 10 minutes);

        bytes32 digest = termsDigest(appId, orderId, buyer, amount, delay, expiresAt);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.startPrank(buyer);
        usdc.approve(address(escrow), amount);

        QAEscrow.EscrowTerms memory t = QAEscrow.EscrowTerms({
            appId: appId,
            orderId: orderId,
            buyer: buyer,
            amount: amount,
            delaySeconds: delay,
            expiresAt: expiresAt
        });

        escrow.depositUsdc(t, sig);

        // open dispute
        escrow.openDispute(appId, orderId);
        vm.stopPrank();

        // resolve split: refund buyer 4 USDC, merchant gets 6
        uint256 buyerRefund = 4e6;

        uint256 buyerBefore = usdc.balanceOf(buyer);
        uint256 merchBefore = usdc.balanceOf(merchant);

        // test contract has ARBITRATOR_ROLE by default in your finalized contract;
        // if not, you'll need to grant it in setUp.
        escrow.resolveDispute(appId, orderId, true, buyerRefund);

        uint256 buyerAfter = usdc.balanceOf(buyer);
        uint256 merchAfter = usdc.balanceOf(merchant);

        assertEq(buyerAfter - buyerBefore, buyerRefund);
        assertEq(merchAfter - merchBefore, amount - buyerRefund);
    }
}
