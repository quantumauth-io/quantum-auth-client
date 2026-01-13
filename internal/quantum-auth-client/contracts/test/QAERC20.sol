// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { QAERC20 } from "../contracts/QAERC20.sol";

contract QAERC20Test is Test {
    address internal owner = address(0xA11CE);
    address internal alice = address(0xB0B);
    address internal bob   = address(0xCAFE);

    QAERC20 internal token;

    function setUp() public {
        vm.prank(owner);
        token = new QAERC20("QA Token", "QA", 6, owner);
    }

    function test_constructor_setsOwnerAndDecimals() public view {
        // owner set via Ownable(owner_)
        assertEq(token.owner(), owner);
        // immutable decimals
        assertEq(token.decimals(), 6);
        // inherited ERC20 metadata
        assertEq(token.name(), "QA Token");
        assertEq(token.symbol(), "QA");
    }

    function test_mint_ownerOnly_mintsAndUpdatesSupply() public {
        vm.prank(owner);
        token.mint(alice, 123);

        assertEq(token.totalSupply(), 123);
        assertEq(token.balanceOf(alice), 123);
    }

    function test_mint_reverts_forNonOwner() public {
        vm.prank(alice);
        vm.expectRevert(); // OwnableUnauthorizedAccount in OZ v5, but selector differs by version
        token.mint(alice, 1);
    }

    function test_burn_burnsCallerTokens() public {
        vm.prank(owner);
        token.mint(alice, 1000);

        vm.prank(alice);
        token.burn(250);

        assertEq(token.balanceOf(alice), 750);
        assertEq(token.totalSupply(), 750);
    }

    function test_burn_reverts_ifInsufficientBalance() public {
        vm.prank(alice);
        vm.expectRevert(); // ERC20InsufficientBalance (OZ v5), but selector differs by version
        token.burn(1);
    }

    function test_burnFrom_spendsAllowance_andBurnsFromAddress() public {
        vm.prank(owner);
        token.mint(alice, 1000);

        // alice approves bob
        vm.prank(alice);
        token.approve(bob, 400);

        // bob burns from alice
        vm.prank(bob);
        token.burnFrom(alice, 300);

        assertEq(token.balanceOf(alice), 700);
        assertEq(token.totalSupply(), 700);
        assertEq(token.allowance(alice, bob), 100);
    }

    function test_burnFrom_reverts_ifAllowanceTooLow() public {
        vm.prank(owner);
        token.mint(alice, 100);

        // alice approves bob for 10 only
        vm.prank(alice);
        token.approve(bob, 10);

        vm.prank(bob);
        vm.expectRevert(); // ERC20InsufficientAllowance (OZ v5)
        token.burnFrom(alice, 11);
    }

    function test_burnFrom_reverts_ifBalanceTooLow_evenWithAllowance() public {
        vm.prank(owner);
        token.mint(alice, 5);

        vm.prank(alice);
        token.approve(bob, 1000);

        vm.prank(bob);
        vm.expectRevert(); // ERC20InsufficientBalance (OZ v5)
        token.burnFrom(alice, 6);
    }
}
