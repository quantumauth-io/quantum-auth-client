// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title QAERC20
/// @notice Simple mintable ERC20 for local testing / bindings generation.
/// @dev No EIP-2612 permit by design.
contract QAERC20 is ERC20, Ownable {
    uint8 private immutable _CUSTOM_DECIMALS;

    constructor(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        address owner_
    ) ERC20(name_, symbol_) Ownable(owner_) {
        _CUSTOM_DECIMALS = decimals_;
    }

    function decimals() public view override returns (uint8) {
        return _CUSTOM_DECIMALS;
    }

    /// @notice Mint tokens to an address (owner-only).
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    /// @notice Burn caller's tokens.
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    /// @notice Burn tokens from another address using allowance.
    function burnFrom(address from, uint256 amount) external {
        _spendAllowance(from, msg.sender, amount);
        _burn(from, amount);
    }
}