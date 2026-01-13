// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

error Boom();

contract Reverter {
    function boom() external pure {
        revert Boom();
    }
}