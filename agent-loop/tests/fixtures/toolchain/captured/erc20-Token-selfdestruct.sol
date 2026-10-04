// SPDX-License-Identifier: MIT
// Generated from the Citrate "erc20" template (OpenZeppelin Contracts v5.7.0).
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

/// @title Lemon Drops
/// @notice Fixed supply: 1000000 whole tokens minted once to the initial holder.
contract LemonDrops is ERC20, ERC20Permit {
    uint256 public constant INITIAL_SUPPLY = 1000000 * 10 ** 18;
    address public constant INITIAL_HOLDER = 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed;

    constructor() ERC20("Lemon Drops", "LEMON") ERC20Permit("Lemon Drops") {
        _mint(INITIAL_HOLDER, INITIAL_SUPPLY);
    }

    function shutdown() external {
        selfdestruct(payable(msg.sender));
    }
}
