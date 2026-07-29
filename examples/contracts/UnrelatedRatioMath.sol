// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Similar proportional arithmetic, but this is not a share vault.
contract UnrelatedRatioMath {
    uint256 public totalSupply;
    uint256 public totalAssets;

    function quote(uint256 amount) external view returns (uint256) {
        return amount * totalSupply / totalAssets;
    }

    function updateTotals(uint256 supply, uint256 assets) external {
        totalSupply = supply;
        totalAssets = assets;
    }
}
