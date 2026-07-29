// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IInflationVaultAsset {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Deliberately vulnerable example for CP-122.
contract VulnerableInflationVault {
    IInflationVaultAsset public immutable asset;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(IInflationVaultAsset asset_) {
        asset = asset_;
    }

    function totalAssets() public view returns (uint256) {
        // Direct transfers change this value without minting any shares.
        return asset.balanceOf(address(this));
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        uint256 supply = totalSupply;
        shares = supply == 0 ? assets : assets * totalSupply / totalAssets();
        require(shares != 0, "ZERO_SHARES");

        require(asset.transferFrom(msg.sender, address(this), assets), "TRANSFER_FAILED");
        _mint(receiver, shares);
    }

    function withdraw(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = assets * totalSupply / totalAssets();
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        require(asset.transfer(receiver, assets), "TRANSFER_FAILED");
    }

    function _mint(address receiver, uint256 shares) internal {
        balanceOf[receiver] += shares;
        totalSupply += shares;
    }
}
