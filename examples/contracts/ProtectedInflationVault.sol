// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IProtectedVaultAsset {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Dead-share initialization prevents a first depositor owning all supply.
contract ProtectedInflationVault {
    uint256 private constant MINIMUM_LIQUIDITY = 1_000;
    address private constant DEAD_SHARES_RECEIVER = address(0xdead);

    IProtectedVaultAsset public immutable asset;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(IProtectedVaultAsset asset_) {
        asset = asset_;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        uint256 supply = totalSupply;
        uint256 assetsBefore = totalAssets();

        if (supply == 0) {
            require(assets > MINIMUM_LIQUIDITY, "MINIMUM_DEPOSIT");
            _mint(DEAD_SHARES_RECEIVER, MINIMUM_LIQUIDITY);
            shares = assets - MINIMUM_LIQUIDITY;
        } else {
            shares = assets * totalSupply / assetsBefore;
        }

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
