pragma solidity ^0.8.0;

interface IERC3156FlashBorrower {
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32);
}

interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
}

/// @notice Same flash-mint shape as FlashMintVulnerable, but enforces the
/// repayment invariant after the callback returns. Used as a
/// false-positive control for intentionally atomic callbacks.
contract FlashMintGuarded {
    IERC20Like public asset;

    function flashLoan(address receiver, uint256 amount, bytes calldata data) external {
        uint256 fee = amount / 1000;
        uint256 balanceBefore = asset.balanceOf(address(this));
        IERC3156FlashBorrower(receiver).onFlashLoan(msg.sender, address(this), amount, fee, data);
        require(asset.balanceOf(address(this)) >= balanceBefore + amount + fee, "not repaid");
    }
}
