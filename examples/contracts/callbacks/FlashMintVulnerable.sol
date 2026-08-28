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

/// @notice Flash-mints tokens to the borrower's callback without ever
/// checking that the loan (plus fee) was repaid. The atomicity flash
/// loans depend on is only real when a post-callback invariant enforces it.
contract FlashMintVulnerable {
    mapping(address => uint256) public totalBorrowed;

    function flashLoan(address receiver, uint256 amount, bytes calldata data) external {
        uint256 fee = amount / 1000;
        IERC3156FlashBorrower(receiver).onFlashLoan(msg.sender, address(this), amount, fee, data);
        totalBorrowed[receiver] += amount;
    }
}
