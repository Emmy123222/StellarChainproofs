pragma solidity ^0.8.0;

/// @notice ERC-4626-style vault whose underlying asset is an ERC-777 token.
/// The sender hook (`tokensToSend`) fires while the vault is mid-deposit,
/// before share accounting is finalized — a read-only reentrancy exposure
/// for any integrator quoting the share price during the callback.
contract ERC777VaultDeposit {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 public totalAssets;

    function deposit(uint256 amount) external {
        totalAssets += amount;
        _callTokensToSend(msg.sender, address(this), amount);
        uint256 minted = amount;
        shares[msg.sender] += minted;
        totalShares += minted;
    }

    function _callTokensToSend(address from, address to, uint256 amount) internal {
        // Dispatches to IERC777Sender(implementer).tokensToSend(...) per the
        // ERC-777 registry lookup; omitted here for fixture brevity.
    }

    function pricePerShare() external view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (totalAssets * 1e18) / totalShares;
    }

    function bonus() external view returns (uint256) {
        return shares[msg.sender];
    }
}
