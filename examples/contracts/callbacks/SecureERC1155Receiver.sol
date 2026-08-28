pragma solidity ^0.8.0;

/// @notice Same accounting as SpoofableERC1155Receiver, but verifies the
/// caller is the configured token contract before trusting the callback
/// arguments. Used as a false-positive control for callback spoofing.
contract SecureERC1155Receiver {
    address public immutable token;
    mapping(address => uint256) public creditedBalance;

    constructor(address _token) {
        token = _token;
    }

    function onERC1155Received(
        address,
        address from,
        uint256,
        uint256 value,
        bytes calldata
    ) external returns (bytes4) {
        require(msg.sender == token, "untrusted caller");
        creditedBalance[from] += value;
        return this.onERC1155Received.selector;
    }
}
