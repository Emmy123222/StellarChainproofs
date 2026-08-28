pragma solidity ^0.8.0;

/// @notice Credits an internal ledger whenever it "receives" ERC-1155
/// tokens, but never checks that the caller is actually the token
/// contract. Anyone can call onERC1155Received directly and mint free
/// credit without transferring anything.
contract SpoofableERC1155Receiver {
    mapping(address => uint256) public creditedBalance;

    function onERC1155Received(
        address,
        address from,
        uint256,
        uint256 value,
        bytes calldata
    ) external returns (bytes4) {
        creditedBalance[from] += value;
        return this.onERC1155Received.selector;
    }
}
