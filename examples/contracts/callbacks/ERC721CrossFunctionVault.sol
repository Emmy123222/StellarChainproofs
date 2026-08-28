pragma solidity ^0.8.0;

interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

/// @notice Withdraw path checks the depositor's accounted balance, fires the
/// ERC-721 receiver-hook callback, and only *then* finalizes state. A
/// sibling function reads the same stale balance during re-entry.
contract ERC721CrossFunctionVault {
    mapping(address => uint256) public balances;
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public rewardsPaid;

    function withdraw(uint256 tokenId) external {
        require(balances[msg.sender] > 0, "no balance");
        require(ownerOf[tokenId] == msg.sender, "not owner");
        _checkOnERC721Received(msg.sender, address(this), msg.sender, tokenId);
        ownerOf[tokenId] = address(0);
        balances[msg.sender] -= 1;
    }

    function _checkOnERC721Received(
        address operator,
        address from,
        address to,
        uint256 tokenId
    ) internal {
        IERC721Receiver(to).onERC721Received(operator, from, tokenId, "");
    }

    function claimBonus() external {
        uint256 bonus = balances[msg.sender] * 2;
        rewardsPaid[msg.sender] += bonus;
    }
}
