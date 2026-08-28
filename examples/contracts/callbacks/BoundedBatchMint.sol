pragma solidity ^0.8.0;

interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

/// @notice Same batch-airdrop shape as UnboundedBatchMint, but caps the
/// batch size explicitly before the loop. Used as a false-positive
/// control for unbounded-batch-callback detection.
contract BoundedBatchMint {
    uint256 public constant MAX_BATCH_SIZE = 50;
    mapping(uint256 => address) public ownerOf;

    function batchMint(address to, uint256[] calldata tokenIds) external {
        require(tokenIds.length <= MAX_BATCH_SIZE, "batch too large");
        for (uint256 i = 0; i < tokenIds.length; i++) {
            ownerOf[tokenIds[i]] = to;
            _checkOnERC721Received(msg.sender, address(0), to, tokenIds[i]);
        }
    }

    function _checkOnERC721Received(
        address operator,
        address from,
        address to,
        uint256 tokenId
    ) internal {
        IERC721Receiver(to).onERC721Received(operator, from, tokenId, "");
    }
}
