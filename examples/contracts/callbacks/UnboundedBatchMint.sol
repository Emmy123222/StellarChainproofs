pragma solidity ^0.8.0;

interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

/// @notice Airdrops an arbitrary-length batch of NFTs, invoking the
/// receiver-hook callback once per item with no cap on the caller-supplied
/// array length — both a per-iteration reentrancy surface and a
/// block-gas-limit denial-of-service vector.
contract UnboundedBatchMint {
    mapping(uint256 => address) public ownerOf;

    function batchMint(address to, uint256[] calldata tokenIds) external {
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
