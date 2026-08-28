pragma solidity ^0.8.0;

interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

/// @notice Naive NFT vault: mints a receipt NFT before finalizing the
/// depositor's accounted balance, exposing a Checks-Effects-Interactions
/// violation through the ERC-721 receiver-hook callback.
contract VulnerableERC721Vault {
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;

    function safeMint(address to, uint256 tokenId) external {
        ownerOf[tokenId] = to;
        _checkOnERC721Received(msg.sender, address(0), to, tokenId);
        balanceOf[to] += 1;
    }

    function _checkOnERC721Received(
        address operator,
        address from,
        address to,
        uint256 tokenId
    ) internal {
        if (_isContract(to)) {
            IERC721Receiver(to).onERC721Received(operator, from, tokenId, "");
        }
    }

    function _isContract(address addr) internal view returns (bool result) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        result = size > 0;
    }
}
