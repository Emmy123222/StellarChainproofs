pragma solidity ^0.8.0;

import "./IERC721Receiver.sol";

/// @notice Same CEI violation as VulnerableERC721Vault, but with the
/// receiver interface pulled in via an import directive — exercises the
/// scanner's import-graph-aware contract view (@chainproof/core builds a
/// MergedContractView, which the callback analysis needs, only for files
/// that use imports).
contract VaultWithImportedReceiver {
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
        IERC721Receiver(to).onERC721Received(operator, from, tokenId, "");
    }
}
