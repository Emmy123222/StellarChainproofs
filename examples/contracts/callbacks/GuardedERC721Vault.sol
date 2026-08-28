pragma solidity ^0.8.0;

interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

/// @notice Same shape as VulnerableERC721Vault, but the accounted balance is
/// finalized before the receiver-hook callback fires — a correct
/// Checks-Effects-Interactions ordering. Used as a false-positive control.
contract GuardedERC721Vault {
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;

    function safeMint(address to, uint256 tokenId) external {
        ownerOf[tokenId] = to;
        balanceOf[to] += 1;
        _checkOnERC721Received(msg.sender, address(0), to, tokenId);
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
