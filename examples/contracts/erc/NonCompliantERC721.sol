// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4);
}

contract NonCompliantERC721 {
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;

    // Violation CP-ERC721-UNRESTRICTED-MINT: public mint without access control
    function mint(address to, uint256 tokenId) public {
        ownerOf[tokenId] = to;
        balanceOf[to]++;
    }

    // Violation CP-ERC721-REENTRANCY: safeTransferFrom invokes receiver callback without reentrancy guard
    function safeTransferFrom(address from, address to, uint256 tokenId) public {
        require(ownerOf[tokenId] == from, "Not owner");
        ownerOf[tokenId] = to;

        uint256 size;
        assembly { size := extcodesize(to) }
        if (size > 0) {
            bytes4 retval = IERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, "");
            require(retval == IERC721Receiver.onERC721Received.selector, "Invalid receiver");
        }
    }

    // Violation CP-ERC721-ERC165: Missing supportsInterface(bytes4) implementation
}
