// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC1155Receiver {
    function onERC1155Received(address operator, address from, uint256 id, uint256 value, bytes calldata data) external returns (bytes4);
}

contract NonCompliantERC1155 {
    mapping(uint256 => mapping(address => uint256)) private _balances;

    // Violation CP-ERC1155-EVENTS: Missing TransferSingle and TransferBatch event declarations

    function balanceOfBatch(address[] calldata owners, uint256[] calldata ids) external view returns (uint256[] memory) {
        uint256[] memory batchBalances = new uint256[](owners.length);
        for (uint256 i = 0; i < owners.length; ++i) {
            batchBalances[i] = _balances[ids[i]][owners[i]];
        }
        return batchBalances;
    }

    // Violation CP-ERC1155-REENTRANCY: safeTransferFrom invokes receiver callback without reentrancy guard
    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) public {
        _balances[id][from] -= amount;
        _balances[id][to] += amount;

        uint256 size;
        assembly { size := extcodesize(to) }
        if (size > 0) {
            bytes4 retval = IERC1155Receiver(to).onERC1155Received(msg.sender, from, id, amount, data);
            require(retval == IERC1155Receiver.onERC1155Received.selector, "Rejected");
        }
    }
}
