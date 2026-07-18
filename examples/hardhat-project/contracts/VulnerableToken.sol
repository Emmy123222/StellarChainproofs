// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableToken
 * @notice Intentionally vulnerable contract for ChainProof Hardhat plugin demos.
 */
contract VulnerableToken {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(tx.origin == owner, "Not owner");
        _;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
    }
}
