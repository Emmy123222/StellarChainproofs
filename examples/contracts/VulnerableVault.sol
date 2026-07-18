// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * VulnerableVault.sol
 *
 * ⚠️  THIS CONTRACT IS INTENTIONALLY VULNERABLE.
 * It is provided for testing ChainProof only.
 * DO NOT deploy this to any network.
 *
 * Vulnerabilities present:
 *   - SWC-107: Reentrancy in withdraw() [intra-function]
 *   - SWC-107-X: Cross-function reentrancy via withdraw() -> getBonus()
 *   - SWC-115: tx.origin authentication in transferOwnership()
 *   - SWC-101: Integer overflow (pragma <0.8, no SafeMath)
 *   - SWC-104: Unchecked return value in sendReward()
 */
contract VulnerableVault {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalDeposited;
    uint256 public rewardPool;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        // SWC-115: using tx.origin instead of msg.sender
        require(tx.origin == owner, "Not owner");
        _;
    }

    function deposit() external payable {
        // SWC-101: Integer overflow — no SafeMath, pragma <0.8
        balances[msg.sender] += msg.value;
        totalDeposited += msg.value;
    }

    // SWC-107: Reentrancy vulnerability
    // External call (call.value) happens BEFORE state update (balances[msg.sender] = 0)
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // ❌ External call BEFORE state update — classic reentrancy
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State updated AFTER call — attacker can re-enter before this line
        balances[msg.sender] -= amount;
        totalDeposited -= amount;
    }

    function addReward(uint256 amount) external onlyOwner {
        // SWC-101: overflow on rewardPool
        rewardPool += amount;
    }

    // SWC-104: return value of send() is not checked
    function sendReward(address recipient) external onlyOwner {
        // ❌ .send() return value ignored — failure is silently swallowed
        recipient.call{value: rewardPool}("");
        rewardPool = 0;
    }

    // SWC-107-X: Cross-function reentrancy
    // This function reads balances[] which can be stale if re-entered during withdraw()
    // Attacker calls withdraw() -> msg.sender.call() -> reenter getBonus() -> reads stale balances
    function getBonus() external view returns (uint256) {
        // ❌ Reads stale state if re-entered during withdraw() before balances[msg.sender] -= amount
        return balances[msg.sender] / 10;
    }

    // SWC-115: tx.origin used for ownership transfer
    function transferOwnership(address newOwner) external {
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
