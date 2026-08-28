// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISecureVestingToken {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract SecureVesting {
    ISecureVestingToken public token;
    address public beneficiary;
    uint256 public vestingStart;
    uint256 public vestingDuration;
    uint256 public cliff;
    uint256 public vestedAmount;
    uint256 public claimed;

    function vestedAmountAt(uint256 timestamp) public view returns (uint256) {
        if (timestamp < vestingStart + cliff) return 0;
        uint256 elapsed = timestamp - vestingStart;
        if (elapsed >= vestingDuration) return vestedAmount;
        return vestedAmount * elapsed / vestingDuration;
    }

    function release() external {
        require(block.timestamp >= vestingStart + cliff, "cliff active");
        uint256 amount = vestedAmountAt(block.timestamp) - claimed;
        claimed += amount;
        require(token.transfer(beneficiary, amount), "transfer failed");
    }
}
