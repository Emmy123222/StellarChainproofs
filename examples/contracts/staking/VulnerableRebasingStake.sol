// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRebasingStakeToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VulnerableRebasingStake {
    IRebasingStakeToken public stakingToken;
    uint256 public totalStaked;
    mapping(address => uint256) public balances;

    function stake(uint256 amount) external {
        stakingToken.transferFrom(msg.sender, address(this), amount);
        totalStaked += amount;
        balances[msg.sender] += amount;
    }

    function restake(uint256 amount) external {
        totalStaked += amount;
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        totalStaked -= amount;
        stakingToken.transfer(msg.sender, amount);
    }
}
