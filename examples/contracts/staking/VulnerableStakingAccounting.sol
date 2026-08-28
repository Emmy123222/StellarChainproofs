// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAccountingToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract VulnerableStakingAccounting {
    IAccountingToken public stakingToken;
    IAccountingToken public rewardTokenA;
    IAccountingToken public rewardTokenB;

    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    uint256 public rewardRate;
    uint256 public rewardsDuration;
    uint256 public periodFinish;
    uint256 public lastUpdateTime;
    uint256 public rewardPerTokenStored;
    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public rewards;

    constructor(IAccountingToken stakeAsset, IAccountingToken firstReward, IAccountingToken secondReward) {
        stakingToken = stakeAsset;
        rewardTokenA = firstReward;
        rewardTokenB = secondReward;
        rewardsDuration = 7 days;
    }

    function rewardPerToken() public view returns (uint256) {
        if (totalSupply == 0) return rewardPerTokenStored;
        return rewardPerTokenStored + (block.timestamp - lastUpdateTime) / totalSupply * rewardRate;
    }

    function stake(uint256 amount) external {
        stakingToken.transferFrom(msg.sender, address(this), amount);
        totalSupply += amount;
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        stakingToken.transfer(msg.sender, amount);
    }

    function notifyRewardAmount(uint256 reward) external {
        rewardRate = reward / rewardsDuration;
        periodFinish = block.timestamp + rewardsDuration;
    }

    function setRewardRate(uint256 newRate) external {
        rewardRate = newRate;
    }

    function emergencyWithdraw() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        totalSupply -= amount;
        stakingToken.transfer(msg.sender, amount);
    }

    function recoverToken(IAccountingToken token, uint256 amount) external {
        token.transfer(msg.sender, amount);
    }
}
