// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISafeAccountingToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract SecureStakingRewards {
    uint256 private constant PRECISION = 1e18;
    ISafeAccountingToken public stakingToken;
    ISafeAccountingToken public rewardsToken;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    uint256 public rewardRate;
    uint256 public rewardsDuration = 7 days;
    uint256 public periodFinish;
    uint256 public lastUpdateTime;
    uint256 public rewardPerTokenStored;
    uint256 public queuedRewards;
    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public rewards;

    event EmergencyRewardForfeited(address indexed account, uint256 reward);

    modifier updateReward(address account) {
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = block.timestamp < periodFinish ? block.timestamp : periodFinish;
        if (account != address(0)) {
            rewards[account] += balances[account] *
                (rewardPerTokenStored - userRewardPerTokenPaid[account]) / PRECISION;
            userRewardPerTokenPaid[account] = rewardPerTokenStored;
        }
        _;
    }

    function rewardPerToken() public view returns (uint256) {
        if (totalSupply == 0) return rewardPerTokenStored;
        return rewardPerTokenStored +
            ((block.timestamp - lastUpdateTime) * rewardRate * PRECISION) / totalSupply;
    }

    function stake(uint256 requested) external updateReward(msg.sender) {
        uint256 balanceBefore = stakingToken.balanceOf(address(this));
        require(stakingToken.transferFrom(msg.sender, address(this), requested), "transfer failed");
        uint256 received = stakingToken.balanceOf(address(this)) - balanceBefore;
        require(received > 0, "zero received");
        totalSupply += received;
        balances[msg.sender] += received;
    }

    function withdraw(uint256 amount) external updateReward(msg.sender) {
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        require(stakingToken.transfer(msg.sender, amount), "transfer failed");
    }

    function notifyRewardAmount(uint256 reward) external updateReward(address(0)) {
        require(rewardsDuration > 0, "duration zero");
        uint256 available = rewardsToken.balanceOf(address(this));
        uint256 leftover = block.timestamp < periodFinish
            ? (periodFinish - block.timestamp) * rewardRate
            : 0;
        rewardRate = (reward + leftover) / rewardsDuration;
        require(rewardRate * rewardsDuration <= available, "underfunded");
        periodFinish = block.timestamp + rewardsDuration;
    }

    function emergencyWithdraw() external updateReward(msg.sender) {
        uint256 amount = balances[msg.sender];
        uint256 forfeited = rewards[msg.sender];
        rewards[msg.sender] = 0;
        balances[msg.sender] = 0;
        totalSupply -= amount;
        emit EmergencyRewardForfeited(msg.sender, forfeited);
        require(stakingToken.transfer(msg.sender, amount), "transfer failed");
    }

    function recoverToken(ISafeAccountingToken token, uint256 amount) external {
        require(address(token) != address(stakingToken), "stake protected");
        require(address(token) != address(rewardsToken), "rewards protected");
        require(token.transfer(msg.sender, amount), "transfer failed");
    }
}
