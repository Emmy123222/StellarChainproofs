// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRebasingSharesToken {
    function transferSharesFrom(address from, address to, uint256 shares) external returns (uint256);
    function transferShares(address to, uint256 shares) external returns (uint256);
}

contract SecureRebasingShares {
    IRebasingSharesToken public stakingToken;
    uint256 public totalShares;
    mapping(address => uint256) public userShares;

    function stake(uint256 shares) external {
        uint256 receivedShares = stakingToken.transferSharesFrom(msg.sender, address(this), shares);
        totalShares += receivedShares;
        userShares[msg.sender] += receivedShares;
    }

    function withdraw(uint256 shares) external {
        userShares[msg.sender] -= shares;
        totalShares -= shares;
        stakingToken.transferShares(msg.sender, shares);
    }
}
