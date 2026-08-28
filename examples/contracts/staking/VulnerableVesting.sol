// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVestingToken {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract VulnerableVesting {
    IVestingToken public token;
    address public beneficiary;
    uint256 public vestingStart;
    uint256 public vestingDuration;
    uint256 public cliff;
    uint256 public vestedAmount;
    uint256 public claimed;

    function vestedNow() public view returns (uint256) {
        uint256 elapsed = block.timestamp - vestingStart;
        if (elapsed >= vestingDuration) return vestedAmount;
        return vestedAmount * elapsed / vestingDuration;
    }

    function release() external {
        uint256 amount = vestedNow() - claimed;
        token.transfer(beneficiary, amount);
        claimed += amount;
    }
}
