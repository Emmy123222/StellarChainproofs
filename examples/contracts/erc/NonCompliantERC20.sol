// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NonCompliantERC20 {
    string public name = "NonCompliantToken";
    string public symbol = "NCT";
    uint256 public totalSupply = 1000000;
    
    // Violation CP-ERC20-DECIMALS: non-uint8 decimals return type
    function decimals() public pure returns (uint256) {
        return 18;
    }

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // Violation CP-ERC20-RETURN: missing bool return parameter on transfer & transferFrom
    function transfer(address to, uint256 amount) public {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    function transferFrom(address from, address to, uint256 amount) public {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }

    // Violation CP-ERC20-APPROVE-RACE: approve without increaseAllowance/decreaseAllowance
    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}
