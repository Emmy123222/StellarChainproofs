// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRouter {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address recipient,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

contract VulnerableLottery {
    address[] public players;

    function enter() external {
        players.push(msg.sender);
    }

    function pickWinner() external view returns (uint256) {
        return uint256(
            keccak256(abi.encodePacked(block.timestamp, block.difficulty, players.length))
        ) % players.length;
    }
}

contract VulnerableSwap {
    IRouter public router;

    constructor(IRouter _router) {
        router = _router;
    }

    function sell(
        uint256 amountIn,
        address[] calldata path,
        uint256 deadline
    ) external {
        router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, deadline);
    }
}

contract VulnerableToken {
    mapping(address => mapping(address => uint256)) public allowance;

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}

contract VulnerableAuction {
    uint256 public highestBid;
    address public highestBidder;

    function bid(uint256 amount) external {
        require(amount > highestBid, "too low");
        highestBid = amount;
        highestBidder = msg.sender;
    }
}
