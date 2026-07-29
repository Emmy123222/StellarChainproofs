import { parseSolidity } from "../../ast/parser";
import { detectFrontRunningMev } from "../cp119-frontrunning";

const RANDOMNESS = `
pragma solidity ^0.8.20;
contract Lottery {
  address[] public players;

  function pickWinner() external view returns (uint256) {
    return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty, players.length)));
  }
}
`;

const ZERO_SLIPPAGE_SWAP = `
pragma solidity ^0.8.20;
interface IRouter {
  function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) external;
}
contract Swap {
  IRouter router;

  function sell(uint256 amountIn, address[] calldata path, uint256 deadline) external {
    router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, deadline);
  }
}
`;

const ERC20_APPROVE = `
pragma solidity ^0.8.20;
contract Token {
  mapping(address => mapping(address => uint256)) public allowance;

  function approve(address spender, uint256 amount) external returns (bool) {
    allowance[msg.sender][spender] = amount;
    return true;
  }
}
`;

const APPROVE_WITH_HELPERS = `
pragma solidity ^0.8.20;
contract Token {
  mapping(address => mapping(address => uint256)) public allowance;

  function approve(address spender, uint256 amount) external returns (bool) {
    allowance[msg.sender][spender] = amount;
    return true;
  }

  function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
    allowance[msg.sender][spender] += addedValue;
    return true;
  }
}
`;

const AUCTION = `
pragma solidity ^0.8.20;
contract Auction {
  uint256 public highestBid;
  address public highestBidder;

  function bid(uint256 amount) external {
    require(amount > highestBid, "too low");
    highestBid = amount;
    highestBidder = msg.sender;
  }
}
`;

const COMMIT_REVEAL_AUCTION = `
pragma solidity ^0.8.20;
contract Auction {
  mapping(address => bytes32) public commitments;
  uint256 public highestBid;
  address public highestBidder;

  function commitBid(bytes32 commitment) external {
    commitments[msg.sender] = commitment;
  }

  function revealBid(uint256 amount, bytes32 salt) external {
    require(commitments[msg.sender] == keccak256(abi.encodePacked(amount, salt)));
    require(amount > highestBid, "too low");
    highestBid = amount;
    highestBidder = msg.sender;
  }
}
`;

function run(source: string) {
  const { ast } = parseSolidity(source, "test.sol");
  expect(ast).not.toBeNull();
  return detectFrontRunningMev(ast!, source, "test.sol");
}

describe("detectFrontRunningMev (CP-119)", () => {
  it("flags block metadata in keccak256 randomness as high severity", () => {
    const findings = run(RANDOMNESS);
    const randomness = findings.find(
      (finding) => finding.title === "Miner-controlled value used for randomness"
    );

    expect(randomness).toBeDefined();
    expect(randomness?.id).toBe("CP-119");
    expect(randomness?.swcId).toBe("SWC-120");
    expect(randomness?.severity).toBe("high");
  });

  it("flags AMM swaps with zero amountOutMin as high severity", () => {
    const findings = run(ZERO_SLIPPAGE_SWAP);
    const swap = findings.find(
      (finding) => finding.title === "AMM swap accepts zero minimum output"
    );

    expect(swap).toBeDefined();
    expect(swap?.severity).toBe("high");
  });

  it("flags ERC-20 approve without allowance adjustment helpers as medium severity", () => {
    const findings = run(ERC20_APPROVE);
    const approve = findings.find(
      (finding) => finding.title === "ERC-20 approve race condition"
    );

    expect(approve).toBeDefined();
    expect(approve?.severity).toBe("medium");
  });

  it("does not flag approve when increaseAllowance is available", () => {
    const findings = run(APPROVE_WITH_HELPERS);
    const approve = findings.filter(
      (finding) => finding.title === "ERC-20 approve race condition"
    );

    expect(approve).toHaveLength(0);
  });

  it("flags public bidding without commit-reveal as medium severity", () => {
    const findings = run(AUCTION);
    const auction = findings.find(
      (finding) => finding.title === "Public bidding without commit-reveal"
    );

    expect(auction).toBeDefined();
    expect(auction?.severity).toBe("medium");
  });

  it("does not flag bidding when commit and reveal functions are present", () => {
    const findings = run(COMMIT_REVEAL_AUCTION);
    const auction = findings.filter(
      (finding) => finding.title === "Public bidding without commit-reveal"
    );

    expect(auction).toHaveLength(0);
  });
});
