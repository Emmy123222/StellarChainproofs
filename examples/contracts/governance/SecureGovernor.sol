// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICheckpointVotes {
    function getPastVotes(address account, uint256 timepoint) external view returns (uint256);
    function getPastTotalSupply(uint256 timepoint) external view returns (uint256);
}

interface IGovernanceTimelock {
    function execute(address target, uint256 value, bytes calldata data, bytes32 predecessor, bytes32 salt)
        external payable returns (bytes memory);
}

/// Minimal secure fixture modeling checkpointed voting and a separate timelock executor.
contract SecureGovernor {
    ICheckpointVotes public governanceToken;
    IGovernanceTimelock public timelock;
    uint256 public proposalThreshold = 1e18;
    uint256 public votingDelay = 7200;
    uint256 public votingPeriod = 50400;
    uint256 public quorumNumerator = 4;
    uint256 public quorumDenominator = 100;
    uint256 public proposalCount;
    mapping(uint256 => uint256) private proposalSnapshots;
    mapping(uint256 => uint256) private deadlines;
    mapping(uint256 => bool) public executed;

    constructor(ICheckpointVotes token_, IGovernanceTimelock timelock_) {
        governanceToken = token_;
        timelock = timelock_;
    }

    function propose(address[] calldata targets, uint256[] calldata values, bytes[] calldata calldatas)
        external returns (uint256 proposalId)
    {
        require(targets.length != 0 && targets.length == values.length, "actions");
        require(values.length == calldatas.length, "actions");
        proposalId = ++proposalCount;
        proposalSnapshots[proposalId] = block.number + votingDelay;
        deadlines[proposalId] = proposalSnapshots[proposalId] + votingPeriod;
    }

    function proposalSnapshot(uint256 proposalId) public view returns (uint256) {
        return proposalSnapshots[proposalId];
    }

    function proposalDeadline(uint256 proposalId) public view returns (uint256) {
        return deadlines[proposalId];
    }

    function castVote(uint256 proposalId, bool support) external returns (uint256) {
        require(block.number >= proposalSnapshots[proposalId] && block.number <= deadlines[proposalId], "window");
        support;
        return governanceToken.getPastVotes(msg.sender, proposalSnapshots[proposalId]);
    }

    function quorum(uint256 snapshot) public view returns (uint256) {
        return governanceToken.getPastTotalSupply(snapshot) * quorumNumerator / quorumDenominator;
    }

    function hashProposal(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata calldatas,
        bytes32 descriptionHash
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(targets, values, calldatas, descriptionHash));
    }

    function execute(
        uint256 proposalId,
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt
    ) external {
        require(!executed[proposalId], "already executed");
        executed[proposalId] = true;
        timelock.execute(target, value, data, predecessor, salt);
    }
}
