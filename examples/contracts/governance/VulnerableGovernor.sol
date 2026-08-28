// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVulnerableVotes {
    function balanceOf(address account) external view returns (uint256);
    function getVotes(address account, uint256 timepoint) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

/// Intentionally vulnerable fixture: each unsafe branch is covered by the governance analyzer tests.
contract VulnerableGovernor {
    IVulnerableVotes public governanceToken;
    uint256 public proposalThreshold;
    uint256 public quorumNumerator;
    uint256 public proposalCount;
    address public guardian;
    mapping(uint256 => bool) public executed;

    constructor(IVulnerableVotes token_, address guardian_) {
        governanceToken = token_;
        guardian = guardian_;
        proposalThreshold = 1;
        quorumNumerator = 4;
    }

    function propose(address[] calldata targets, uint256[] calldata values, bytes[] calldata calldatas)
        external returns (uint256)
    {
        require(governanceToken.balanceOf(msg.sender) >= proposalThreshold, "threshold");
        require(targets.length == values.length && targets.length == calldatas.length, "length");
        proposalCount += 1;
        return proposalCount;
    }

    function getVotes(address account) public view returns (uint256) {
        // Live balance and current-block checkpoint both permit atomic voting-power acquisition.
        return governanceToken.balanceOf(account) + governanceToken.getVotes(account, block.number);
    }

    function castVote(uint256, bool) external returns (uint256) {
        uint256 weight = getVotes(msg.sender);
        return weight;
    }

    function quorum(uint256) public view returns (uint256) {
        // Division before multiplication can truncate a non-zero quorum fraction to zero.
        return governanceToken.totalSupply() / 100 * quorumNumerator;
    }

    function hashProposal(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata calldatas,
        bytes32 descriptionHash
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(targets, descriptionHash));
    }

    function execute(uint256 proposalId, address target, uint256 value, bytes calldata data) external {
        (bool ok,) = target.call{value: value}(data);
        require(ok, "execution failed");
        executed[proposalId] = true;
    }

    function emergencyExecute(address target, bytes calldata data) external {
        require(msg.sender == guardian, "guardian");
        (bool ok,) = target.call(data);
        require(ok, "guardian execution failed");
    }

    function emergencyUpgrade(address proxy, address implementation, bytes calldata data) external {
        require(msg.sender == guardian, "guardian");
        (bool ok,) = proxy.call(
            abi.encodeWithSignature("upgradeToAndCall(address,bytes)", implementation, data)
        );
        require(ok, "upgrade failed");
    }
}
