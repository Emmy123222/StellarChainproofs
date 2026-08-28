// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableCrossChainGovernor {
    address public bridge;
    bytes32 public messageId;
    uint256 public proposalCount;
    uint256 public quorumVotes;

    constructor(address bridge_) {
        bridge = bridge_;
    }

    function receiveMessage(
        bytes32 incomingMessageId,
        uint256 sourceChainId,
        address target,
        bytes calldata data
    ) external {
        require(msg.sender == bridge, "bridge");
        incomingMessageId;
        sourceChainId;
        (bool ok,) = target.call(data);
        require(ok, "message execution failed");
    }
}
