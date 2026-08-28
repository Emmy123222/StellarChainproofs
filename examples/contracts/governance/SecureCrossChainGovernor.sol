// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureCrossChainGovernor {
    address public bridge;
    uint256 public sourceChainId;
    mapping(bytes32 => bool) public processedMessages;
    uint256 public proposalCount;
    uint256 public quorumVotes;

    constructor(address bridge_, uint256 sourceChainId_) {
        bridge = bridge_;
        sourceChainId = sourceChainId_;
    }

    function receiveMessage(bytes32 messageId, uint256 origin, address target, bytes calldata data) external {
        require(msg.sender == bridge, "bridge");
        require(origin == sourceChainId, "domain");
        require(!processedMessages[messageId], "replayed");
        processedMessages[messageId] = true;
        (bool ok,) = target.call(data);
        require(ok, "message execution failed");
    }
}
