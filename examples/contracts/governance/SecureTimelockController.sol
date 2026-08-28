// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureTimelockController {
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    uint256 private constant DONE_TIMESTAMP = 1;
    uint256 private _minDelay;
    mapping(bytes32 => uint256) private _timestamps;
    mapping(bytes32 => mapping(address => bool)) private roles;

    modifier onlyRole(bytes32 role) {
        require(roles[role][msg.sender], "role");
        _;
    }

    constructor(uint256 delay, address proposer, address executor) {
        require(delay > 0, "delay");
        _minDelay = delay;
        roles[PROPOSER_ROLE][proposer] = true;
        roles[EXECUTOR_ROLE][executor] = true;
    }

    function hashOperation(address target, uint256 value, bytes calldata data, bytes32 predecessor, bytes32 salt)
        public pure returns (bytes32)
    {
        return keccak256(abi.encode(target, value, data, predecessor, salt));
    }

    function schedule(address target, uint256 value, bytes calldata data, bytes32 predecessor, bytes32 salt)
        external onlyRole(PROPOSER_ROLE)
    {
        bytes32 id = hashOperation(target, value, data, predecessor, salt);
        require(_timestamps[id] == 0, "scheduled");
        _timestamps[id] = block.timestamp + _minDelay;
    }

    function execute(address target, uint256 value, bytes calldata data, bytes32 predecessor, bytes32 salt)
        external onlyRole(EXECUTOR_ROLE)
    {
        bytes32 id = hashOperation(target, value, data, predecessor, salt);
        require(_timestamps[id] > DONE_TIMESTAMP && _timestamps[id] <= block.timestamp, "not ready");
        require(predecessor == bytes32(0) || _timestamps[predecessor] == DONE_TIMESTAMP, "dependency");
        _timestamps[id] = DONE_TIMESTAMP;
        (bool ok,) = target.call{value: value}(data);
        require(ok, "execution failed");
    }

    function updateDelay(uint256 newDelay) external {
        require(msg.sender == address(this), "self only");
        require(newDelay > 0, "delay");
        _minDelay = newDelay;
    }
}
