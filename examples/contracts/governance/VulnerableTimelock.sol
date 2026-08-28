// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableTimelock {
    address public admin;
    uint256 public minDelay;
    mapping(bytes32 => uint256) public timestamps;

    modifier onlyAdmin() {
        require(msg.sender == admin, "admin");
        _;
    }

    constructor(address admin_) {
        admin = admin_;
        minDelay = 2 days;
    }

    function hashOperation(address target, uint256 value, bytes calldata data, bytes32 predecessor, bytes32 salt)
        public pure returns (bytes32)
    {
        return keccak256(abi.encode(target, value, data));
    }

    function schedule(address target, uint256 value, bytes calldata data, bytes32 predecessor, bytes32 salt)
        external onlyAdmin
    {
        bytes32 id = keccak256(abi.encode(target, value, data));
        timestamps[id] = block.timestamp + minDelay;
    }

    function execute(address target, uint256 value, bytes calldata data, bytes32 predecessor)
        external onlyAdmin
    {
        predecessor;
        bytes32 id = keccak256(abi.encode(target, value, data));
        (bool ok,) = target.call{value: value}(data);
        require(ok, "execution failed");
        timestamps[id] = 1;
    }

    function updateDelay(uint256 newDelay) external onlyAdmin {
        minDelay = newDelay;
    }
}
