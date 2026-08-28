// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableMultisig {
    address[] public owners;
    uint256 public threshold;
    uint256 public nonce;
    mapping(bytes32 => bool) public executed;

    constructor(address[] memory owners_, uint256 threshold_) {
        owners = owners_;
        threshold = threshold_;
    }

    function execTransaction(address target, uint256 value, bytes calldata data, bytes calldata signatures)
        external returns (bool)
    {
        signatures;
        (bool ok,) = target.call{value: value}(data);
        return ok;
    }
}
