// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Same shape as SecureVaultInvariants.sol, with every guard removed
/// or misordered — the "vulnerable" half of the fixture pair. Every
/// invariant in `examples/invariant-specs/vault.cpinv.json` is expected to
/// `fail` against this contract.
contract Vault {
    address public owner;
    uint256 public totalAssets;
    uint256 public totalDebt;
    mapping(address => uint256) public balances;

    event Withdrawn(address indexed account, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    /// access VIOLATION: no owner check at all.
    function adjustAssets(uint256 delta) external {
        totalAssets += delta;
    }

    /// state + arithmetic VIOLATION: debt can exceed reserves.
    function borrow(uint256 amount) external {
        totalDebt += amount;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// call-order VIOLATION (classic reentrancy): the external call happens
    /// before the balance is updated. event VIOLATION: no Withdrawn emitted.
    function withdraw(uint256 amount) external {
        require(amount <= balances[msg.sender], "insufficient balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        _recordWithdrawal(msg.sender, amount);
    }

    function _recordWithdrawal(address account, uint256 amount) internal {
        balances[account] -= amount;
    }
}
