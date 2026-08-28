// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Fixture exercising every invariant kind the DSL supports, written
/// so each guarded path is actually enforced — the "secure" half of the
/// vulnerable/secure fixture pair used by the invariant-DSL evaluator tests
/// and by `examples/invariant-specs/vault.cpinv.json`.
contract Vault {
    address public owner;
    uint256 public totalAssets;
    uint256 public totalDebt;
    mapping(address => uint256) public balances;

    event Withdrawn(address indexed account, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// access: only the owner may adjust the reserve.
    function adjustAssets(uint256 delta) external onlyOwner {
        require(totalAssets >= totalDebt, "state invariant");
        require(delta <= 1000000, "delta too large");
        totalAssets += delta;
    }

    /// state + arithmetic: reserves must always cover outstanding debt.
    function borrow(uint256 amount) external {
        require(totalAssets >= totalDebt, "state invariant");
        require(totalAssets >= totalDebt + amount, "insufficient assets");
        totalDebt += amount;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// call-order + event: effects (balance update) happen before the
    /// external interaction, and a Withdrawn event is always emitted.
    function withdraw(uint256 amount) external {
        require(amount <= balances[msg.sender], "insufficient balance");
        _recordWithdrawal(msg.sender, amount);
        emit Withdrawn(msg.sender, amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function _recordWithdrawal(address account, uint256 amount) internal {
        balances[account] -= amount;
    }
}
