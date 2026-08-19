// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPriceOracle {
    function getAssetPrice(address asset) external view returns (uint256);
}

/**
 * @title DeFiSystemFixture
 * @notice A composite fixture containing typical patterns for threat modeling:
 * - Access control (owner)
 * - Token balance ledger (balances, totalSupply)
 * - Oracle pricing integration
 * - Upgradeable pattern (initialize)
 * - Deposit / withdraw logic (vault behavior)
 */
contract DeFiSystemFixture {
    address public owner;
    address public priceOracle;
    bool public paused;
    bool private initialized;

    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Paused");
        _;
    }

    function initialize(address _oracle) external {
        require(!initialized, "Already initialized");
        owner = msg.sender;
        priceOracle = _oracle;
        initialized = true;
    }

    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
    }

    function setOracle(address _oracle) external onlyOwner {
        priceOracle = _oracle;
    }

    function deposit() external payable whenNotPaused {
        require(msg.value > 0, "Zero deposit");
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external whenNotPaused {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Potential reentrancy pattern (state updated after external call)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
        totalSupply -= amount;
        
        emit Withdrawn(msg.sender, amount);
    }

    function getVaultValueInUSD() external view returns (uint256) {
        uint256 price = IPriceOracle(priceOracle).getAssetPrice(address(this));
        return (totalSupply * price) / 1e18;
    }
}
