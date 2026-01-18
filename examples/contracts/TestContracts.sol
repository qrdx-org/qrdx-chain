// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SimpleStorage
 * @dev Basic smart contract for testing QRDX contract support
 */
contract SimpleStorage {
    uint256 private value;
    address public owner;
    
    event ValueChanged(uint256 indexed oldValue, uint256 indexed newValue, address indexed changer);
    
    constructor(uint256 initialValue) {
        value = initialValue;
        owner = msg.sender;
        emit ValueChanged(0, initialValue, msg.sender);
    }
    
    function setValue(uint256 newValue) public {
        uint256 oldValue = value;
        value = newValue;
        emit ValueChanged(oldValue, newValue, msg.sender);
    }
    
    function getValue() public view returns (uint256) {
        return value;
    }
    
    function increment() public {
        setValue(value + 1);
    }
    
    function decrement() public {
        require(value > 0, "Value already zero");
        setValue(value - 1);
    }
}

/**
 * @title QRDXToken
 * @dev Simple ERC20-like token for QRDX
 */
contract QRDXToken {
    string public name = "QRDX Test Token";
    string public symbol = "QTT";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    
    mapping(address => uint256) private balances;
    mapping(address => mapping(address => uint256)) private allowances;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    constructor(uint256 initialSupply) {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balances[msg.sender] = totalSupply;
        emit Transfer(address(0), msg.sender, totalSupply);
    }
    
    function balanceOf(address account) public view returns (uint256) {
        return balances[account];
    }
    
    function transfer(address to, uint256 amount) public returns (bool) {
        require(to != address(0), "Transfer to zero address");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        balances[to] += amount;
        
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    
    function approve(address spender, uint256 amount) public returns (bool) {
        require(spender != address(0), "Approve to zero address");
        
        allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
    
    function allowance(address owner, address spender) public view returns (uint256) {
        return allowances[owner][spender];
    }
    
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(from != address(0), "Transfer from zero address");
        require(to != address(0), "Transfer to zero address");
        require(balances[from] >= amount, "Insufficient balance");
        require(allowances[from][msg.sender] >= amount, "Insufficient allowance");
        
        balances[from] -= amount;
        balances[to] += amount;
        allowances[from][msg.sender] -= amount;
        
        emit Transfer(from, to, amount);
        return true;
    }
}

/**
 * @title QuantumResistantVault
 * @dev Demonstrates QRDX quantum-resistant features
 */
contract QuantumResistantVault {
    mapping(address => uint256) private deposits;
    mapping(address => bool) public hasDeposited;
    
    event Deposit(address indexed depositor, uint256 amount);
    event Withdrawal(address indexed withdrawer, uint256 amount);
    
    function deposit() public payable {
        require(msg.value > 0, "Must deposit non-zero amount");
        
        deposits[msg.sender] += msg.value;
        hasDeposited[msg.sender] = true;
        
        emit Deposit(msg.sender, msg.value);
    }
    
    function getBalance() public view returns (uint256) {
        return deposits[msg.sender];
    }
    
    function withdraw(uint256 amount) public {
        require(deposits[msg.sender] >= amount, "Insufficient balance");
        
        deposits[msg.sender] -= amount;
        
        // Send to quantum-resistant QRDX address
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Withdrawal(msg.sender, amount);
    }
    
    function getTotalDeposits() public view returns (uint256) {
        uint256 total = 0;
        // Note: In production, this would use an accumulator
        // This is simplified for demonstration
        return total;
    }
}
