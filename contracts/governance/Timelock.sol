// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./ITimelock.sol";

/**
 * @title Timelock
 * @notice Time-locked transaction execution for governance security
 * 
 * Provides delayed execution of governance proposals:
 * - Minimum 7-day delay between queue and execution
 * - 3-day grace period for execution
 * - Emergency cancellation by admin
 * - Two-step admin transfer for safety
 * 
 * Security Features:
 * - Prevents immediate execution of malicious proposals
 * - Allows community to exit before harmful changes
 * - Admin can cancel suspicious transactions
 * - Transparent on-chain execution schedule
 */
contract Timelock is ITimelock {
    // =============================================================
    //                        CONSTANTS
    // =============================================================
    
    /// @notice Minimum delay (7 days)
    uint256 public constant MINIMUM_DELAY = 7 days;
    
    /// @notice Maximum delay (30 days)
    uint256 public constant MAXIMUM_DELAY = 30 days;
    
    /// @notice Grace period for execution (3 days)
    uint256 public constant GRACE_PERIOD = 3 days;
    
    // =============================================================
    //                        STORAGE
    // =============================================================
    
    /// @notice Current admin (Governor contract)
    address public override admin;
    
    /// @notice Pending admin for two-step transfer
    address public override pendingAdmin;
    
    /// @notice Current delay in seconds
    uint256 public override delay;
    
    /// @notice Grace period in seconds
    uint256 public immutable override gracePeriod = GRACE_PERIOD;
    
    /// @notice Mapping of transaction hash to queued status
    mapping(bytes32 => bool) public override queuedTransactions;
    
    /// @notice Mapping of transaction hash to transaction data
    mapping(bytes32 => QueuedTransaction) private transactions;
    
    // =============================================================
    //                        MODIFIERS
    // =============================================================
    
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }
    
    modifier onlyTimelock() {
        require(msg.sender == address(this), "Only timelock");
        _;
    }
    
    modifier onlyPendingAdmin() {
        require(msg.sender == pendingAdmin, "Only pending admin");
        _;
    }
    
    // =============================================================
    //                        CONSTRUCTOR
    // =============================================================
    
    /**
     * @notice Initialize the Timelock contract
     * @param _admin Initial admin address (Governor contract)
     * @param _delay Initial delay in seconds
     */
    constructor(address _admin, uint256 _delay) {
        require(_admin != address(0), "Invalid admin");
        require(_delay >= MINIMUM_DELAY, "Delay below minimum");
        require(_delay <= MAXIMUM_DELAY, "Delay above maximum");
        
        admin = _admin;
        delay = _delay;
        
        emit AdminUpdated(address(0), _admin);
        emit DelayUpdated(0, _delay);
    }
    
    // =============================================================
    //                    TRANSACTION FUNCTIONS
    // =============================================================
    
    /**
     * @inheritdoc ITimelock
     */
    function queueTransaction(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 eta
    ) external override onlyAdmin returns (bytes32) {
        require(target != address(0), "Invalid target");
        require(eta >= block.timestamp + delay, "ETA too soon");
        
        bytes32 txHash = getTxHash(target, value, data, eta);
        require(!queuedTransactions[txHash], "Transaction already queued");
        
        queuedTransactions[txHash] = true;
        transactions[txHash] = QueuedTransaction({
            txHash: txHash,
            target: target,
            value: value,
            data: data,
            eta: eta,
            executed: false,
            canceled: false
        });
        
        emit TransactionQueued(txHash, target, value, data, eta);
        
        return txHash;
    }
    
    /**
     * @inheritdoc ITimelock
     */
    function executeTransaction(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 eta
    ) external payable override onlyAdmin returns (bytes memory) {
        bytes32 txHash = getTxHash(target, value, data, eta);
        
        require(queuedTransactions[txHash], "Transaction not queued");
        require(block.timestamp >= eta, "Transaction not yet executable");
        require(block.timestamp <= eta + GRACE_PERIOD, "Transaction expired");
        
        QueuedTransaction storage transaction = transactions[txHash];
        require(!transaction.executed, "Transaction already executed");
        require(!transaction.canceled, "Transaction canceled");
        
        transaction.executed = true;
        queuedTransactions[txHash] = false;
        
        // Execute transaction
        (bool success, bytes memory returnData) = target.call{value: value}(data);
        require(success, "Transaction execution failed");
        
        emit TransactionExecuted(txHash, target, value, data, eta);
        
        return returnData;
    }
    
    /**
     * @inheritdoc ITimelock
     */
    function cancelTransaction(bytes32 txHash) external override onlyAdmin {
        require(queuedTransactions[txHash], "Transaction not queued");
        
        QueuedTransaction storage transaction = transactions[txHash];
        require(!transaction.executed, "Transaction already executed");
        require(!transaction.canceled, "Transaction already canceled");
        
        transaction.canceled = true;
        queuedTransactions[txHash] = false;
        
        emit TransactionCanceled(txHash);
    }
    
    // =============================================================
    //                    ADMIN FUNCTIONS
    // =============================================================
    
    /**
     * @inheritdoc ITimelock
     */
    function setPendingAdmin(address newPendingAdmin) external override onlyAdmin {
        require(newPendingAdmin != address(0), "Invalid pending admin");
        pendingAdmin = newPendingAdmin;
        
        emit PendingAdminUpdated(newPendingAdmin);
    }
    
    /**
     * @inheritdoc ITimelock
     */
    function acceptAdmin() external override onlyPendingAdmin {
        address oldAdmin = admin;
        admin = pendingAdmin;
        pendingAdmin = address(0);
        
        emit AdminUpdated(oldAdmin, admin);
    }
    
    /**
     * @inheritdoc ITimelock
     */
    function setDelay(uint256 newDelay) external override onlyTimelock {
        require(newDelay >= MINIMUM_DELAY, "Delay below minimum");
        require(newDelay <= MAXIMUM_DELAY, "Delay above maximum");
        
        uint256 oldDelay = delay;
        delay = newDelay;
        
        emit DelayUpdated(oldDelay, newDelay);
    }
    
    // =============================================================
    //                    VIEW FUNCTIONS
    // =============================================================
    
    /**
     * @inheritdoc ITimelock
     */
    function getTransaction(bytes32 txHash) external view override returns (QueuedTransaction memory) {
        require(transactions[txHash].txHash != bytes32(0), "Transaction does not exist");
        return transactions[txHash];
    }
    
    /**
     * @inheritdoc ITimelock
     */
    function getTxHash(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 eta
    ) public pure override returns (bytes32) {
        return keccak256(abi.encode(target, value, data, eta));
    }
    
    // =============================================================
    //                    RECEIVE FUNCTION
    // =============================================================
    
    /**
     * @notice Allow contract to receive ETH
     */
    receive() external payable {}
}
