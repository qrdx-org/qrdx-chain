// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ITimelock
 * @notice Interface for time-locked transaction execution
 * 
 * Provides security through delayed execution:
 * - Minimum delay between queue and execution
 * - Grace period for execution window
 * - Emergency cancellation mechanism
 * - Admin controls for critical operations
 */
interface ITimelock {
    // =============================================================
    //                        STRUCTS
    // =============================================================
    
    /**
     * @notice Queued transaction data
     */
    struct QueuedTransaction {
        bytes32 txHash;         // Transaction hash
        address target;         // Target contract
        uint256 value;          // ETH value
        bytes data;             // Call data
        uint256 eta;            // Estimated execution time
        bool executed;          // Whether executed
        bool canceled;          // Whether canceled
    }
    
    // =============================================================
    //                        EVENTS
    // =============================================================
    
    /**
     * @notice Emitted when a transaction is queued
     * @param txHash Transaction hash
     * @param target Target contract address
     * @param value ETH value to send
     * @param data Encoded function call
     * @param eta Estimated execution time (timestamp)
     */
    event TransactionQueued(
        bytes32 indexed txHash,
        address indexed target,
        uint256 value,
        bytes data,
        uint256 eta
    );
    
    /**
     * @notice Emitted when a transaction is executed
     * @param txHash Transaction hash
     * @param target Target contract address
     * @param value ETH value sent
     * @param data Encoded function call
     * @param eta Execution time
     */
    event TransactionExecuted(
        bytes32 indexed txHash,
        address indexed target,
        uint256 value,
        bytes data,
        uint256 eta
    );
    
    /**
     * @notice Emitted when a transaction is canceled
     * @param txHash Transaction hash
     */
    event TransactionCanceled(bytes32 indexed txHash);
    
    /**
     * @notice Emitted when the delay is updated
     * @param oldDelay Previous delay
     * @param newDelay New delay
     */
    event DelayUpdated(uint256 oldDelay, uint256 newDelay);
    
    /**
     * @notice Emitted when the admin is updated
     * @param oldAdmin Previous admin
     * @param newAdmin New admin
     */
    event AdminUpdated(address indexed oldAdmin, address indexed newAdmin);
    
    /**
     * @notice Emitted when the pending admin is updated
     * @param pendingAdmin New pending admin
     */
    event PendingAdminUpdated(address indexed pendingAdmin);
    
    // =============================================================
    //                    TRANSACTION FUNCTIONS
    // =============================================================
    
    /**
     * @notice Queue a transaction for execution
     * @dev Only callable by admin (Governor contract)
     * @param target Target contract address
     * @param value ETH value to send
     * @param data Encoded function call
     * @param eta Estimated execution time (must be >= block.timestamp + delay)
     * @return txHash Transaction hash
     */
    function queueTransaction(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 eta
    ) external returns (bytes32 txHash);
    
    /**
     * @notice Execute a queued transaction
     * @dev Only callable after delay has passed and within grace period
     * @param target Target contract address
     * @param value ETH value to send
     * @param data Encoded function call
     * @param eta Execution time (must match queued value)
     * @return Result of the executed transaction
     */
    function executeTransaction(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 eta
    ) external payable returns (bytes memory);
    
    /**
     * @notice Cancel a queued transaction
     * @dev Only callable by admin
     * @param txHash Transaction hash to cancel
     */
    function cancelTransaction(bytes32 txHash) external;
    
    // =============================================================
    //                    ADMIN FUNCTIONS
    // =============================================================
    
    /**
     * @notice Set a new pending admin
     * @dev Two-step admin transfer for safety
     * @param newPendingAdmin Address of new pending admin
     */
    function setPendingAdmin(address newPendingAdmin) external;
    
    /**
     * @notice Accept admin role
     * @dev Must be called by pending admin
     */
    function acceptAdmin() external;
    
    /**
     * @notice Update the delay
     * @dev Only callable by timelock itself (via governance)
     * @param newDelay New delay in seconds
     */
    function setDelay(uint256 newDelay) external;
    
    // =============================================================
    //                    VIEW FUNCTIONS
    // =============================================================
    
    /**
     * @notice Get the current admin (Governor contract)
     * @return Admin address
     */
    function admin() external view returns (address);
    
    /**
     * @notice Get the pending admin
     * @return Pending admin address
     */
    function pendingAdmin() external view returns (address);
    
    /**
     * @notice Get the current delay
     * @return Delay in seconds
     */
    function delay() external view returns (uint256);
    
    /**
     * @notice Get the grace period
     * @return Grace period in seconds
     */
    function gracePeriod() external view returns (uint256);
    
    /**
     * @notice Check if a transaction is queued
     * @param txHash Transaction hash
     * @return Whether transaction is queued
     */
    function queuedTransactions(bytes32 txHash) external view returns (bool);
    
    /**
     * @notice Get transaction details
     * @param txHash Transaction hash
     * @return QueuedTransaction struct
     */
    function getTransaction(bytes32 txHash) external view returns (QueuedTransaction memory);
    
    /**
     * @notice Calculate transaction hash
     * @param target Target contract address
     * @param value ETH value
     * @param data Call data
     * @param eta Execution time
     * @return Transaction hash
     */
    function getTxHash(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 eta
    ) external pure returns (bytes32);
}
