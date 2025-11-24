// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IQRDXBridge
 * @notice Interface for quantum-resistant ETH<->QRDX bridge
 * 
 * Enables trustless cross-chain asset transfers using:
 * - Merkle proof verification
 * - Dilithium signature validation (quantum-resistant)
 * - Validator consensus
 * - Time-locked deposits/withdrawals
 */
interface IQRDXBridge {
    // =============================================================
    //                          ENUMS
    // =============================================================
    
    enum TransferStatus {
        Pending,      // Transfer initiated, awaiting confirmation
        Confirmed,    // Confirmed by validators
        Completed,    // Tokens released
        Challenged,   // Under dispute
        Cancelled     // Transfer cancelled/expired
    }
    
    enum ChainId {
        Ethereum,     // Ethereum mainnet
        QRDX          // QRDX chain
    }
    
    // =============================================================
    //                          STRUCTS
    // =============================================================
    
    /**
     * @dev Cross-chain transfer request
     */
    struct TransferRequest {
        bytes32 id;                  // Unique transfer ID
        address sender;              // Sender address
        address recipient;           // Recipient address
        address token;               // Token address (0x0 for native)
        uint256 amount;              // Amount to transfer
        ChainId sourceChain;         // Source chain
        ChainId targetChain;         // Target chain
        uint256 timestamp;           // Request timestamp
        uint256 confirmations;       // Validator confirmations
        TransferStatus status;       // Current status
        bytes32 merkleRoot;          // Merkle root of inclusion proof
    }
    
    /**
     * @dev Validator information
     */
    struct Validator {
        address ethAddress;          // Ethereum address
        bytes dilithiumPublicKey;    // Dilithium public key (1952 bytes)
        uint256 stake;               // Staked amount
        bool active;                 // Active status
        uint256 confirmedTransfers;  // Number of transfers confirmed
        uint256 lastActiveBlock;     // Last activity block
    }
    
    /**
     * @dev Merkle proof for transfer verification
     */
    struct MerkleProof {
        bytes32[] proof;             // Merkle proof path
        bytes32 leaf;                // Leaf hash
        uint256 index;               // Leaf index
    }
    
    // =============================================================
    //                          EVENTS
    // =============================================================
    
    /**
     * @notice Emitted when a deposit is initiated
     */
    event DepositInitiated(
        bytes32 indexed transferId,
        address indexed sender,
        address indexed recipient,
        address token,
        uint256 amount,
        ChainId sourceChain,
        ChainId targetChain
    );
    
    /**
     * @notice Emitted when a transfer is confirmed by validators
     */
    event TransferConfirmed(
        bytes32 indexed transferId,
        address indexed validator,
        uint256 confirmations,
        uint256 requiredConfirmations
    );
    
    /**
     * @notice Emitted when a transfer is completed
     */
    event TransferCompleted(
        bytes32 indexed transferId,
        address indexed recipient,
        uint256 amount
    );
    
    /**
     * @notice Emitted when a transfer is challenged
     */
    event TransferChallenged(
        bytes32 indexed transferId,
        address indexed challenger,
        string reason
    );
    
    /**
     * @notice Emitted when a validator is added
     */
    event ValidatorAdded(
        address indexed ethAddress,
        bytes dilithiumPublicKey,
        uint256 stake
    );
    
    /**
     * @notice Emitted when a validator is removed
     */
    event ValidatorRemoved(
        address indexed ethAddress,
        uint256 returnedStake
    );
    
    // =============================================================
    //                     DEPOSIT FUNCTIONS
    // =============================================================
    
    /**
     * @notice Deposit ETH/tokens to bridge for transfer to QRDX
     * @param recipient Recipient address on target chain
     * @param token Token address (0x0 for ETH)
     * @param amount Amount to deposit
     * @return transferId Unique transfer identifier
     */
    function deposit(
        address recipient,
        address token,
        uint256 amount
    ) external payable returns (bytes32 transferId);
    
    /**
     * @notice Deposit ETH (convenience function)
     * @param recipient Recipient address on QRDX
     * @return transferId Unique transfer identifier
     */
    function depositETH(address recipient) external payable returns (bytes32 transferId);
    
    // =============================================================
    //                    WITHDRAWAL FUNCTIONS
    // =============================================================
    
    /**
     * @notice Withdraw tokens from QRDX to Ethereum
     * @param transferId Transfer ID from QRDX chain
     * @param proof Merkle proof of transfer on QRDX
     * @param dilithiumSignatures Validator Dilithium signatures
     * @return success Whether withdrawal succeeded
     */
    function withdraw(
        bytes32 transferId,
        MerkleProof calldata proof,
        bytes[] calldata dilithiumSignatures
    ) external returns (bool success);
    
    /**
     * @notice Claim tokens after transfer is confirmed
     * @param transferId Transfer identifier
     * @return amount Amount claimed
     */
    function claim(bytes32 transferId) external returns (uint256 amount);
    
    // =============================================================
    //                   VALIDATION FUNCTIONS
    // =============================================================
    
    /**
     * @notice Confirm a transfer (validator only)
     * @param transferId Transfer identifier
     * @param dilithiumSignature Validator's Dilithium signature
     * @return confirmed Whether transfer reached required confirmations
     */
    function confirmTransfer(
        bytes32 transferId,
        bytes calldata dilithiumSignature
    ) external returns (bool confirmed);
    
    /**
     * @notice Challenge a potentially fraudulent transfer
     * @param transferId Transfer identifier
     * @param proof Proof of fraud
     * @param reason Challenge reason
     */
    function challengeTransfer(
        bytes32 transferId,
        bytes calldata proof,
        string calldata reason
    ) external;
    
    /**
     * @notice Verify Merkle proof for a transfer
     * @param transferId Transfer identifier
     * @param proof Merkle proof
     * @return valid Whether proof is valid
     */
    function verifyMerkleProof(
        bytes32 transferId,
        MerkleProof calldata proof
    ) external view returns (bool valid);
    
    // =============================================================
    //                   VALIDATOR MANAGEMENT
    // =============================================================
    
    /**
     * @notice Add a validator to the bridge
     * @param ethAddress Ethereum address
     * @param dilithiumPublicKey Dilithium public key (1952 bytes)
     * @param stake Stake amount
     */
    function addValidator(
        address ethAddress,
        bytes calldata dilithiumPublicKey,
        uint256 stake
    ) external;
    
    /**
     * @notice Remove a validator from the bridge
     * @param ethAddress Validator's Ethereum address
     */
    function removeValidator(address ethAddress) external;
    
    /**
     * @notice Update validator stake
     * @param amount Amount to add/remove
     * @param increase Whether to increase (true) or decrease (false)
     */
    function updateValidatorStake(uint256 amount, bool increase) external;
    
    // =============================================================
    //                      VIEW FUNCTIONS
    // =============================================================
    
    /**
     * @notice Get transfer details
     * @param transferId Transfer identifier
     * @return request Transfer request details
     */
    function getTransfer(bytes32 transferId) external view returns (TransferRequest memory request);
    
    /**
     * @notice Get validator information
     * @param ethAddress Validator's Ethereum address
     * @return validator Validator details
     */
    function getValidator(address ethAddress) external view returns (Validator memory validator);
    
    /**
     * @notice Check if address is an active validator
     * @param ethAddress Address to check
     * @return isValidator Whether address is active validator
     */
    function isValidator(address ethAddress) external view returns (bool isValidator);
    
    /**
     * @notice Get number of active validators
     * @return count Validator count
     */
    function getValidatorCount() external view returns (uint256 count);
    
    /**
     * @notice Get required confirmations for transfers
     * @return required Number of required confirmations
     */
    function getRequiredConfirmations() external view returns (uint256 required);
    
    /**
     * @notice Get total locked value in bridge
     * @param token Token address (0x0 for ETH)
     * @return amount Locked amount
     */
    function getTotalLocked(address token) external view returns (uint256 amount);
}
