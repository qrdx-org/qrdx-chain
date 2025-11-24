// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IGovernor
 * @notice Interface for the QRDX quantum-resistant governance system
 * 
 * Enables decentralized protocol governance through:
 * - Proposal creation with multiple actions
 * - Quantum-resistant voting (Dilithium signatures)
 * - Time-locked execution
 * - Quorum and threshold enforcement
 */
interface IGovernor {
    // =============================================================
    //                        ENUMS
    // =============================================================
    
    /**
     * @notice Proposal lifecycle states
     * 
     * State transitions:
     * Pending → Active → Defeated
     *                  → Succeeded → Queued → Executed
     *                                       → Expired
     *                              → Canceled
     */
    enum ProposalState {
        Pending,    // Proposal created, voting not yet started
        Active,     // Voting period active
        Canceled,   // Proposal canceled by proposer
        Defeated,   // Proposal failed (quorum not met or more against than for)
        Succeeded,  // Proposal passed (quorum met and threshold reached)
        Queued,     // Proposal queued in timelock
        Expired,    // Proposal expired (not executed within grace period)
        Executed    // Proposal executed successfully
    }
    
    /**
     * @notice Vote support types
     */
    enum VoteType {
        Against,    // Vote against the proposal
        For,        // Vote for the proposal
        Abstain     // Abstain from voting (counts toward quorum)
    }
    
    // =============================================================
    //                        STRUCTS
    // =============================================================
    
    /**
     * @notice Proposal data structure
     * @dev Stores all proposal information including votes and execution data
     */
    struct Proposal {
        uint256 id;                 // Unique proposal ID
        address proposer;           // Address that created the proposal
        string title;               // Short proposal title
        string description;         // Detailed proposal description
        address[] targets;          // Target contracts to call
        uint256[] values;           // ETH values for each call
        bytes[] calldatas;          // Encoded function calls
        uint256 startBlock;         // Block voting starts
        uint256 endBlock;           // Block voting ends
        uint256 forVotes;           // Total votes in favor
        uint256 againstVotes;       // Total votes against
        uint256 abstainVotes;       // Total abstain votes
        bool canceled;              // Whether proposal was canceled
        bool executed;              // Whether proposal was executed
    }
    
    /**
     * @notice Vote receipt for a voter
     * @dev Tracks individual voting records with quantum-resistant signatures
     */
    struct Receipt {
        bool hasVoted;              // Whether voter has voted
        uint8 support;              // Vote type (0=against, 1=for, 2=abstain)
        uint256 votes;              // Voting power used
        bytes dilithiumSignature;   // Dilithium signature (3,309 bytes)
        bytes32 dilithiumPublicKey; // Voter's Dilithium public key hash
    }
    
    // =============================================================
    //                        EVENTS
    // =============================================================
    
    /**
     * @notice Emitted when a new proposal is created
     * @param proposalId Unique proposal identifier
     * @param proposer Address that created the proposal
     * @param targets Target contracts to execute
     * @param values ETH values for each call
     * @param signatures Function signatures (for display)
     * @param calldatas Encoded function call data
     * @param startBlock Block number when voting starts
     * @param endBlock Block number when voting ends
     * @param description Proposal description
     */
    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        address[] targets,
        uint256[] values,
        string[] signatures,
        bytes[] calldatas,
        uint256 startBlock,
        uint256 endBlock,
        string description
    );
    
    /**
     * @notice Emitted when a vote is cast
     * @param voter Address that cast the vote
     * @param proposalId Proposal being voted on
     * @param support Vote type (0=against, 1=for, 2=abstain)
     * @param votes Voting power used
     * @param reason Optional vote reason string
     */
    event VoteCast(
        address indexed voter,
        uint256 indexed proposalId,
        uint8 support,
        uint256 votes,
        string reason
    );
    
    /**
     * @notice Emitted when a vote is cast with quantum-resistant signature
     * @param voter Address that cast the vote
     * @param proposalId Proposal being voted on
     * @param support Vote type (0=against, 1=for, 2=abstain)
     * @param votes Voting power used
     * @param reason Optional vote reason string
     * @param dilithiumSignature Quantum-resistant signature
     */
    event VoteCastWithSignature(
        address indexed voter,
        uint256 indexed proposalId,
        uint8 support,
        uint256 votes,
        string reason,
        bytes dilithiumSignature
    );
    
    /**
     * @notice Emitted when a proposal is canceled
     * @param proposalId Proposal that was canceled
     */
    event ProposalCanceled(uint256 indexed proposalId);
    
    /**
     * @notice Emitted when a proposal is queued for execution
     * @param proposalId Proposal that was queued
     * @param eta Estimated execution time (timestamp)
     */
    event ProposalQueued(uint256 indexed proposalId, uint256 eta);
    
    /**
     * @notice Emitted when a proposal is executed
     * @param proposalId Proposal that was executed
     */
    event ProposalExecuted(uint256 indexed proposalId);
    
    // =============================================================
    //                    PROPOSAL FUNCTIONS
    // =============================================================
    
    /**
     * @notice Create a new governance proposal
     * @dev Proposer must meet minimum proposal threshold
     * @param targets Target contracts to call
     * @param values ETH values for each call
     * @param calldatas Encoded function calls
     * @param title Short proposal title
     * @param description Detailed description with rationale
     * @return proposalId Unique identifier for the proposal
     */
    function propose(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory title,
        string memory description
    ) external returns (uint256 proposalId);
    
    /**
     * @notice Queue a succeeded proposal for execution
     * @dev Only callable after voting period ends and proposal succeeds
     * @param proposalId Proposal to queue
     */
    function queue(uint256 proposalId) external;
    
    /**
     * @notice Execute a queued proposal
     * @dev Only callable after timelock delay has passed
     * @param proposalId Proposal to execute
     */
    function execute(uint256 proposalId) external payable;
    
    /**
     * @notice Cancel a proposal
     * @dev Only callable by proposer or if proposer's voting power drops below threshold
     * @param proposalId Proposal to cancel
     */
    function cancel(uint256 proposalId) external;
    
    // =============================================================
    //                    VOTING FUNCTIONS
    // =============================================================
    
    /**
     * @notice Cast a vote on a proposal
     * @param proposalId Proposal to vote on
     * @param support Vote type (0=against, 1=for, 2=abstain)
     */
    function castVote(uint256 proposalId, uint8 support) external;
    
    /**
     * @notice Cast a vote with a reason string
     * @param proposalId Proposal to vote on
     * @param support Vote type (0=against, 1=for, 2=abstain)
     * @param reason Explanation for vote choice
     */
    function castVoteWithReason(
        uint256 proposalId,
        uint8 support,
        string calldata reason
    ) external;
    
    /**
     * @notice Cast a vote with quantum-resistant signature
     * @dev Enables offline voting and vote delegation
     * @param proposalId Proposal to vote on
     * @param support Vote type (0=against, 1=for, 2=abstain)
     * @param dilithiumSignature Quantum-resistant signature (3,309 bytes)
     * @param dilithiumPublicKey Voter's Dilithium public key (1,952 bytes)
     */
    function castVoteWithSignature(
        uint256 proposalId,
        uint8 support,
        bytes calldata dilithiumSignature,
        bytes calldata dilithiumPublicKey
    ) external;
    
    // =============================================================
    //                    VIEW FUNCTIONS
    // =============================================================
    
    /**
     * @notice Get the current state of a proposal
     * @param proposalId Proposal to check
     * @return Current ProposalState
     */
    function state(uint256 proposalId) external view returns (ProposalState);
    
    /**
     * @notice Get proposal details
     * @param proposalId Proposal to query
     * @return Proposal struct with all details
     */
    function getProposal(uint256 proposalId) external view returns (Proposal memory);
    
    /**
     * @notice Get voting receipt for a voter on a proposal
     * @param proposalId Proposal to query
     * @param voter Address of voter
     * @return Receipt struct with vote details
     */
    function getReceipt(uint256 proposalId, address voter) external view returns (Receipt memory);
    
    /**
     * @notice Get voting power of an address at a specific block
     * @param account Address to check
     * @param blockNumber Block number to query
     * @return Voting power (staked QRDX balance)
     */
    function getVotes(address account, uint256 blockNumber) external view returns (uint256);
    
    /**
     * @notice Get proposal threshold (minimum tokens to create proposal)
     * @return Minimum tokens required to propose
     */
    function proposalThreshold() external view returns (uint256);
    
    /**
     * @notice Get quorum requirement at a block number
     * @param blockNumber Block number to query
     * @return Minimum votes required for quorum
     */
    function quorum(uint256 blockNumber) external view returns (uint256);
    
    /**
     * @notice Get voting period duration in blocks
     * @return Number of blocks voting is active
     */
    function votingPeriod() external view returns (uint256);
    
    /**
     * @notice Get voting delay (blocks between proposal and voting start)
     * @return Number of blocks before voting starts
     */
    function votingDelay() external view returns (uint256);
    
    /**
     * @notice Get the current proposal count
     * @return Total number of proposals created
     */
    function proposalCount() external view returns (uint256);
    
    /**
     * @notice Check if an address has voted on a proposal
     * @param proposalId Proposal to check
     * @param voter Address to check
     * @return Whether the address has voted
     */
    function hasVoted(uint256 proposalId, address voter) external view returns (bool);
}
