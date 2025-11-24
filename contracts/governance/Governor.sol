// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IGovernor.sol";
import "./ITimelock.sol";
import "../staking/IStakeTracker.sol";

/**
 * @title Governor
 * @notice Quantum-resistant governance system for QRDX protocol
 * 
 * Features:
 * - Proposal creation with multiple executable actions
 * - Dilithium signature verification for quantum-resistant voting
 * - Time-locked execution for security
 * - Quorum and threshold enforcement
 * - Integration with QR-PoS for voting power
 * 
 * Voting Parameters:
 * - Voting Period: 7 days (302,400 blocks @ 2 seconds/block)
 * - Voting Delay: 1 day (43,200 blocks)
 * - Quorum: 10% of total staked QRDX
 * - Approval Threshold: 66% of votes cast
 * - Proposal Threshold: 1% of staked QRDX (15,000 QRDX if 1.5M staked)
 */
contract Governor is IGovernor {
    // =============================================================
    //                        CONSTANTS
    // =============================================================
    
    /// @dev Dilithium signature verification precompile
    address constant DILITHIUM_PRECOMPILE = address(0x09);
    
    /// @dev BLAKE3 hashing precompile
    address constant BLAKE3_PRECOMPILE = address(0x0c);
    
    /// @notice Voting period duration (7 days in blocks)
    uint256 public constant VOTING_PERIOD = 302_400; // 7 days @ 2s/block
    
    /// @notice Voting delay before voting starts (1 day in blocks)
    uint256 public constant VOTING_DELAY = 43_200; // 1 day @ 2s/block
    
    /// @notice Quorum percentage (10% of staked QRDX)
    uint256 public constant QUORUM_PERCENTAGE = 10;
    
    /// @notice Approval threshold percentage (66% of votes cast)
    uint256 public constant APPROVAL_THRESHOLD = 66;
    
    /// @notice Proposal threshold percentage (1% of staked QRDX to propose)
    uint256 public constant PROPOSAL_THRESHOLD_PERCENTAGE = 1;
    
    /// @dev Dilithium public key size
    uint256 constant DILITHIUM_PUBLIC_KEY_SIZE = 1952;
    
    /// @dev Dilithium signature size
    uint256 constant DILITHIUM_SIGNATURE_SIZE = 3309;
    
    // =============================================================
    //                        STORAGE
    // =============================================================
    
    /// @notice Name of the governance system
    string public name;
    
    /// @notice Timelock contract for delayed execution
    ITimelock public timelock;
    
    /// @notice QR-PoS stake tracker for voting power
    address public stakeTracker;
    
    /// @notice Total number of proposals created
    uint256 public proposalCount;
    
    /// @notice Mapping of proposal ID to proposal data
    mapping(uint256 => ProposalData) private proposals;
    
    /// @notice Mapping of proposal ID to voter to receipt
    mapping(uint256 => mapping(address => Receipt)) private receipts;
    
    /// @notice Mapping to track used Dilithium signature nonces (prevent replay)
    mapping(bytes32 => bool) private usedSignatures;
    
    /**
     * @dev Internal proposal structure with additional data
     */
    struct ProposalData {
        uint256 id;
        address proposer;
        string title;
        string description;
        address[] targets;
        uint256[] values;
        bytes[] calldatas;
        uint256 startBlock;
        uint256 endBlock;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 abstainVotes;
        bool canceled;
        bool executed;
        uint256 eta; // Execution time after queueing
    }
    
    // =============================================================
    //                        CONSTRUCTOR
    // =============================================================
    
    /**
     * @notice Initialize the Governor contract
     * @param _name Name of the governance system
     * @param _timelock Address of the Timelock contract
     * @param _stakeTracker Address of the QR-PoS stake tracker
     */
    constructor(
        string memory _name,
        address _timelock,
        address _stakeTracker
    ) {
        require(_timelock != address(0), "Invalid timelock");
        require(_stakeTracker != address(0), "Invalid stake tracker");
        
        name = _name;
        timelock = ITimelock(_timelock);
        stakeTracker = _stakeTracker;
    }
    
    // =============================================================
    //                    PROPOSAL FUNCTIONS
    // =============================================================
    
    /**
     * @inheritdoc IGovernor
     */
    function propose(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory title,
        string memory description
    ) external override returns (uint256) {
        // Validate proposer has sufficient voting power
        uint256 proposerVotes = getVotes(msg.sender, block.number - 1);
        require(
            proposerVotes >= proposalThreshold(),
            "Insufficient voting power to propose"
        );
        
        // Validate proposal data
        require(targets.length > 0, "Must provide actions");
        require(targets.length == values.length, "Length mismatch: targets/values");
        require(targets.length == calldatas.length, "Length mismatch: targets/calldatas");
        require(targets.length <= 10, "Too many actions");
        require(bytes(title).length > 0, "Title required");
        require(bytes(description).length > 0, "Description required");
        
        // Create proposal
        uint256 proposalId = ++proposalCount;
        uint256 startBlock = block.number + VOTING_DELAY;
        uint256 endBlock = startBlock + VOTING_PERIOD;
        
        ProposalData storage proposal = proposals[proposalId];
        proposal.id = proposalId;
        proposal.proposer = msg.sender;
        proposal.title = title;
        proposal.description = description;
        proposal.targets = targets;
        proposal.values = values;
        proposal.calldatas = calldatas;
        proposal.startBlock = startBlock;
        proposal.endBlock = endBlock;
        
        // Emit event
        string[] memory signatures = new string[](targets.length);
        for (uint256 i = 0; i < targets.length; i++) {
            signatures[i] = _extractFunctionSignature(calldatas[i]);
        }
        
        emit ProposalCreated(
            proposalId,
            msg.sender,
            targets,
            values,
            signatures,
            calldatas,
            startBlock,
            endBlock,
            description
        );
        
        return proposalId;
    }
    
    /**
     * @inheritdoc IGovernor
     */
    function queue(uint256 proposalId) external override {
        require(state(proposalId) == ProposalState.Succeeded, "Proposal not succeeded");
        
        ProposalData storage proposal = proposals[proposalId];
        uint256 eta = block.timestamp + timelock.delay();
        proposal.eta = eta;
        
        // Queue all actions in the timelock
        for (uint256 i = 0; i < proposal.targets.length; i++) {
            timelock.queueTransaction(
                proposal.targets[i],
                proposal.values[i],
                proposal.calldatas[i],
                eta
            );
        }
        
        emit ProposalQueued(proposalId, eta);
    }
    
    /**
     * @inheritdoc IGovernor
     */
    function execute(uint256 proposalId) external payable override {
        require(state(proposalId) == ProposalState.Queued, "Proposal not queued");
        
        ProposalData storage proposal = proposals[proposalId];
        proposal.executed = true;
        
        // Execute all actions through the timelock
        for (uint256 i = 0; i < proposal.targets.length; i++) {
            timelock.executeTransaction{value: proposal.values[i]}(
                proposal.targets[i],
                proposal.values[i],
                proposal.calldatas[i],
                proposal.eta
            );
        }
        
        emit ProposalExecuted(proposalId);
    }
    
    /**
     * @inheritdoc IGovernor
     */
    function cancel(uint256 proposalId) external override {
        ProposalData storage proposal = proposals[proposalId];
        ProposalState currentState = state(proposalId);
        
        require(
            currentState != ProposalState.Executed,
            "Cannot cancel executed proposal"
        );
        
        // Allow cancellation if:
        // 1. Called by proposer
        // 2. Proposer's voting power dropped below threshold
        require(
            msg.sender == proposal.proposer ||
            getVotes(proposal.proposer, block.number - 1) < proposalThreshold(),
            "Only proposer or if below threshold"
        );
        
        proposal.canceled = true;
        
        emit ProposalCanceled(proposalId);
    }
    
    // =============================================================
    //                    VOTING FUNCTIONS
    // =============================================================
    
    /**
     * @inheritdoc IGovernor
     */
    function castVote(uint256 proposalId, uint8 support) external override {
        return _castVote(msg.sender, proposalId, support, "");
    }
    
    /**
     * @inheritdoc IGovernor
     */
    function castVoteWithReason(
        uint256 proposalId,
        uint8 support,
        string calldata reason
    ) external override {
        return _castVote(msg.sender, proposalId, support, reason);
    }
    
    /**
     * @inheritdoc IGovernor
     */
    function castVoteWithSignature(
        uint256 proposalId,
        uint8 support,
        bytes calldata dilithiumSignature,
        bytes calldata dilithiumPublicKey
    ) external override {
        // Validate signature size
        require(
            dilithiumSignature.length == DILITHIUM_SIGNATURE_SIZE,
            "Invalid signature length"
        );
        require(
            dilithiumPublicKey.length == DILITHIUM_PUBLIC_KEY_SIZE,
            "Invalid public key length"
        );
        
        // Verify signature hasn't been used
        bytes32 sigHash = keccak256(dilithiumSignature);
        require(!usedSignatures[sigHash], "Signature already used");
        
        // Extract voter address from public key (last 20 bytes of BLAKE3 hash)
        bytes32 pubKeyHash = _blake3Hash(dilithiumPublicKey);
        address voter = address(uint160(uint256(pubKeyHash)));
        
        // Create message to verify (proposal ID + support)
        bytes memory message = abi.encodePacked(
            "vote",
            proposalId,
            support,
            block.chainid
        );
        
        // Verify Dilithium signature
        require(
            _verifyDilithiumSignature(message, dilithiumSignature, dilithiumPublicKey),
            "Invalid signature"
        );
        
        // Mark signature as used
        usedSignatures[sigHash] = true;
        
        // Cast vote
        _castVote(voter, proposalId, support, "");
        
        emit VoteCastWithSignature(
            voter,
            proposalId,
            support,
            getVotes(voter, proposals[proposalId].startBlock),
            "",
            dilithiumSignature
        );
    }
    
    /**
     * @dev Internal vote casting logic
     */
    function _castVote(
        address voter,
        uint256 proposalId,
        uint8 support,
        string memory reason
    ) internal {
        require(state(proposalId) == ProposalState.Active, "Voting not active");
        require(support <= uint8(VoteType.Abstain), "Invalid vote type");
        
        ProposalData storage proposal = proposals[proposalId];
        Receipt storage receipt = receipts[proposalId][voter];
        
        require(!receipt.hasVoted, "Already voted");
        
        // Get voting power at proposal start block
        uint256 votes = getVotes(voter, proposal.startBlock);
        require(votes > 0, "No voting power");
        
        // Record vote
        receipt.hasVoted = true;
        receipt.support = support;
        receipt.votes = votes;
        
        // Update vote tallies
        if (support == uint8(VoteType.Against)) {
            proposal.againstVotes += votes;
        } else if (support == uint8(VoteType.For)) {
            proposal.forVotes += votes;
        } else {
            proposal.abstainVotes += votes;
        }
        
        emit VoteCast(voter, proposalId, support, votes, reason);
    }
    
    // =============================================================
    //                    VIEW FUNCTIONS
    // =============================================================
    
    /**
     * @inheritdoc IGovernor
     */
    function state(uint256 proposalId) public view override returns (ProposalState) {
        ProposalData storage proposal = proposals[proposalId];
        require(proposal.id != 0, "Proposal does not exist");
        
        if (proposal.canceled) {
            return ProposalState.Canceled;
        }
        
        if (proposal.executed) {
            return ProposalState.Executed;
        }
        
        if (block.number <= proposal.startBlock) {
            return ProposalState.Pending;
        }
        
        if (block.number <= proposal.endBlock) {
            return ProposalState.Active;
        }
        
        // Check if proposal succeeded
        uint256 totalVotes = proposal.forVotes + proposal.againstVotes + proposal.abstainVotes;
        uint256 quorumVotes = quorum(proposal.startBlock);
        
        // Failed if quorum not met
        if (totalVotes < quorumVotes) {
            return ProposalState.Defeated;
        }
        
        // Failed if not enough support
        uint256 approvalVotes = (proposal.forVotes * 100) / (proposal.forVotes + proposal.againstVotes);
        if (approvalVotes < APPROVAL_THRESHOLD) {
            return ProposalState.Defeated;
        }
        
        // Check if queued
        if (proposal.eta == 0) {
            return ProposalState.Succeeded;
        }
        
        // Check if expired
        if (block.timestamp > proposal.eta + timelock.gracePeriod()) {
            return ProposalState.Expired;
        }
        
        return ProposalState.Queued;
    }
    
    /**
     * @inheritdoc IGovernor
     */
    function getProposal(uint256 proposalId) external view override returns (Proposal memory) {
        ProposalData storage data = proposals[proposalId];
        require(data.id != 0, "Proposal does not exist");
        
        return Proposal({
            id: data.id,
            proposer: data.proposer,
            title: data.title,
            description: data.description,
            targets: data.targets,
            values: data.values,
            calldatas: data.calldatas,
            startBlock: data.startBlock,
            endBlock: data.endBlock,
            forVotes: data.forVotes,
            againstVotes: data.againstVotes,
            abstainVotes: data.abstainVotes,
            canceled: data.canceled,
            executed: data.executed
        });
    }
    
    /**
     * @inheritdoc IGovernor
     */
    function getReceipt(
        uint256 proposalId,
        address voter
    ) external view override returns (Receipt memory) {
        return receipts[proposalId][voter];
    }
    
    /**
     * @inheritdoc IGovernor
     */
    function getVotes(address account, uint256 blockNumber) public view override returns (uint256) {
        // Query QR-PoS stake tracker for voting power at specific block
        return IStakeTracker(stakeTracker).getVotesAtBlock(account, blockNumber);
    }
    
    /**
     * @inheritdoc IGovernor
     */
    function proposalThreshold() public view override returns (uint256) {
        // 1% of total staked QRDX
        uint256 totalStaked = _getTotalStaked();
        return (totalStaked * PROPOSAL_THRESHOLD_PERCENTAGE) / 100;
    }
    
    /**
     * @inheritdoc IGovernor
     */
    function quorum(uint256 blockNumber) public view override returns (uint256) {
        // 10% of total staked QRDX at the given block
        uint256 totalStaked = _getTotalStaked();
        return (totalStaked * QUORUM_PERCENTAGE) / 100;
    }
    
    /**
     * @inheritdoc IGovernor
     */
    function votingPeriod() external pure override returns (uint256) {
        return VOTING_PERIOD;
    }
    
    /**
     * @inheritdoc IGovernor
     */
    function votingDelay() external pure override returns (uint256) {
        return VOTING_DELAY;
    }
    
    /**
     * @inheritdoc IGovernor
     */
    function hasVoted(uint256 proposalId, address voter) external view override returns (bool) {
        return receipts[proposalId][voter].hasVoted;
    }
    
    // =============================================================
    //                    INTERNAL FUNCTIONS
    // =============================================================
    
    /**
     * @dev Verify Dilithium signature using precompile
     */
    function _verifyDilithiumSignature(
        bytes memory message,
        bytes memory signature,
        bytes memory publicKey
    ) internal view returns (bool) {
        // Call Dilithium precompile at 0x09
        // Input: message || signature || publicKey
        // Output: 1 byte (0x01 = valid, 0x00 = invalid)
        
        (bool success, bytes memory result) = DILITHIUM_PRECOMPILE.staticcall(
            abi.encodePacked(message, signature, publicKey)
        );
        
        return success && result.length == 1 && result[0] == 0x01;
    }
    
    /**
     * @dev Hash data using BLAKE3 precompile
     */
    function _blake3Hash(bytes memory data) internal view returns (bytes32) {
        // Call BLAKE3 precompile at 0x0c
        (bool success, bytes memory result) = BLAKE3_PRECOMPILE.staticcall(data);
        require(success && result.length == 32, "BLAKE3 hash failed");
        
        return bytes32(result);
    }
    
    /**
     * @dev Get total staked QRDX from stake tracker
     */
    function _getTotalStaked() internal view returns (uint256) {
        // Query stake tracker for total active stake
        return IStakeTracker(stakeTracker).getTotalActiveStake();
    }
    
    /**
     * @dev Extract function signature from calldata
     */
    function _extractFunctionSignature(bytes memory data) internal pure returns (string memory) {
        if (data.length < 4) {
            return "unknown()";
        }
        
        bytes4 selector;
        assembly {
            selector := mload(add(data, 32))
        }
        
        // Return selector as hex string
        return string(abi.encodePacked(
            "0x",
            _toHexString(uint32(selector))
        ));
    }
    
    /**
     * @dev Convert uint to hex string
     */
    function _toHexString(uint256 value) internal pure returns (string memory) {
        bytes memory buffer = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            buffer[7 - i] = _toHexChar(uint8(value & 0xf));
            value >>= 4;
        }
        return string(buffer);
    }
    
    /**
     * @dev Convert uint8 to hex character
     */
    function _toHexChar(uint8 value) internal pure returns (bytes1) {
        if (value < 10) {
            return bytes1(uint8(bytes1('0')) + value);
        }
        return bytes1(uint8(bytes1('a')) + (value - 10));
    }
}
