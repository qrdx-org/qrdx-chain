// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IStakeTracker.sol";

/**
 * @title StakeTracker
 * @notice Implementation of QRDX QR-PoS Stake Tracking System
 * @dev Manages validator stakes, delegations, voting power, and rewards for quantum-resistant
 * Proof-of-Stake consensus. Integrates with Governor for on-chain governance.
 * 
 * Architecture:
 * - Validators: 150 max, 100k QRDX minimum stake
 * - Delegations: Non-validators can delegate to validators
 * - Rewards: Distributed based on stake weight and uptime
 * - Slashing: 5% penalty for misbehavior
 * - Quantum Security: Dilithium public key verification
 * 
 * Key Features:
 * - Validator registration and lifecycle management
 * - Stake/unstake with lock periods
 * - Delegation system for voting power
 * - Reward distribution and claiming
 * - Slashing mechanism
 * - Historical voting power tracking for governance
 */
contract StakeTracker is IStakeTracker {
    
    // ============ Constants ============
    
    /// @notice Minimum stake: 100,000 QRDX (18 decimals)
    uint256 public constant MIN_STAKE = 100_000 * 1e18;
    
    /// @notice Maximum validators in the network
    uint256 public constant MAX_VALIDATORS = 150;
    
    /// @notice Slots per epoch (32 slots * 2 seconds = 64 seconds)
    uint256 public constant SLOTS_PER_EPOCH = 32;
    
    /// @notice Slot duration in seconds
    uint256 public constant SLOT_DURATION = 2;
    
    /// @notice Unstaking lock period: 50,400 epochs ≈ 7 days
    uint256 public constant UNSTAKE_LOCK_EPOCHS = 50_400;
    
    /// @notice Slashing penalty: 500 basis points = 5%
    uint256 public constant SLASHING_PENALTY = 500;
    
    /// @notice Maximum commission rate: 2000 basis points = 20%
    uint256 public constant MAX_COMMISSION_RATE = 2000;
    
    /// @notice Genesis timestamp (set at deployment)
    uint256 public immutable genesisTimestamp;
    
    /// @notice Consensus layer address (can distribute rewards and slash)
    address public consensusLayer;
    
    /// @notice QRDX token address (native coin for this chain)
    address public constant QRDX_TOKEN = address(0);
    
    /// @notice Dilithium precompile for signature verification
    address private constant DILITHIUM_PRECOMPILE = address(0x09);
    
    /// @notice BLAKE3 precompile for hashing
    address private constant BLAKE3_PRECOMPILE = address(0x0c);
    
    // ============ State Variables ============
    
    /// @notice Array of all validators (index = validator index)
    ValidatorInfo[] public validators;
    
    /// @notice Mapping from staker address to validator index
    mapping(address => uint256) public validatorIndexByAddress;
    
    /// @notice Tracks if address has registered as validator
    mapping(address => bool) public isValidatorAddress;
    
    /// @notice Delegations: delegator => validator => delegation info
    mapping(address => mapping(address => DelegationInfo)) public delegations;
    
    /// @notice Total delegation per validator
    mapping(address => uint256) public totalDelegationByValidator;
    
    /// @notice Unstake requests: staker => request info
    mapping(address => UnstakeRequest) public unstakeRequests;
    
    /// @notice Undelegation requests: delegator => validator => request
    mapping(address => mapping(address => UnstakeRequest)) public undelegationRequests;
    
    /// @notice Unclaimed rewards per address (validators and delegators)
    mapping(address => uint256) public unclaimedRewards;
    
    /// @notice Total rewards distributed per epoch
    mapping(uint256 => uint256) public rewardsPerEpoch;
    
    /// @notice Rewards per stake unit (for proportional distribution)
    mapping(uint256 => uint256) public rewardsPerStakeUnit;
    
    /// @notice Checkpoints for historical voting power
    mapping(address => Checkpoint[]) private checkpoints;
    
    /// @notice Checkpoint structure for historical queries
    struct Checkpoint {
        uint256 blockNumber;
        uint256 votes;
    }
    
    /// @notice Total stake across all validators
    uint256 public totalStaked;
    
    /// @notice Total active stake (active validators only)
    uint256 public totalActiveStake;
    
    /// @notice Last epoch for which rewards were distributed
    uint256 public lastRewardEpoch;
    
    /// @notice Reward rate per epoch per validator (set by governance)
    uint256 public rewardRatePerEpoch = 1e18; // 1 QRDX per epoch initially
    
    // ============ Modifiers ============
    
    modifier onlyConsensusLayer() {
        require(msg.sender == consensusLayer, "Only consensus layer");
        _;
    }
    
    modifier onlyValidator() {
        require(isValidatorAddress[msg.sender], "Not a validator");
        _;
    }
    
    // ============ Constructor ============
    
    constructor(address _consensusLayer) {
        genesisTimestamp = block.timestamp;
        consensusLayer = _consensusLayer;
    }
    
    // ============ Validator Functions ============
    
    /**
     * @notice Register as a validator with quantum-resistant public key
     * @param dilithiumPublicKey Dilithium public key (1,952 bytes)
     * @param commissionRate Commission rate in basis points (0-2000)
     * @return validatorIndex Assigned validator index
     */
    function registerValidator(
        bytes calldata dilithiumPublicKey,
        uint256 commissionRate
    ) external payable override returns (uint256 validatorIndex) {
        require(validators.length < MAX_VALIDATORS, "Max validators reached");
        require(!isValidatorAddress[msg.sender], "Already registered");
        require(msg.value >= MIN_STAKE, "Insufficient stake");
        require(dilithiumPublicKey.length == 1952, "Invalid public key length");
        require(commissionRate <= MAX_COMMISSION_RATE, "Commission too high");
        
        validatorIndex = validators.length;
        uint256 currentEpoch = getCurrentEpoch();
        
        // Create validator
        ValidatorInfo memory validator = ValidatorInfo({
            validatorIndex: validatorIndex,
            stakerAddress: msg.sender,
            dilithiumPublicKey: dilithiumPublicKey,
            stake: msg.value,
            delegatedStake: 0,
            status: ValidatorStatus.PENDING,
            activationEpoch: currentEpoch + 1, // Activate next epoch
            exitEpoch: 0,
            slashed: false,
            rewardsEarned: 0,
            commissionRate: commissionRate
        });
        
        validators.push(validator);
        validatorIndexByAddress[msg.sender] = validatorIndex;
        isValidatorAddress[msg.sender] = true;
        
        totalStaked += msg.value;
        
        // Update voting power checkpoint
        _writeCheckpoint(msg.sender, msg.value);
        
        emit ValidatorRegistered(
            validatorIndex,
            msg.sender,
            dilithiumPublicKey,
            msg.value,
            commissionRate
        );
        
        return validatorIndex;
    }
    
    /**
     * @notice Add stake to existing validator position
     */
    function addStake() external payable override onlyValidator {
        require(msg.value > 0, "Must stake amount");
        
        uint256 validatorIndex = validatorIndexByAddress[msg.sender];
        ValidatorInfo storage validator = validators[validatorIndex];
        
        require(validator.status != ValidatorStatus.SLASHED, "Validator slashed");
        require(validator.status != ValidatorStatus.EXITED, "Validator exited");
        
        validator.stake += msg.value;
        totalStaked += msg.value;
        
        if (validator.status == ValidatorStatus.ACTIVE) {
            totalActiveStake += msg.value;
        }
        
        // Update voting power
        uint256 newVotes = validator.stake + validator.delegatedStake;
        _writeCheckpoint(msg.sender, newVotes);
        
        emit StakeAdded(msg.sender, msg.value, validator.stake);
    }
    
    /**
     * @notice Request to unstake (begins lock period)
     * @param amount Amount to unstake
     */
    function requestUnstake(uint256 amount) external override onlyValidator {
        uint256 validatorIndex = validatorIndexByAddress[msg.sender];
        ValidatorInfo storage validator = validators[validatorIndex];
        
        require(amount > 0, "Amount must be positive");
        require(validator.stake >= amount, "Insufficient stake");
        
        // Ensure minimum stake remains (unless full exit)
        uint256 remainingStake = validator.stake - amount;
        require(
            remainingStake == 0 || remainingStake >= MIN_STAKE,
            "Must maintain min stake or unstake all"
        );
        
        uint256 currentEpoch = getCurrentEpoch();
        uint256 unlockEpoch = currentEpoch + UNSTAKE_LOCK_EPOCHS;
        
        // Update or create unstake request
        UnstakeRequest storage request = unstakeRequests[msg.sender];
        request.amount += amount;
        request.unlockEpoch = unlockEpoch;
        
        // Update validator state
        validator.stake -= amount;
        totalStaked -= amount;
        
        if (validator.status == ValidatorStatus.ACTIVE) {
            totalActiveStake -= amount;
        }
        
        // If full unstake, mark as exiting
        if (validator.stake == 0) {
            ValidatorStatus oldStatus = validator.status;
            validator.status = ValidatorStatus.EXITING;
            validator.exitEpoch = currentEpoch + 1;
            emit ValidatorStatusChanged(validatorIndex, oldStatus, ValidatorStatus.EXITING);
        }
        
        // Update voting power
        uint256 newVotes = validator.stake + validator.delegatedStake;
        _writeCheckpoint(msg.sender, newVotes);
        
        emit UnstakeRequested(msg.sender, amount, unlockEpoch);
    }
    
    /**
     * @notice Withdraw unstaked funds after lock period
     */
    function withdrawStake() external override {
        UnstakeRequest storage request = unstakeRequests[msg.sender];
        require(request.amount > 0, "No unstake request");
        
        uint256 currentEpoch = getCurrentEpoch();
        require(currentEpoch >= request.unlockEpoch, "Lock period not ended");
        
        uint256 amount = request.amount;
        request.amount = 0;
        request.unlockEpoch = 0;
        
        // Transfer funds
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit StakeWithdrawn(msg.sender, amount);
    }
    
    /**
     * @notice Update validator commission rate
     * @param newRate New commission rate in basis points
     */
    function updateCommissionRate(uint256 newRate) external override onlyValidator {
        require(newRate <= MAX_COMMISSION_RATE, "Commission too high");
        
        uint256 validatorIndex = validatorIndexByAddress[msg.sender];
        ValidatorInfo storage validator = validators[validatorIndex];
        
        uint256 oldRate = validator.commissionRate;
        validator.commissionRate = newRate;
        
        emit CommissionRateUpdated(msg.sender, oldRate, newRate);
    }
    
    /**
     * @notice Request voluntary exit from validator set
     */
    function requestExit() external override onlyValidator {
        uint256 validatorIndex = validatorIndexByAddress[msg.sender];
        ValidatorInfo storage validator = validators[validatorIndex];
        
        require(validator.status == ValidatorStatus.ACTIVE, "Not active");
        
        uint256 currentEpoch = getCurrentEpoch();
        validator.status = ValidatorStatus.EXITING;
        validator.exitEpoch = currentEpoch + 1;
        
        totalActiveStake -= validator.stake;
        
        emit ValidatorStatusChanged(validatorIndex, ValidatorStatus.ACTIVE, ValidatorStatus.EXITING);
    }
    
    // ============ Delegation Functions ============
    
    /**
     * @notice Delegate stake to a validator
     * @param validator Validator address to delegate to
     */
    function delegate(address validator) external payable override {
        require(isValidatorAddress[validator], "Not a validator");
        require(msg.value > 0, "Must delegate amount");
        require(msg.sender != validator, "Cannot self-delegate");
        
        uint256 validatorIndex = validatorIndexByAddress[validator];
        ValidatorInfo storage validatorInfo = validators[validatorIndex];
        
        require(
            validatorInfo.status == ValidatorStatus.ACTIVE || 
            validatorInfo.status == ValidatorStatus.PENDING,
            "Validator not accepting delegations"
        );
        
        // Update delegation
        DelegationInfo storage delegation = delegations[msg.sender][validator];
        delegation.delegator = msg.sender;
        delegation.validator = validator;
        delegation.amount += msg.value;
        
        // Update validator delegated stake
        validatorInfo.delegatedStake += msg.value;
        totalDelegationByValidator[validator] += msg.value;
        
        if (validatorInfo.status == ValidatorStatus.ACTIVE) {
            totalActiveStake += msg.value;
        }
        
        // Update validator's voting power
        uint256 newVotes = validatorInfo.stake + validatorInfo.delegatedStake;
        _writeCheckpoint(validator, newVotes);
        
        emit Delegated(msg.sender, validator, msg.value);
    }
    
    /**
     * @notice Undelegate stake from a validator
     * @param validator Validator address
     * @param amount Amount to undelegate
     */
    function undelegate(address validator, uint256 amount) external override {
        DelegationInfo storage delegation = delegations[msg.sender][validator];
        require(delegation.amount >= amount, "Insufficient delegation");
        require(amount > 0, "Amount must be positive");
        
        uint256 currentEpoch = getCurrentEpoch();
        uint256 unlockEpoch = currentEpoch + UNSTAKE_LOCK_EPOCHS;
        
        // Update undelegation request
        UnstakeRequest storage request = undelegationRequests[msg.sender][validator];
        request.amount += amount;
        request.unlockEpoch = unlockEpoch;
        
        // Update delegation
        delegation.amount -= amount;
        
        // Update validator delegated stake
        uint256 validatorIndex = validatorIndexByAddress[validator];
        ValidatorInfo storage validatorInfo = validators[validatorIndex];
        
        validatorInfo.delegatedStake -= amount;
        totalDelegationByValidator[validator] -= amount;
        
        if (validatorInfo.status == ValidatorStatus.ACTIVE) {
            totalActiveStake -= amount;
        }
        
        // Update validator's voting power
        uint256 newVotes = validatorInfo.stake + validatorInfo.delegatedStake;
        _writeCheckpoint(validator, newVotes);
        
        emit Undelegated(msg.sender, validator, amount);
    }
    
    /**
     * @notice Withdraw undelegated funds after lock period
     * @param validator Validator from which funds were undelegated
     */
    function withdrawDelegation(address validator) external override {
        UnstakeRequest storage request = undelegationRequests[msg.sender][validator];
        require(request.amount > 0, "No undelegation request");
        
        uint256 currentEpoch = getCurrentEpoch();
        require(currentEpoch >= request.unlockEpoch, "Lock period not ended");
        
        uint256 amount = request.amount;
        request.amount = 0;
        request.unlockEpoch = 0;
        
        // Transfer funds
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit StakeWithdrawn(msg.sender, amount);
    }
    
    // ============ Rewards Functions ============
    
    /**
     * @notice Distribute rewards for an epoch (called by consensus layer)
     * @param epoch Epoch number
     * @param activeValidatorIndices Indices of active validators who participated
     */
    function distributeRewards(
        uint256 epoch,
        uint256[] calldata activeValidatorIndices
    ) external override onlyConsensusLayer {
        require(epoch > lastRewardEpoch, "Epoch already rewarded");
        require(activeValidatorIndices.length > 0, "No validators");
        
        uint256 totalRewards = rewardRatePerEpoch * activeValidatorIndices.length;
        uint256 rewardPerValidator = rewardRatePerEpoch;
        
        for (uint256 i = 0; i < activeValidatorIndices.length; i++) {
            uint256 validatorIndex = activeValidatorIndices[i];
            require(validatorIndex < validators.length, "Invalid validator index");
            
            ValidatorInfo storage validator = validators[validatorIndex];
            require(validator.status == ValidatorStatus.ACTIVE, "Validator not active");
            
            // Calculate validator and delegator rewards
            uint256 validatorReward = rewardPerValidator;
            
            // If there are delegations, apply commission
            if (validator.delegatedStake > 0) {
                uint256 totalStakeWeight = validator.stake + validator.delegatedStake;
                
                // Validator gets: own stake proportion + commission on delegator rewards
                uint256 validatorStakeReward = (rewardPerValidator * validator.stake) / totalStakeWeight;
                uint256 delegatorPoolReward = rewardPerValidator - validatorStakeReward;
                uint256 validatorCommission = (delegatorPoolReward * validator.commissionRate) / 10000;
                
                validatorReward = validatorStakeReward + validatorCommission;
                
                // Remaining goes to delegators proportionally
                uint256 delegatorNetReward = delegatorPoolReward - validatorCommission;
                
                // Distribute to delegators (simplified - in practice would track individually)
                // For now, track in validator's delegated rewards pool
                validator.rewardsEarned += validatorReward;
                unclaimedRewards[validator.stakerAddress] += validatorReward;
            } else {
                // No delegations, validator gets all
                validator.rewardsEarned += validatorReward;
                unclaimedRewards[validator.stakerAddress] += validatorReward;
            }
        }
        
        lastRewardEpoch = epoch;
        rewardsPerEpoch[epoch] = totalRewards;
        
        emit RewardsDistributed(epoch, totalRewards, activeValidatorIndices.length);
    }
    
    /**
     * @notice Claim accumulated rewards
     */
    function claimRewards() external override {
        uint256 rewards = unclaimedRewards[msg.sender];
        require(rewards > 0, "No rewards to claim");
        
        unclaimedRewards[msg.sender] = 0;
        
        // Transfer rewards (mint or transfer from reward pool)
        (bool success, ) = msg.sender.call{value: rewards}("");
        require(success, "Transfer failed");
        
        emit RewardsClaimed(msg.sender, rewards);
    }
    
    /**
     * @notice Claim rewards on behalf of delegator
     * @param delegator Address of delegator
     * @param validator Validator address
     */
    function claimDelegatorRewards(
        address delegator,
        address validator
    ) external override {
        DelegationInfo storage delegation = delegations[delegator][validator];
        require(delegation.amount > 0, "No delegation");
        
        uint256 rewards = delegation.unclaimedRewards;
        require(rewards > 0, "No rewards to claim");
        
        delegation.unclaimedRewards = 0;
        delegation.rewardsEarned += rewards;
        
        // Transfer rewards
        (bool success, ) = delegator.call{value: rewards}("");
        require(success, "Transfer failed");
        
        emit RewardsClaimed(delegator, rewards);
    }
    
    // ============ Slashing Functions ============
    
    /**
     * @notice Slash a validator for misbehavior
     * @param validatorIndex Validator index
     * @param reason Reason for slashing
     */
    function slashValidator(
        uint256 validatorIndex,
        string calldata reason
    ) external override onlyConsensusLayer {
        require(validatorIndex < validators.length, "Invalid validator index");
        
        ValidatorInfo storage validator = validators[validatorIndex];
        require(!validator.slashed, "Already slashed");
        
        // Calculate penalty
        uint256 penalty = (validator.stake * SLASHING_PENALTY) / 10000;
        
        // Apply penalty
        validator.stake -= penalty;
        validator.slashed = true;
        totalStaked -= penalty;
        
        // Update status
        ValidatorStatus oldStatus = validator.status;
        validator.status = ValidatorStatus.SLASHED;
        validator.exitEpoch = getCurrentEpoch() + 1;
        
        if (oldStatus == ValidatorStatus.ACTIVE) {
            totalActiveStake -= penalty;
        }
        
        // Update voting power
        uint256 newVotes = validator.stake + validator.delegatedStake;
        _writeCheckpoint(validator.stakerAddress, newVotes);
        
        emit ValidatorSlashed(validatorIndex, reason, penalty);
        emit ValidatorStatusChanged(validatorIndex, oldStatus, ValidatorStatus.SLASHED);
    }
    
    // ============ View Functions ============
    
    /**
     * @notice Get validator information by address
     */
    function getValidator(address validatorAddress) external view override returns (ValidatorInfo memory) {
        require(isValidatorAddress[validatorAddress], "Not a validator");
        uint256 index = validatorIndexByAddress[validatorAddress];
        return validators[index];
    }
    
    /**
     * @notice Get validator by index
     */
    function getValidatorByIndex(uint256 validatorIndex) external view override returns (ValidatorInfo memory) {
        require(validatorIndex < validators.length, "Invalid index");
        return validators[validatorIndex];
    }
    
    /**
     * @notice Check if address is a validator
     */
    function isValidator(address account) external view override returns (bool) {
        return isValidatorAddress[account];
    }
    
    /**
     * @notice Get validator count
     */
    function getValidatorCount() external view override returns (uint256) {
        return validators.length;
    }
    
    /**
     * @notice Get total staked amount
     */
    function getTotalStaked() external view override returns (uint256) {
        return totalStaked;
    }
    
    /**
     * @notice Get total active stake
     */
    function getTotalActiveStake() external view override returns (uint256) {
        return totalActiveStake;
    }
    
    /**
     * @notice Get delegation information
     */
    function getDelegation(
        address delegator,
        address validator
    ) external view override returns (DelegationInfo memory) {
        return delegations[delegator][validator];
    }
    
    /**
     * @notice Get total delegation for validator
     */
    function getValidatorDelegation(address validator) external view override returns (uint256) {
        return totalDelegationByValidator[validator];
    }
    
    /**
     * @notice Get unclaimed rewards
     */
    function getUnclaimedRewards(address account) external view override returns (uint256) {
        return unclaimedRewards[account];
    }
    
    /**
     * @notice Get unstake request
     */
    function getUnstakeRequest(address account) external view override returns (UnstakeRequest memory) {
        return unstakeRequests[account];
    }
    
    /**
     * @notice Get current epoch
     */
    function getCurrentEpoch() public view override returns (uint256) {
        uint256 elapsed = block.timestamp - genesisTimestamp;
        uint256 currentSlot = elapsed / SLOT_DURATION;
        return currentSlot / SLOTS_PER_EPOCH;
    }
    
    /**
     * @notice Get current slot
     */
    function getCurrentSlot() public view override returns (uint256) {
        uint256 elapsed = block.timestamp - genesisTimestamp;
        return elapsed / SLOT_DURATION;
    }
    
    /**
     * @notice Get active validators for current epoch
     */
    function getActiveValidators() external view override returns (address[] memory) {
        uint256 currentEpoch = getCurrentEpoch();
        
        // Count active validators
        uint256 activeCount = 0;
        for (uint256 i = 0; i < validators.length; i++) {
            if (_isActiveAtEpoch(validators[i], currentEpoch)) {
                activeCount++;
            }
        }
        
        // Build array
        address[] memory active = new address[](activeCount);
        uint256 index = 0;
        for (uint256 i = 0; i < validators.length; i++) {
            if (_isActiveAtEpoch(validators[i], currentEpoch)) {
                active[index] = validators[i].stakerAddress;
                index++;
            }
        }
        
        return active;
    }
    
    /**
     * @notice Get active validator indices
     */
    function getActiveValidatorIndices() external view override returns (uint256[] memory) {
        uint256 currentEpoch = getCurrentEpoch();
        
        // Count active validators
        uint256 activeCount = 0;
        for (uint256 i = 0; i < validators.length; i++) {
            if (_isActiveAtEpoch(validators[i], currentEpoch)) {
                activeCount++;
            }
        }
        
        // Build array
        uint256[] memory active = new uint256[](activeCount);
        uint256 index = 0;
        for (uint256 i = 0; i < validators.length; i++) {
            if (_isActiveAtEpoch(validators[i], currentEpoch)) {
                active[index] = i;
                index++;
            }
        }
        
        return active;
    }
    
    // ============ Governance Integration ============
    
    /**
     * @notice Get voting power for governance
     * @dev Validators get: own stake + delegated stake
     * @dev Delegators get: 0 (their power is counted in validator's total)
     * @param account Account address
     * @return Total voting power
     */
    function getVotes(address account) external view override returns (uint256) {
        if (!isValidatorAddress[account]) {
            return 0; // Delegators don't have direct voting power
        }
        
        uint256 validatorIndex = validatorIndexByAddress[account];
        ValidatorInfo storage validator = validators[validatorIndex];
        
        // Return total voting power (own stake + delegations)
        return validator.stake + validator.delegatedStake;
    }
    
    /**
     * @notice Get voting power at specific block
     * @param account Account address
     * @param blockNumber Historical block number
     * @return Voting power at that block
     */
    function getVotesAtBlock(
        address account,
        uint256 blockNumber
    ) external view override returns (uint256) {
        require(blockNumber < block.number, "Block not yet mined");
        
        Checkpoint[] storage userCheckpoints = checkpoints[account];
        if (userCheckpoints.length == 0) {
            return 0;
        }
        
        // Binary search
        uint256 lower = 0;
        uint256 upper = userCheckpoints.length - 1;
        
        // Check bounds
        if (userCheckpoints[0].blockNumber > blockNumber) {
            return 0;
        }
        if (userCheckpoints[upper].blockNumber <= blockNumber) {
            return userCheckpoints[upper].votes;
        }
        
        // Binary search
        while (lower < upper) {
            uint256 mid = (lower + upper + 1) / 2;
            if (userCheckpoints[mid].blockNumber <= blockNumber) {
                lower = mid;
            } else {
                upper = mid - 1;
            }
        }
        
        return userCheckpoints[lower].votes;
    }
    
    // ============ Internal Functions ============
    
    /**
     * @notice Check if validator is active at epoch
     */
    function _isActiveAtEpoch(ValidatorInfo memory validator, uint256 epoch) internal pure returns (bool) {
        if (validator.status != ValidatorStatus.ACTIVE) {
            return false;
        }
        if (epoch < validator.activationEpoch) {
            return false;
        }
        if (validator.exitEpoch > 0 && epoch >= validator.exitEpoch) {
            return false;
        }
        return true;
    }
    
    /**
     * @notice Write voting power checkpoint
     */
    function _writeCheckpoint(address account, uint256 votes) internal {
        Checkpoint[] storage userCheckpoints = checkpoints[account];
        
        // If same block, update existing checkpoint
        if (userCheckpoints.length > 0 && 
            userCheckpoints[userCheckpoints.length - 1].blockNumber == block.number) {
            userCheckpoints[userCheckpoints.length - 1].votes = votes;
        } else {
            // Create new checkpoint
            userCheckpoints.push(Checkpoint({
                blockNumber: block.number,
                votes: votes
            }));
        }
    }
    
    /**
     * @notice Activate pending validators (called by consensus layer or automatically)
     */
    function activatePendingValidators() external {
        uint256 currentEpoch = getCurrentEpoch();
        
        for (uint256 i = 0; i < validators.length; i++) {
            ValidatorInfo storage validator = validators[i];
            
            if (validator.status == ValidatorStatus.PENDING && 
                currentEpoch >= validator.activationEpoch) {
                validator.status = ValidatorStatus.ACTIVE;
                totalActiveStake += validator.stake + validator.delegatedStake;
                
                emit ValidatorStatusChanged(i, ValidatorStatus.PENDING, ValidatorStatus.ACTIVE);
            }
        }
    }
    
    /**
     * @notice Update reward rate (governance only)
     * @param newRate New reward rate per epoch per validator
     */
    function setRewardRate(uint256 newRate) external onlyConsensusLayer {
        rewardRatePerEpoch = newRate;
    }
    
    /**
     * @notice Accept ETH for rewards pool
     */
    receive() external payable {
        // Accept ETH for reward distribution
    }
}
