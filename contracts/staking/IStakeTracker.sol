// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IStakeTracker
 * @notice Interface for QRDX QR-PoS Stake Tracking System
 * @dev Tracks validator stakes, delegations, voting power, and rewards for the quantum-resistant
 * Proof-of-Stake consensus mechanism. Integrates with Governor for on-chain governance.
 * 
 * Key Features:
 * - Validator registration and stake management
 * - Delegation system for non-validator token holders
 * - Voting power calculation for governance
 * - Reward distribution to validators and delegators
 * - Slashing mechanism for misbehavior
 * - Quantum-resistant Dilithium signature verification
 */
interface IStakeTracker {
    
    // ============ Enums ============
    
    /**
     * @notice Validator lifecycle states
     * @dev Matches the ValidatorStatus enum from py-evm/eth/consensus/qrpos.py
     */
    enum ValidatorStatus {
        PENDING,    // Waiting to be activated
        ACTIVE,     // Currently validating
        EXITING,    // Requested exit
        SLASHED,    // Penalized for misbehavior
        EXITED      // No longer validating
    }
    
    // ============ Structs ============
    
    /**
     * @notice Validator information
     * @param validatorIndex Unique validator index (0-149)
     * @param stakerAddress Address that staked for this validator
     * @param dilithiumPublicKey Quantum-resistant public key (1,952 bytes)
     * @param stake Amount staked in wei
     * @param delegatedStake Total stake delegated to this validator
     * @param status Current validator status
     * @param activationEpoch Epoch when validator became active
     * @param exitEpoch Epoch when validator will exit (0 if not exiting)
     * @param slashed Whether validator has been slashed
     * @param rewardsEarned Lifetime rewards earned
     * @param commissionRate Percentage of delegator rewards taken (basis points, e.g., 1000 = 10%)
     */
    struct ValidatorInfo {
        uint256 validatorIndex;
        address stakerAddress;
        bytes dilithiumPublicKey;
        uint256 stake;
        uint256 delegatedStake;
        ValidatorStatus status;
        uint256 activationEpoch;
        uint256 exitEpoch;
        bool slashed;
        uint256 rewardsEarned;
        uint256 commissionRate;
    }
    
    /**
     * @notice Delegation information
     * @param delegator Address of delegator
     * @param validator Validator being delegated to
     * @param amount Amount delegated
     * @param rewardsEarned Lifetime rewards earned
     * @param unclaimedRewards Rewards not yet claimed
     */
    struct DelegationInfo {
        address delegator;
        address validator;
        uint256 amount;
        uint256 rewardsEarned;
        uint256 unclaimedRewards;
    }
    
    /**
     * @notice Unstaking request information
     * @param amount Amount to unstake
     * @param unlockEpoch Epoch when funds can be withdrawn
     */
    struct UnstakeRequest {
        uint256 amount;
        uint256 unlockEpoch;
    }
    
    // ============ Events ============
    
    /**
     * @notice Emitted when a validator registers
     * @param validatorIndex Validator's unique index
     * @param stakerAddress Address that registered
     * @param dilithiumPublicKey Validator's public key
     * @param stake Initial stake amount
     * @param commissionRate Commission rate in basis points
     */
    event ValidatorRegistered(
        uint256 indexed validatorIndex,
        address indexed stakerAddress,
        bytes dilithiumPublicKey,
        uint256 stake,
        uint256 commissionRate
    );
    
    /**
     * @notice Emitted when stake is added
     * @param validator Validator address
     * @param amount Amount added
     * @param newTotalStake New total stake
     */
    event StakeAdded(
        address indexed validator,
        uint256 amount,
        uint256 newTotalStake
    );
    
    /**
     * @notice Emitted when unstake is requested
     * @param validator Validator address
     * @param amount Amount to unstake
     * @param unlockEpoch Epoch when unlock occurs
     */
    event UnstakeRequested(
        address indexed validator,
        uint256 amount,
        uint256 unlockEpoch
    );
    
    /**
     * @notice Emitted when stake is withdrawn
     * @param validator Validator address
     * @param amount Amount withdrawn
     */
    event StakeWithdrawn(
        address indexed validator,
        uint256 amount
    );
    
    /**
     * @notice Emitted when delegation occurs
     * @param delegator Delegator address
     * @param validator Validator address
     * @param amount Amount delegated
     */
    event Delegated(
        address indexed delegator,
        address indexed validator,
        uint256 amount
    );
    
    /**
     * @notice Emitted when delegation is removed
     * @param delegator Delegator address
     * @param validator Validator address
     * @param amount Amount undelegated
     */
    event Undelegated(
        address indexed delegator,
        address indexed validator,
        uint256 amount
    );
    
    /**
     * @notice Emitted when rewards are distributed
     * @param epoch Epoch for which rewards are distributed
     * @param totalRewards Total rewards distributed
     * @param validatorCount Number of validators receiving rewards
     */
    event RewardsDistributed(
        uint256 indexed epoch,
        uint256 totalRewards,
        uint256 validatorCount
    );
    
    /**
     * @notice Emitted when rewards are claimed
     * @param recipient Address receiving rewards
     * @param amount Amount claimed
     */
    event RewardsClaimed(
        address indexed recipient,
        uint256 amount
    );
    
    /**
     * @notice Emitted when a validator is slashed
     * @param validatorIndex Validator index
     * @param reason Reason for slashing
     * @param penaltyAmount Amount slashed
     */
    event ValidatorSlashed(
        uint256 indexed validatorIndex,
        string reason,
        uint256 penaltyAmount
    );
    
    /**
     * @notice Emitted when validator status changes
     * @param validatorIndex Validator index
     * @param oldStatus Previous status
     * @param newStatus New status
     */
    event ValidatorStatusChanged(
        uint256 indexed validatorIndex,
        ValidatorStatus oldStatus,
        ValidatorStatus newStatus
    );
    
    /**
     * @notice Emitted when commission rate is updated
     * @param validator Validator address
     * @param oldRate Old commission rate
     * @param newRate New commission rate
     */
    event CommissionRateUpdated(
        address indexed validator,
        uint256 oldRate,
        uint256 newRate
    );
    
    // ============ Constants ============
    
    /**
     * @notice Minimum stake required to become a validator (100,000 QRDX)
     */
    function MIN_STAKE() external view returns (uint256);
    
    /**
     * @notice Maximum number of validators (150)
     */
    function MAX_VALIDATORS() external view returns (uint256);
    
    /**
     * @notice Slots per epoch (32 slots = 64 seconds)
     */
    function SLOTS_PER_EPOCH() external view returns (uint256);
    
    /**
     * @notice Unstaking lock period in epochs (e.g., 7 days)
     */
    function UNSTAKE_LOCK_EPOCHS() external view returns (uint256);
    
    /**
     * @notice Slashing penalty percentage (basis points, e.g., 500 = 5%)
     */
    function SLASHING_PENALTY() external view returns (uint256);
    
    /**
     * @notice Maximum commission rate (basis points, e.g., 2000 = 20%)
     */
    function MAX_COMMISSION_RATE() external view returns (uint256);
    
    // ============ Validator Functions ============
    
    /**
     * @notice Register as a validator
     * @param dilithiumPublicKey Quantum-resistant public key (1,952 bytes)
     * @param commissionRate Commission rate in basis points (0-2000)
     * @return validatorIndex The assigned validator index
     */
    function registerValidator(
        bytes calldata dilithiumPublicKey,
        uint256 commissionRate
    ) external payable returns (uint256 validatorIndex);
    
    /**
     * @notice Add stake to existing validator position
     * @dev Sender must be the validator's staker address
     */
    function addStake() external payable;
    
    /**
     * @notice Request to unstake (begins lock period)
     * @param amount Amount to unstake
     */
    function requestUnstake(uint256 amount) external;
    
    /**
     * @notice Withdraw unstaked funds after lock period
     */
    function withdrawStake() external;
    
    /**
     * @notice Update validator commission rate
     * @param newRate New commission rate in basis points
     */
    function updateCommissionRate(uint256 newRate) external;
    
    /**
     * @notice Request voluntary exit from validator set
     */
    function requestExit() external;
    
    // ============ Delegation Functions ============
    
    /**
     * @notice Delegate stake to a validator
     * @param validator Validator address to delegate to
     */
    function delegate(address validator) external payable;
    
    /**
     * @notice Undelegate stake from a validator
     * @param validator Validator address
     * @param amount Amount to undelegate
     */
    function undelegate(address validator, uint256 amount) external;
    
    /**
     * @notice Withdraw undelegated funds after lock period
     * @param validator Validator from which funds were undelegated
     */
    function withdrawDelegation(address validator) external;
    
    // ============ Rewards Functions ============
    
    /**
     * @notice Distribute rewards for an epoch (called by consensus layer)
     * @param epoch Epoch number
     * @param activeValidatorIndices Indices of active validators
     */
    function distributeRewards(
        uint256 epoch,
        uint256[] calldata activeValidatorIndices
    ) external;
    
    /**
     * @notice Claim accumulated rewards
     */
    function claimRewards() external;
    
    /**
     * @notice Claim rewards on behalf of another address (for delegators)
     * @param delegator Address of delegator
     * @param validator Validator address
     */
    function claimDelegatorRewards(address delegator, address validator) external;
    
    // ============ Slashing Functions ============
    
    /**
     * @notice Slash a validator for misbehavior (called by consensus layer)
     * @param validatorIndex Validator index
     * @param reason Reason for slashing
     */
    function slashValidator(uint256 validatorIndex, string calldata reason) external;
    
    // ============ View Functions ============
    
    /**
     * @notice Get validator information
     * @param validatorAddress Validator's staker address
     * @return Validator information struct
     */
    function getValidator(address validatorAddress) external view returns (ValidatorInfo memory);
    
    /**
     * @notice Get validator by index
     * @param validatorIndex Validator index (0-149)
     * @return Validator information struct
     */
    function getValidatorByIndex(uint256 validatorIndex) external view returns (ValidatorInfo memory);
    
    /**
     * @notice Check if address is a registered validator
     * @param account Address to check
     * @return True if account is a validator
     */
    function isValidator(address account) external view returns (bool);
    
    /**
     * @notice Get number of registered validators
     * @return Total validator count
     */
    function getValidatorCount() external view returns (uint256);
    
    /**
     * @notice Get total staked amount across all validators
     * @return Total stake in wei
     */
    function getTotalStaked() external view returns (uint256);
    
    /**
     * @notice Get total active stake for current epoch
     * @return Total active stake in wei
     */
    function getTotalActiveStake() external view returns (uint256);
    
    /**
     * @notice Get delegation information
     * @param delegator Delegator address
     * @param validator Validator address
     * @return Delegation information struct
     */
    function getDelegation(
        address delegator,
        address validator
    ) external view returns (DelegationInfo memory);
    
    /**
     * @notice Get total delegation for a validator
     * @param validator Validator address
     * @return Total delegated amount
     */
    function getValidatorDelegation(address validator) external view returns (uint256);
    
    /**
     * @notice Get unclaimed rewards for an account
     * @param account Account address
     * @return Unclaimed rewards amount
     */
    function getUnclaimedRewards(address account) external view returns (uint256);
    
    /**
     * @notice Get unstake request information
     * @param account Account address
     * @return Unstake request struct
     */
    function getUnstakeRequest(address account) external view returns (UnstakeRequest memory);
    
    /**
     * @notice Get current epoch number
     * @return Current epoch
     */
    function getCurrentEpoch() external view returns (uint256);
    
    /**
     * @notice Get current slot number
     * @return Current slot
     */
    function getCurrentSlot() external view returns (uint256);
    
    // ============ Governance Integration ============
    
    /**
     * @notice Get voting power for governance (stake + delegated stake)
     * @dev This is the critical function that Governor.sol needs
     * @param account Account address
     * @return Total voting power (own stake + delegated stake if validator)
     */
    function getVotes(address account) external view returns (uint256);
    
    /**
     * @notice Get voting power at a specific block
     * @param account Account address
     * @param blockNumber Historical block number
     * @return Voting power at that block
     */
    function getVotesAtBlock(address account, uint256 blockNumber) external view returns (uint256);
    
    /**
     * @notice Get all active validator addresses for current epoch
     * @return Array of active validator addresses
     */
    function getActiveValidators() external view returns (address[] memory);
    
    /**
     * @notice Get active validator indices for current epoch
     * @return Array of active validator indices
     */
    function getActiveValidatorIndices() external view returns (uint256[] memory);
}
