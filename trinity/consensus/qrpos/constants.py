"""
QR-PoS Consensus Constants

All timing, stake, and reward parameters for the quantum-resistant PoS consensus mechanism.
These values are calibrated for mainnet security and performance.
"""

# ========== Timing Parameters ==========

# Slot duration in seconds
# Each slot is an opportunity for a block proposal
SLOT_DURATION = 2  # 2 seconds per slot (5x faster than Ethereum 2.0's 12 seconds)

# Number of slots in one epoch
# Epochs are used for validator shuffling, rewards, and finality checkpoints
SLOTS_PER_EPOCH = 32  # 32 slots per epoch

# Epoch duration in seconds
EPOCH_DURATION = SLOT_DURATION * SLOTS_PER_EPOCH  # 64 seconds

# Slots per historical root (for state history)
SLOTS_PER_HISTORICAL_ROOT = 8192  # ~4.5 hours of history

# Maximum lookahead for validator assignments
MAX_SEED_LOOKAHEAD = 4  # epochs


# ========== Validator Staking Parameters ==========

# Minimum stake required to become a validator (in wei)
# 32,000 QRDX tokens minimum
MIN_VALIDATOR_STAKE = 32_000 * 10**18

# Maximum effective balance for reward calculations (in wei)
# Validators can stake more, but only this amount counts for rewards/penalties
MAX_EFFECTIVE_BALANCE = 32_000 * 10**18

# Maximum number of active validators
# Network capacity limit for security and performance
MAX_VALIDATORS = 1024

# Minimum number of validators for network security
MIN_VALIDATORS = 64

# Activation delay for new validators (in epochs)
# Prevents rapid validator set changes
VALIDATOR_ACTIVATION_DELAY = 4  # ~4.3 minutes

# Exit delay for validators (in epochs)
# Ensures validators remain accountable for their attestations
MIN_VALIDATOR_WITHDRAWABILITY_DELAY = 256  # ~4.5 hours

# Maximum per-epoch churn (validators entering/exiting)
CHURN_LIMIT_QUOTIENT = 65536

# ========== Reward Parameters ==========

# Base reward factor for calculating validator rewards
# Higher value = higher rewards
BASE_REWARD_FACTOR = 64

# Proposer reward as fraction of total rewards
# Block proposers get 1/8 of attestation rewards
PROPOSER_REWARD_QUOTIENT = 8

# Inactivity penalty quotient
# Applies when finality is not reached
INACTIVITY_PENALTY_QUOTIENT = 2**24

# Minimum slashing penalty quotient
# Base penalty for slashable offenses
MIN_SLASHING_PENALTY_QUOTIENT = 32

# Proportional slashing multiplier
# Penalties scale with total slashed stake in withdrawal period
PROPORTIONAL_SLASHING_MULTIPLIER = 3

# Whistleblower reward quotient
# Reward for reporting slashable behavior
WHISTLEBLOWER_REWARD_QUOTIENT = 512


# ========== Finality Parameters ==========

# Supermajority threshold for finality
# 2/3 of validator stake must attest
FINALITY_THRESHOLD = 2 / 3  # 66.67%

# Epochs required for a checkpoint to be justified
JUSTIFIED_CHECKPOINT_AGE = 2  # epochs

# Epochs required for a checkpoint to be finalized
FINALIZED_CHECKPOINT_AGE = 1  # epoch after justification

# Maximum epochs without finality before inactivity leak
# After this, penalties increase to force finality
MAX_EPOCHS_WITHOUT_FINALITY = 4


# ========== Slashing Conditions ==========

# Slashing occurs for:
# 1. Double proposal: Validator proposes two conflicting blocks at same slot
# 2. Surround vote: Attestation surrounds another attestation
# 3. Double vote: Two attestations for same target epoch

# Minimum epochs a slashed validator must wait before withdrawal
MIN_SLASHED_WITHDRAWAL_DELAY = 256  # ~4.5 hours


# ========== Fork Choice Parameters ==========

# Weight threshold for considering a block as part of the canonical chain
# Used in LMD-GHOST fork choice
SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY = 128

# Intervals for updating proposer boost
PROPOSER_BOOST_QUOTIENT = 4


# ========== Attestation Parameters ==========

# Target number of attestations per slot
TARGET_ATTESTATIONS_PER_SLOT = 128

# Attestation inclusion delay range
MIN_ATTESTATION_INCLUSION_DELAY = 1  # slots
SLOTS_PER_ATTESTATION = 32  # Maximum age of valid attestation


# ========== Signature Parameters ==========

# ML-DSA-87 (Dilithium5) signature sizes
DILITHIUM_PUBKEY_SIZE = 2592  # bytes
DILITHIUM_SIGNATURE_SIZE = 4595  # bytes

# BLAKE3 hash size for quantum resistance
BLAKE3_HASH_SIZE = 64  # 512 bits for 256-bit quantum security


# ========== Gas and Execution Limits ==========

# Maximum gas per block
MAX_GAS_PER_BLOCK = 30_000_000  # 30M gas

# Target gas per block for dynamic adjustment
TARGET_GAS_PER_BLOCK = 15_000_000  # 15M gas

# Base fee adjustment factor
BASE_FEE_MAX_CHANGE_DENOMINATOR = 8  # EIP-1559 style

# Maximum extra data size in block header
MAX_EXTRA_DATA_BYTES = 32


# ========== Genesis Parameters ==========

# Far future epoch (used for pending/uninitialized fields)
FAR_FUTURE_EPOCH = 2**64 - 1

# Genesis slot and epoch
GENESIS_SLOT = 0
GENESIS_EPOCH = 0

# Genesis validator activation epoch
GENESIS_ACTIVATION_EPOCH = 0

# Initial fork version
GENESIS_FORK_VERSION = bytes.fromhex('00000000')


# ========== Network Parameters ==========

# Maximum proposer slashings per block
MAX_PROPOSER_SLASHINGS = 16

# Maximum attester slashings per block
MAX_ATTESTER_SLASHINGS = 2

# Maximum attestations per block
MAX_ATTESTATIONS = 128

# Maximum deposits per block
MAX_DEPOSITS = 16

# Maximum voluntary exits per block
MAX_VOLUNTARY_EXITS = 16


# ========== Sync Committee (Future) ==========

# For light client support (future enhancement)
SYNC_COMMITTEE_SIZE = 512
EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256


# ========== Withdrawal Parameters ==========

# Maximum withdrawals per payload
MAX_WITHDRAWALS_PER_PAYLOAD = 16

# Maximum validators per withdrawals sweep
MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP = 16384
