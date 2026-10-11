"""
QRDX Validator Module

Implements Quantum-Resistant Proof-of-Stake (QR-PoS) validation.

CRITICAL: Validators MUST use Post-Quantum (PQ) wallets with Dilithium3 signatures.
Classical ECDSA wallets are NOT permitted as validators.

Components:
- ValidatorManager: Main coordinator for validator operations
- StakeManager: Stake deposits, withdrawals, and tracking
- ValidatorSelector: Pseudo-random proposer/committee selection
- AttestationPool: Attestation collection and aggregation
- SlashingExecutor: Slashing condition enforcement
- ForkChoice: LMD-GHOST fork choice with Casper FFG finality
- EpochProcessor: Epoch boundary processing and rewards
- SyncCommitteeManager: Sync committee selection and aggregation
- GenesisCreator: Genesis state and block creation

Usage:
    from qrdx.validator import ValidatorManager, ValidatorConfig

    config = ValidatorConfig.from_file("config.toml")
    manager = await ValidatorManager.create(config)
    await manager.start()
"""

from .attestation import Attestation, AttestationPool
from .config import (
    SlashingProtectionConfig,
    StakingConfig,
    ValidatorConfig,
)
from .epoch_processing import (
    EpochProcessingResult,
    EpochProcessor,
    ValidatorRecord,
    ValidatorShuffling,
)
from .fork_choice import (
    BlockNode,
    Checkpoint,
    ForkChoice,
    ForkChoiceStore,
)
from .genesis import (
    GenesisBlock,
    GenesisConfig,
    GenesisCreator,
    GenesisState,
    GenesisValidator,
    create_mainnet_genesis,
    create_testnet_genesis,
)
from .gossip import (
    AttestationMessage,
    BeaconBlockMessage,
    BeaconGossip,
    GossipHandler,
    GossipMessage,
    GossipTopic,
    MessageValidation,
    MessageValidator,
    SlashingMessage,
    VoluntaryExitMessage,
)
from .lifecycle import (
    DepositRequest,
    ExitRequest,
    LifecycleManager,
    LifecycleState,
    ValidatorActivationQueue,
    ValidatorExitQueue,
    ValidatorLifecycle,
    WithdrawalRequest,
)
from .manager import ValidatorManager
from .rewards import (
    EpochRewardReport,
    InflationSchedule,
    RewardsCalculator,
    RewardSummary,
)
from .selection import ValidatorSelector
from .slashing import (
    SLASHING_PENALTIES,
    SlashingConditions,
    SlashingEvidence,
    SlashingExecutor,
)
from .stake import StakeDeposit, StakeManager, StakeWithdrawal
from .sync_committee import (
    LightClientUpdate,
    SyncAggregate,
    SyncCommittee,
    SyncCommitteeManager,
)
from .types import (
    AlreadyAttestedError,
    AlreadyProposedError,
    EpochInfo,
    InsufficientStakeError,
    InvalidValidatorError,
    NotPQWalletError,
    SlotInfo,
    Validator,
    ValidatorError,
    ValidatorNotActiveError,
    ValidatorSet,
    ValidatorStatus,
)

__all__ = [
    # Configuration
    "ValidatorConfig",
    "StakingConfig",
    "SlashingProtectionConfig",
    # Core Components
    "ValidatorManager",
    "StakeManager",
    "ValidatorSelector",
    "AttestationPool",
    "SlashingExecutor",
    # Types & Data Classes
    "Validator",
    "ValidatorStatus",
    "ValidatorSet",
    "EpochInfo",
    "SlotInfo",
    "StakeDeposit",
    "StakeWithdrawal",
    "Attestation",
    "SlashingConditions",
    "SlashingEvidence",
    "SLASHING_PENALTIES",
    # Fork Choice & Finality
    "ForkChoice",
    "ForkChoiceStore",
    "BlockNode",
    "Checkpoint",
    # Epoch Processing
    "EpochProcessor",
    "EpochProcessingResult",
    "ValidatorRecord",
    "ValidatorShuffling",
    # Rewards
    "RewardsCalculator",
    "RewardSummary",
    "EpochRewardReport",
    "InflationSchedule",
    # Genesis
    "GenesisCreator",
    "GenesisConfig",
    "GenesisState",
    "GenesisBlock",
    "GenesisValidator",
    "create_testnet_genesis",
    "create_mainnet_genesis",
    # Sync Committee
    "SyncCommittee",
    "SyncCommitteeManager",
    "SyncAggregate",
    "LightClientUpdate",
    # Lifecycle Management
    "LifecycleManager",
    "ValidatorLifecycle",
    "LifecycleState",
    "ValidatorActivationQueue",
    "ValidatorExitQueue",
    "DepositRequest",
    "ExitRequest",
    "WithdrawalRequest",
    # P2P Gossip
    "GossipHandler",
    "GossipTopic",
    "GossipMessage",
    "BeaconGossip",
    "BeaconBlockMessage",
    "AttestationMessage",
    "VoluntaryExitMessage",
    "SlashingMessage",
    "MessageValidator",
    "MessageValidation",
    # Exceptions
    "ValidatorError",
    "InsufficientStakeError",
    "InvalidValidatorError",
    "NotPQWalletError",
    "ValidatorNotActiveError",
    "AlreadyProposedError",
    "AlreadyAttestedError",
]
