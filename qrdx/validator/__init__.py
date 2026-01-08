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

from .config import (
    ValidatorConfig,
    StakingConfig,
    SlashingProtectionConfig,
)
from .manager import ValidatorManager
from .stake import StakeManager, StakeDeposit, StakeWithdrawal
from .selection import ValidatorSelector
from .attestation import Attestation, AttestationPool
from .slashing import (
    SlashingConditions,
    SlashingEvidence,
    SlashingExecutor,
    SLASHING_PENALTIES,
)
from .types import (
    Validator,
    ValidatorStatus,
    ValidatorSet,
    EpochInfo,
    SlotInfo,
    ValidatorError,
    InsufficientStakeError,
    InvalidValidatorError,
    NotPQWalletError,
    ValidatorNotActiveError,
    AlreadyProposedError,
    AlreadyAttestedError,
)
from .fork_choice import (
    ForkChoice,
    ForkChoiceStore,
    BlockNode,
    Checkpoint,
)
from .epoch_processing import (
    EpochProcessor,
    EpochProcessingResult,
    ValidatorRecord,
    ValidatorShuffling,
)
from .rewards import (
    RewardsCalculator,
    RewardSummary,
    EpochRewardReport,
    InflationSchedule,
)
from .genesis import (
    GenesisCreator,
    GenesisConfig,
    GenesisState,
    GenesisBlock,
    GenesisValidator,
    create_testnet_genesis,
    create_mainnet_genesis,
)
from .sync_committee import (
    SyncCommittee,
    SyncCommitteeManager,
    SyncAggregate,
    LightClientUpdate,
)
from .lifecycle import (
    LifecycleManager,
    ValidatorLifecycle,
    LifecycleState,
    ValidatorActivationQueue,
    ValidatorExitQueue,
    DepositRequest,
    ExitRequest,
    WithdrawalRequest,
)
from .gossip import (
    GossipHandler,
    GossipTopic,
    GossipMessage,
    BeaconGossip,
    BeaconBlockMessage,
    AttestationMessage,
    VoluntaryExitMessage,
    SlashingMessage,
    MessageValidator,
    MessageValidation,
)

__all__ = [
    # Configuration
    'ValidatorConfig',
    'StakingConfig',
    'SlashingProtectionConfig',
    
    # Core Components
    'ValidatorManager',
    'StakeManager',
    'ValidatorSelector',
    'AttestationPool',
    'SlashingExecutor',
    
    # Types & Data Classes
    'Validator',
    'ValidatorStatus',
    'ValidatorSet',
    'EpochInfo',
    'SlotInfo',
    'StakeDeposit',
    'StakeWithdrawal',
    'Attestation',
    'SlashingConditions',
    'SlashingEvidence',
    'SLASHING_PENALTIES',
    
    # Fork Choice & Finality
    'ForkChoice',
    'ForkChoiceStore',
    'BlockNode',
    'Checkpoint',
    
    # Epoch Processing
    'EpochProcessor',
    'EpochProcessingResult',
    'ValidatorRecord',
    'ValidatorShuffling',
    
    # Rewards
    'RewardsCalculator',
    'RewardSummary',
    'EpochRewardReport',
    'InflationSchedule',
    
    # Genesis
    'GenesisCreator',
    'GenesisConfig',
    'GenesisState',
    'GenesisBlock',
    'GenesisValidator',
    'create_testnet_genesis',
    'create_mainnet_genesis',
    
    # Sync Committee
    'SyncCommittee',
    'SyncCommitteeManager',
    'SyncAggregate',
    'LightClientUpdate',
    
    # Lifecycle Management
    'LifecycleManager',
    'ValidatorLifecycle',
    'LifecycleState',
    'ValidatorActivationQueue',
    'ValidatorExitQueue',
    'DepositRequest',
    'ExitRequest',
    'WithdrawalRequest',
    
    # P2P Gossip
    'GossipHandler',
    'GossipTopic',
    'GossipMessage',
    'BeaconGossip',
    'BeaconBlockMessage',
    'AttestationMessage',
    'VoluntaryExitMessage',
    'SlashingMessage',
    'MessageValidator',
    'MessageValidation',
    
    # Exceptions
    'ValidatorError',
    'InsufficientStakeError',
    'InvalidValidatorError',
    'NotPQWalletError',
    'ValidatorNotActiveError',
    'AlreadyProposedError',
    'AlreadyAttestedError',
]