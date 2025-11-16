"""
Quantum-Resistant Proof of Stake (QR-PoS) Consensus

This module implements a production-grade PoS consensus mechanism with:
- Dilithium (ML-DSA-87) signed blocks
- LMD-GHOST fork choice rule
- Casper FFG finality gadget
- Validator registry and stake management
- Rewards and penalties
- Slashing conditions

Based on Ethereum 2.0 PoS design principles with quantum-resistant cryptography.
"""

from .constants import (
    SLOT_DURATION,
    SLOTS_PER_EPOCH,
    EPOCH_DURATION,
    MIN_VALIDATOR_STAKE,
    MAX_VALIDATORS,
    MAX_EFFECTIVE_BALANCE,
    VALIDATOR_ACTIVATION_DELAY,
    BASE_REWARD_FACTOR,
    PROPOSER_REWARD_QUOTIENT,
    INACTIVITY_PENALTY_QUOTIENT,
    WHISTLEBLOWER_REWARD_QUOTIENT,
    MIN_SLASHING_PENALTY_QUOTIENT,
    PROPORTIONAL_SLASHING_MULTIPLIER,
    FINALITY_THRESHOLD,
    JUSTIFIED_CHECKPOINT_AGE,
    SLOTS_PER_HISTORICAL_ROOT,
    DILITHIUM_PUBKEY_SIZE,
    DILITHIUM_SIGNATURE_SIZE,
)

from .validator import (
    Validator,
    ValidatorRegistry,
    ValidatorStatus,
)

from .block_proposal import (
    BlockProposal,
    BlockProposer,
    create_genesis_block_proposal,
)

from .fork_choice import (
    Vote,
    BlockNode,
    LMDGHOSTForkChoice,
)

from .finality import (
    Checkpoint,
    Attestation,
    CasperFFG,
)

from .rewards import (
    RewardsCalculator,
    ValidatorRewards,
    calculate_base_reward,
)

from .state import (
    BeaconState,
)

from .consensus import (
    QRPoSConsensusContext,
    QRPoSConsensus,
)

__all__ = [
    # Constants
    'SLOT_DURATION',
    'SLOTS_PER_EPOCH',
    'EPOCH_DURATION',
    'MIN_VALIDATOR_STAKE',
    'MAX_VALIDATORS',
    'MAX_EFFECTIVE_BALANCE',
    'VALIDATOR_ACTIVATION_DELAY',
    'BASE_REWARD_FACTOR',
    'PROPOSER_REWARD_QUOTIENT',
    'INACTIVITY_PENALTY_QUOTIENT',
    'WHISTLEBLOWER_REWARD_QUOTIENT',
    'MIN_SLASHING_PENALTY_QUOTIENT',
    'PROPORTIONAL_SLASHING_MULTIPLIER',
    'FINALITY_THRESHOLD',
    'JUSTIFIED_CHECKPOINT_AGE',
    'SLOTS_PER_HISTORICAL_ROOT',
    'DILITHIUM_PUBKEY_SIZE',
    'DILITHIUM_SIGNATURE_SIZE',
    
    # Validator management
    'Validator',
    'ValidatorRegistry',
    'ValidatorStatus',
    
    # Block proposal
    'BlockProposal',
    'BlockProposer',
    'create_genesis_block_proposal',
    
    # Fork choice
    'Vote',
    'BlockNode',
    'LMDGHOSTForkChoice',
    'Checkpoint',
    
    # Finality
    'Attestation',
    'CasperFFG',
    
    # Rewards
    'RewardsCalculator',
    'ValidatorRewards',
    'calculate_base_reward',
    
    # State
    'BeaconState',
    
    # Consensus API (Trinity integration)
    'QRPoSConsensusContext',
    'QRPoSConsensus',
]
