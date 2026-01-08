"""
QRDX Rewards Distribution System

Implements comprehensive reward calculation and distribution for QR-PoS:
- Block proposer rewards
- Attestation rewards  
- Sync committee rewards
- Penalty calculations
- Inflation schedule

Compatible with Ethereum 2.0 reward mechanics with QRDX-specific parameters.
"""

import math
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_DOWN, ROUND_HALF_UP
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from ..logger import get_logger
from ..constants import (
    SLOTS_PER_EPOCH,
    BASE_REWARD_FACTOR,
    PROPOSER_REWARD_QUOTIENT,
    ATTESTATION_REWARD_QUOTIENT,
    INACTIVITY_PENALTY_QUOTIENT,
    SYNC_COMMITTEE_SIZE,
)

logger = get_logger(__name__)


# Reward weights (sum should equal WEIGHT_DENOMINATOR)
WEIGHT_DENOMINATOR = 64
TIMELY_SOURCE_WEIGHT = 14
TIMELY_TARGET_WEIGHT = 26
TIMELY_HEAD_WEIGHT = 14
SYNC_REWARD_WEIGHT = 2
PROPOSER_WEIGHT = 8

# Inflation parameters
INITIAL_ANNUAL_INFLATION = Decimal("0.02")  # 2% initial annual inflation
MIN_ANNUAL_INFLATION = Decimal("0.005")  # 0.5% minimum inflation
INFLATION_DECAY_RATE = Decimal("0.9")  # Decay per year

# Penalty parameters
INACTIVITY_PENALTY_QUOTIENT_ALTAIR = 3 * 2**24  # ~50M
MIN_SLASHING_PENALTY_QUOTIENT = 128
WHISTLEBLOWER_REWARD_QUOTIENT = 512


@dataclass
class RewardSummary:
    """Summary of rewards/penalties for a single validator."""
    validator_address: str
    epoch: int
    
    # Component rewards
    source_reward: Decimal = Decimal("0")
    target_reward: Decimal = Decimal("0")
    head_reward: Decimal = Decimal("0")
    proposer_reward: Decimal = Decimal("0")
    sync_committee_reward: Decimal = Decimal("0")
    inclusion_delay_reward: Decimal = Decimal("0")
    
    # Penalties
    source_penalty: Decimal = Decimal("0")
    target_penalty: Decimal = Decimal("0")
    head_penalty: Decimal = Decimal("0")
    inactivity_penalty: Decimal = Decimal("0")
    
    @property
    def total_reward(self) -> Decimal:
        return (
            self.source_reward + self.target_reward + self.head_reward +
            self.proposer_reward + self.sync_committee_reward + 
            self.inclusion_delay_reward
        )
    
    @property
    def total_penalty(self) -> Decimal:
        return (
            self.source_penalty + self.target_penalty + 
            self.head_penalty + self.inactivity_penalty
        )
    
    @property
    def net_reward(self) -> Decimal:
        return self.total_reward - self.total_penalty


@dataclass
class EpochRewardReport:
    """Complete reward report for an epoch."""
    epoch: int
    slot_range: Tuple[int, int]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Aggregate stats
    total_rewards: Decimal = Decimal("0")
    total_penalties: Decimal = Decimal("0")
    total_net_issuance: Decimal = Decimal("0")
    
    # Breakdown
    total_proposer_rewards: Decimal = Decimal("0")
    total_attestation_rewards: Decimal = Decimal("0")
    total_sync_rewards: Decimal = Decimal("0")
    total_inactivity_penalties: Decimal = Decimal("0")
    
    # Per-validator summaries
    validator_summaries: Dict[str, RewardSummary] = field(default_factory=dict)
    
    # Participation metrics
    participation_rate: float = 0.0
    attestation_inclusion_rate: float = 0.0


class RewardsCalculator:
    """
    Calculates rewards and penalties for QR-PoS validators.
    
    Based on Ethereum 2.0 Altair reward mechanics.
    """
    
    def __init__(self, slots_per_epoch: int = SLOTS_PER_EPOCH):
        self.slots_per_epoch = slots_per_epoch
    
    def get_base_reward(
        self,
        effective_balance: Decimal,
        total_active_balance: Decimal,
    ) -> Decimal:
        """
        Calculate the base reward for a validator.
        
        Formula: effective_balance * BASE_REWARD_FACTOR / sqrt(total_balance)
        
        Args:
            effective_balance: Validator's effective stake
            total_active_balance: Sum of all active validators' effective balances
            
        Returns:
            Base reward amount in QRDX
        """
        if total_active_balance <= 0:
            return Decimal("0")
        
        sqrt_total = Decimal(str(math.sqrt(float(total_active_balance))))
        
        base_reward = (
            effective_balance * BASE_REWARD_FACTOR / sqrt_total
        ).quantize(Decimal("0.000001"), ROUND_DOWN)
        
        return base_reward
    
    def get_proposer_reward(
        self,
        base_reward: Decimal,
        attestations_included: int,
    ) -> Decimal:
        """
        Calculate block proposer reward.
        
        Proposers get rewarded for:
        1. Producing a valid block
        2. Including attestations
        3. Including sync committee signatures
        """
        # Base proposer reward for producing a block
        proposer_reward = (
            base_reward * PROPOSER_WEIGHT / WEIGHT_DENOMINATOR
        ).quantize(Decimal("0.000001"), ROUND_DOWN)
        
        # Additional reward for each attestation included
        attestation_inclusion_reward = (
            base_reward * attestations_included / PROPOSER_REWARD_QUOTIENT
        ).quantize(Decimal("0.000001"), ROUND_DOWN)
        
        return proposer_reward + attestation_inclusion_reward
    
    def get_attestation_rewards(
        self,
        base_reward: Decimal,
        voted_correct_source: bool,
        voted_correct_target: bool,
        voted_correct_head: bool,
        source_participating_balance: Decimal,
        target_participating_balance: Decimal,
        head_participating_balance: Decimal,
        total_active_balance: Decimal,
    ) -> Tuple[Decimal, Decimal, Decimal]:
        """
        Calculate attestation component rewards.
        
        Validators are rewarded for voting correctly on:
        - Source: Previous justified checkpoint
        - Target: Current epoch checkpoint  
        - Head: Current head of chain
        
        Returns:
            Tuple of (source_reward, target_reward, head_reward)
        """
        if total_active_balance <= 0:
            return Decimal("0"), Decimal("0"), Decimal("0")
        
        source_reward = Decimal("0")
        target_reward = Decimal("0")
        head_reward = Decimal("0")
        
        # Source reward (for voting on correct justified checkpoint)
        if voted_correct_source:
            source_reward = (
                base_reward * TIMELY_SOURCE_WEIGHT * source_participating_balance /
                (total_active_balance * WEIGHT_DENOMINATOR)
            ).quantize(Decimal("0.000001"), ROUND_DOWN)
        
        # Target reward (for voting on correct target checkpoint)
        if voted_correct_target:
            target_reward = (
                base_reward * TIMELY_TARGET_WEIGHT * target_participating_balance /
                (total_active_balance * WEIGHT_DENOMINATOR)
            ).quantize(Decimal("0.000001"), ROUND_DOWN)
        
        # Head reward (for voting on correct chain head)
        if voted_correct_head:
            head_reward = (
                base_reward * TIMELY_HEAD_WEIGHT * head_participating_balance /
                (total_active_balance * WEIGHT_DENOMINATOR)
            ).quantize(Decimal("0.000001"), ROUND_DOWN)
        
        return source_reward, target_reward, head_reward
    
    def get_attestation_penalties(
        self,
        base_reward: Decimal,
        voted_correct_source: bool,
        voted_correct_target: bool,
        voted_correct_head: bool,
    ) -> Tuple[Decimal, Decimal, Decimal]:
        """
        Calculate penalties for incorrect/missing attestations.
        
        Returns:
            Tuple of (source_penalty, target_penalty, head_penalty)
        """
        source_penalty = Decimal("0")
        target_penalty = Decimal("0")
        head_penalty = Decimal("0")
        
        if not voted_correct_source:
            source_penalty = (
                base_reward * TIMELY_SOURCE_WEIGHT / WEIGHT_DENOMINATOR
            ).quantize(Decimal("0.000001"), ROUND_DOWN)
        
        if not voted_correct_target:
            target_penalty = (
                base_reward * TIMELY_TARGET_WEIGHT / WEIGHT_DENOMINATOR
            ).quantize(Decimal("0.000001"), ROUND_DOWN)
        
        if not voted_correct_head:
            head_penalty = (
                base_reward * TIMELY_HEAD_WEIGHT / WEIGHT_DENOMINATOR
            ).quantize(Decimal("0.000001"), ROUND_DOWN)
        
        return source_penalty, target_penalty, head_penalty
    
    def get_sync_committee_reward(
        self,
        base_reward: Decimal,
        participated: bool,
        total_active_validators: int,
    ) -> Decimal:
        """
        Calculate sync committee participation reward.
        
        Sync committee members sign each block to help light clients.
        """
        if not participated:
            return Decimal("0")
        
        # Sync committee reward per slot
        committee_reward = (
            base_reward * SYNC_REWARD_WEIGHT / 
            (WEIGHT_DENOMINATOR * SYNC_COMMITTEE_SIZE)
        ).quantize(Decimal("0.000001"), ROUND_DOWN)
        
        return committee_reward
    
    def get_inactivity_penalty(
        self,
        effective_balance: Decimal,
        inactivity_score: int,
        finality_delay: int,
    ) -> Decimal:
        """
        Calculate inactivity penalty for non-participating validators.
        
        Penalties increase exponentially when finality is delayed.
        
        Args:
            effective_balance: Validator's effective stake
            inactivity_score: Accumulated inactivity score
            finality_delay: Epochs since last finality
            
        Returns:
            Inactivity penalty amount
        """
        if finality_delay <= 4:
            return Decimal("0")
        
        # Quadratic leak during extended non-finality
        penalty = (
            effective_balance * inactivity_score / INACTIVITY_PENALTY_QUOTIENT_ALTAIR
        ).quantize(Decimal("0.000001"), ROUND_DOWN)
        
        return penalty
    
    def get_slashing_penalty(
        self,
        effective_balance: Decimal,
        total_slashed_balance: Decimal,
        total_active_balance: Decimal,
    ) -> Decimal:
        """
        Calculate slashing penalty.
        
        Penalty scales with the proportion of validators slashed.
        More validators slashed = higher penalty (correlation penalty).
        """
        # Initial penalty: 1/32 of stake
        initial_penalty = effective_balance / 32
        
        # Correlation penalty: scales with total slashed
        if total_active_balance > 0:
            slashed_ratio = min(
                total_slashed_balance * 3 / total_active_balance,
                Decimal("1")
            )
            correlation_penalty = effective_balance * slashed_ratio
        else:
            correlation_penalty = Decimal("0")
        
        total_penalty = (initial_penalty + correlation_penalty).quantize(
            Decimal("0.000001"), ROUND_DOWN
        )
        
        return total_penalty
    
    def calculate_epoch_rewards(
        self,
        epoch: int,
        validators: List[Dict],
        attestations: List[Dict],
        blocks: List[Dict],
        sync_committee_participants: List[str],
        justified_checkpoint: Dict,
        total_active_balance: Decimal,
        finality_delay: int,
        inactivity_scores: Dict[str, int],
    ) -> EpochRewardReport:
        """
        Calculate all rewards and penalties for an epoch.
        
        Args:
            epoch: Epoch number
            validators: List of active validators with their balances
            attestations: All attestations in the epoch
            blocks: All blocks in the epoch
            sync_committee_participants: Validators in sync committee
            justified_checkpoint: Current justified checkpoint
            total_active_balance: Sum of all effective balances
            finality_delay: Epochs since last finality
            inactivity_scores: Per-validator inactivity scores
            
        Returns:
            Complete reward report for the epoch
        """
        start_slot = epoch * self.slots_per_epoch
        end_slot = start_slot + self.slots_per_epoch - 1
        
        report = EpochRewardReport(
            epoch=epoch,
            slot_range=(start_slot, end_slot),
        )
        
        # Index attestations by validator
        validator_attestations: Dict[str, List[Dict]] = {}
        for attestation in attestations:
            validator = attestation.get('validator_address')
            if validator:
                if validator not in validator_attestations:
                    validator_attestations[validator] = []
                validator_attestations[validator].append(attestation)
        
        # Index blocks by proposer
        proposer_blocks: Dict[str, List[Dict]] = {}
        for block in blocks:
            proposer = block.get('proposer_address')
            if proposer:
                if proposer not in proposer_blocks:
                    proposer_blocks[proposer] = []
                proposer_blocks[proposer].append(block)
        
        # Calculate participating balances
        source_participating = Decimal("0")
        target_participating = Decimal("0")
        head_participating = Decimal("0")
        
        for validator in validators:
            address = validator['address']
            balance = Decimal(str(validator.get('effective_balance', 0)))
            
            validator_atts = validator_attestations.get(address, [])
            has_correct_source = any(
                a.get('source_correct', False) for a in validator_atts
            )
            has_correct_target = any(
                a.get('target_correct', False) for a in validator_atts
            )
            has_correct_head = any(
                a.get('head_correct', False) for a in validator_atts
            )
            
            if has_correct_source:
                source_participating += balance
            if has_correct_target:
                target_participating += balance
            if has_correct_head:
                head_participating += balance
        
        # Calculate per-validator rewards
        attesters = set(validator_attestations.keys())
        total_validators = len(validators)
        
        for validator in validators:
            address = validator['address']
            effective_balance = Decimal(str(validator.get('effective_balance', 0)))
            
            summary = RewardSummary(
                validator_address=address,
                epoch=epoch,
            )
            
            base_reward = self.get_base_reward(effective_balance, total_active_balance)
            
            # Get attestation status
            validator_atts = validator_attestations.get(address, [])
            voted_source = any(a.get('source_correct', False) for a in validator_atts)
            voted_target = any(a.get('target_correct', False) for a in validator_atts)
            voted_head = any(a.get('head_correct', False) for a in validator_atts)
            
            # Attestation rewards
            source_r, target_r, head_r = self.get_attestation_rewards(
                base_reward,
                voted_source, voted_target, voted_head,
                source_participating, target_participating, head_participating,
                total_active_balance,
            )
            summary.source_reward = source_r
            summary.target_reward = target_r
            summary.head_reward = head_r
            
            # Attestation penalties
            source_p, target_p, head_p = self.get_attestation_penalties(
                base_reward, voted_source, voted_target, voted_head
            )
            summary.source_penalty = source_p
            summary.target_penalty = target_p
            summary.head_penalty = head_p
            
            # Proposer rewards
            validator_blocks = proposer_blocks.get(address, [])
            if validator_blocks:
                total_attestations_included = sum(
                    b.get('attestations_included', 0) for b in validator_blocks
                )
                summary.proposer_reward = self.get_proposer_reward(
                    base_reward, total_attestations_included
                )
            
            # Sync committee rewards
            if address in sync_committee_participants:
                summary.sync_committee_reward = self.get_sync_committee_reward(
                    base_reward, True, total_validators
                )
            
            # Inactivity penalty
            if finality_delay > 4:
                inactivity_score = inactivity_scores.get(address, 0)
                summary.inactivity_penalty = self.get_inactivity_penalty(
                    effective_balance, inactivity_score, finality_delay
                )
            
            # Add to report
            report.validator_summaries[address] = summary
            report.total_rewards += summary.total_reward
            report.total_penalties += summary.total_penalty
            report.total_proposer_rewards += summary.proposer_reward
            report.total_attestation_rewards += (
                summary.source_reward + summary.target_reward + summary.head_reward
            )
            report.total_sync_rewards += summary.sync_committee_reward
            report.total_inactivity_penalties += summary.inactivity_penalty
        
        report.total_net_issuance = report.total_rewards - report.total_penalties
        report.participation_rate = float(len(attesters)) / total_validators if total_validators > 0 else 0
        
        logger.info(
            f"Epoch {epoch} rewards: total={report.total_rewards:.2f}, "
            f"penalties={report.total_penalties:.2f}, "
            f"net={report.total_net_issuance:.2f}"
        )
        
        return report


class InflationSchedule:
    """
    Manages the token inflation schedule for QRDX.
    
    Implements a decreasing inflation rate over time.
    """
    
    def __init__(
        self,
        initial_rate: Decimal = INITIAL_ANNUAL_INFLATION,
        min_rate: Decimal = MIN_ANNUAL_INFLATION,
        decay_rate: Decimal = INFLATION_DECAY_RATE,
        genesis_year: int = 2025,
    ):
        self.initial_rate = initial_rate
        self.min_rate = min_rate
        self.decay_rate = decay_rate
        self.genesis_year = genesis_year
    
    def get_annual_inflation_rate(self, year: int) -> Decimal:
        """Get the inflation rate for a given year."""
        years_since_genesis = max(0, year - self.genesis_year)
        
        rate = self.initial_rate * (self.decay_rate ** years_since_genesis)
        return max(self.min_rate, rate.quantize(Decimal("0.0001"), ROUND_HALF_UP))
    
    def get_epoch_inflation(
        self,
        epoch: int,
        total_supply: Decimal,
        slots_per_epoch: int = SLOTS_PER_EPOCH,
        seconds_per_slot: int = 2,
    ) -> Decimal:
        """
        Calculate the inflation amount for a single epoch.
        
        Args:
            epoch: Current epoch number
            total_supply: Current total token supply
            slots_per_epoch: Number of slots per epoch
            seconds_per_slot: Seconds per slot
            
        Returns:
            Amount of new tokens to be issued this epoch
        """
        # Calculate year from epoch
        seconds_per_epoch = slots_per_epoch * seconds_per_slot
        epochs_per_year = 365.25 * 24 * 60 * 60 / seconds_per_epoch
        
        year = self.genesis_year + int(epoch / epochs_per_year)
        annual_rate = self.get_annual_inflation_rate(year)
        
        # Per-epoch inflation
        epoch_rate = annual_rate / Decimal(str(epochs_per_year))
        epoch_inflation = (total_supply * epoch_rate).quantize(
            Decimal("0.000001"), ROUND_DOWN
        )
        
        return epoch_inflation
    
    def get_projected_supply(
        self,
        initial_supply: Decimal,
        years: int,
    ) -> List[Tuple[int, Decimal]]:
        """
        Project total supply over multiple years.
        
        Returns:
            List of (year, projected_supply) tuples
        """
        projections = []
        supply = initial_supply
        
        for i in range(years + 1):
            year = self.genesis_year + i
            projections.append((year, supply))
            
            rate = self.get_annual_inflation_rate(year)
            supply = supply * (1 + rate)
        
        return projections
