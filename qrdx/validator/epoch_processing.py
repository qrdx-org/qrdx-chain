"""
QRDX Epoch Processing

Implements epoch boundary processing for QR-PoS consensus including:
- Validator shuffling for committees
- Reward and penalty distribution  
- Validator activation/exit processing
- Finality checkpoint updates
- RANDAO accumulation

This runs at the end of each epoch (every 32 slots / 64 seconds).
"""

import hashlib
import math
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_DOWN
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime
import asyncio

from ..logger import get_logger
from ..constants import (
    SLOTS_PER_EPOCH,
    MIN_VALIDATOR_STAKE,
    MAX_VALIDATORS,
    BASE_REWARD_FACTOR,
    PROPOSER_REWARD_QUOTIENT,
    ATTESTATION_REWARD_QUOTIENT,
    INACTIVITY_PENALTY_QUOTIENT,
    ATTESTATION_THRESHOLD,
    ACTIVATION_DELAY_EPOCHS,
    WITHDRAWAL_DELAY_EPOCHS,
    SLASHING_DOUBLE_SIGN,
)
from .types import Validator, ValidatorStatus, ValidatorSet

logger = get_logger(__name__)


# Effective balance constants
EFFECTIVE_BALANCE_INCREMENT = Decimal("1000")  # 1000 QRDX granularity
MAX_EFFECTIVE_BALANCE = Decimal("1000000")  # 1M QRDX cap


@dataclass
class EpochProcessingResult:
    """Result of epoch processing."""
    epoch: int
    
    # Validator changes
    activated_validators: List[str] = field(default_factory=list)
    exited_validators: List[str] = field(default_factory=list)
    slashed_validators: List[str] = field(default_factory=list)
    
    # Rewards/penalties
    total_rewards: Decimal = Decimal("0")
    total_penalties: Decimal = Decimal("0")
    rewards_by_validator: Dict[str, Decimal] = field(default_factory=dict)
    penalties_by_validator: Dict[str, Decimal] = field(default_factory=dict)
    
    # Finality
    justified: bool = False
    finalized: bool = False
    finalized_epoch: Optional[int] = None
    
    # Participation
    participation_rate: float = 0.0
    attesting_balance: Decimal = Decimal("0")
    total_active_balance: Decimal = Decimal("0")


@dataclass
class ValidatorRecord:
    """Extended validator record for epoch processing."""
    address: str
    public_key: bytes
    effective_balance: Decimal
    slashed: bool
    activation_eligibility_epoch: Optional[int]
    activation_epoch: Optional[int]
    exit_epoch: Optional[int]
    withdrawable_epoch: Optional[int]
    
    # Performance tracking
    proposed_blocks: int = 0
    missed_blocks: int = 0
    attestations_included: int = 0
    attestations_missed: int = 0
    
    @property
    def is_active(self) -> bool:
        return self.activation_epoch is not None and self.exit_epoch is None
    
    @property
    def is_slashable(self) -> bool:
        return self.is_active and not self.slashed


class EpochProcessor:
    """
    Processes epoch transitions for QR-PoS consensus.
    
    Handles all state transitions that occur at epoch boundaries.
    """
    
    def __init__(
        self,
        slots_per_epoch: int = SLOTS_PER_EPOCH,
        min_validator_stake: Decimal = MIN_VALIDATOR_STAKE,
        max_validators: int = MAX_VALIDATORS,
    ):
        self.slots_per_epoch = slots_per_epoch
        self.min_stake = min_validator_stake
        self.max_validators = max_validators
        
        # Activation queue
        self.activation_queue: List[str] = []
        self.exit_queue: List[str] = []
        
        # Churn limit (max validators to activate/exit per epoch)
        self.churn_limit = 4  # Minimum churn limit
        
        # Inactivity tracking
        self.inactivity_scores: Dict[str, int] = {}
        self.finality_delay = 0  # Epochs since last finality
    
    def compute_activation_exit_epoch(self, epoch: int) -> int:
        """Compute the epoch when a validator can be activated or exit."""
        return epoch + 1 + ACTIVATION_DELAY_EPOCHS
    
    def get_validator_churn_limit(self, active_validator_count: int) -> int:
        """
        Get the maximum number of validators that can enter/exit per epoch.
        
        Scales with validator set size for stability.
        """
        return max(4, active_validator_count // 65536)
    
    async def process_epoch(
        self,
        epoch: int,
        validators: List[ValidatorRecord],
        attestations: List[Dict[str, Any]],
        blocks: List[Dict[str, Any]],
        randao_mix: bytes,
        database: Any = None,
    ) -> EpochProcessingResult:
        """
        Process an epoch transition.
        
        Args:
            epoch: The epoch that just ended
            validators: All registered validators
            attestations: Attestations from this epoch
            blocks: Blocks from this epoch
            randao_mix: Current RANDAO mix
            database: Database instance for persistence
            
        Returns:
            EpochProcessingResult with all changes
        """
        result = EpochProcessingResult(epoch=epoch)
        
        # Filter active validators
        active_validators = [v for v in validators if v.is_active]
        result.total_active_balance = sum(v.effective_balance for v in active_validators)
        
        if not active_validators:
            logger.warning(f"No active validators for epoch {epoch}")
            return result
        
        # Update churn limit based on validator set size
        self.churn_limit = self.get_validator_churn_limit(len(active_validators))
        
        logger.info(f"Processing epoch {epoch}: {len(active_validators)} active validators")
        
        # 1. Process justification and finalization
        await self._process_justification_finalization(
            epoch, active_validators, attestations, result
        )
        
        # 2. Process rewards and penalties
        await self._process_rewards_penalties(
            epoch, active_validators, attestations, blocks, result
        )
        
        # 3. Process validator registry updates
        await self._process_registry_updates(
            epoch, validators, result
        )
        
        # 4. Process slashings
        await self._process_slashings(
            epoch, validators, result
        )
        
        # 5. Update effective balances
        await self._update_effective_balances(
            validators, result
        )
        
        # 6. Compute next epoch RANDAO
        new_randao = self._compute_next_randao(randao_mix, epoch)
        
        # 7. Persist to database if available
        if database:
            await self._persist_epoch_data(epoch, result, new_randao, database)
        
        logger.info(
            f"Epoch {epoch} processed: "
            f"rewards={result.total_rewards:.2f}, "
            f"penalties={result.total_penalties:.2f}, "
            f"activated={len(result.activated_validators)}, "
            f"exited={len(result.exited_validators)}, "
            f"participation={result.participation_rate:.1%}"
        )
        
        return result
    
    async def _process_justification_finalization(
        self,
        epoch: int,
        active_validators: List[ValidatorRecord],
        attestations: List[Dict[str, Any]],
        result: EpochProcessingResult,
    ):
        """
        Process justification and finalization (Casper FFG).
        
        Determines if checkpoints should be justified/finalized based on attestations.
        """
        # Get attestations for current and previous epoch targets
        current_epoch_attestations = [
            a for a in attestations 
            if a.get('target_epoch') == epoch
        ]
        previous_epoch_attestations = [
            a for a in attestations 
            if a.get('target_epoch') == epoch - 1
        ]
        
        # Calculate attesting balances
        current_attesting_validators = set(a.get('validator_address') for a in current_epoch_attestations)
        previous_attesting_validators = set(a.get('validator_address') for a in previous_epoch_attestations)
        
        current_attesting_balance = sum(
            v.effective_balance for v in active_validators
            if v.address in current_attesting_validators
        )
        previous_attesting_balance = sum(
            v.effective_balance for v in active_validators
            if v.address in previous_attesting_validators
        )
        
        result.attesting_balance = current_attesting_balance
        result.participation_rate = float(
            current_attesting_balance / result.total_active_balance
        ) if result.total_active_balance > 0 else 0.0
        
        # Justification threshold: 2/3 of total active balance
        threshold = result.total_active_balance * ATTESTATION_THRESHOLD
        
        # Check current epoch justification
        if current_attesting_balance >= threshold:
            result.justified = True
            logger.info(f"Epoch {epoch} JUSTIFIED")
        
        # Check finalization (requires consecutive justified epochs)
        # Simplified: if previous was justified and current is justified, finalize previous
        if previous_attesting_balance >= threshold and result.justified:
            result.finalized = True
            result.finalized_epoch = epoch - 1
            self.finality_delay = 0
            logger.info(f"Epoch {epoch - 1} FINALIZED")
        else:
            self.finality_delay += 1
    
    async def _process_rewards_penalties(
        self,
        epoch: int,
        active_validators: List[ValidatorRecord],
        attestations: List[Dict[str, Any]],
        blocks: List[Dict[str, Any]],
        result: EpochProcessingResult,
    ):
        """
        Calculate and distribute rewards and penalties.
        
        Rewards:
        - Attestation rewards: For attesting correctly
        - Proposer rewards: For including attestations
        - Sync committee rewards: For participating in sync committees
        
        Penalties:
        - Missed attestation penalties
        - Inactivity penalties (during finality delays)
        """
        # Calculate base reward
        total_balance = result.total_active_balance
        if total_balance == 0:
            return
        
        # Base reward per validator per epoch
        # Formula: effective_balance * BASE_REWARD_FACTOR / sqrt(total_balance)
        sqrt_total_balance = Decimal(str(math.sqrt(float(total_balance))))
        
        # Get attesting validators this epoch
        attesting_addresses = set(a.get('validator_address') for a in attestations)
        
        # Get block proposers
        proposer_addresses = set(b.get('proposer_address') for b in blocks)
        proposer_attestation_counts = {}
        for block in blocks:
            proposer = block.get('proposer_address')
            attestations_in_block = block.get('attestations_included', 0)
            proposer_attestation_counts[proposer] = (
                proposer_attestation_counts.get(proposer, 0) + attestations_in_block
            )
        
        for validator in active_validators:
            base_reward = (
                validator.effective_balance * BASE_REWARD_FACTOR / sqrt_total_balance
            ).quantize(Decimal("0.000001"), ROUND_DOWN)
            
            reward = Decimal("0")
            penalty = Decimal("0")
            
            # Attestation reward/penalty
            if validator.address in attesting_addresses:
                # Reward for correct attestation
                attestation_reward = base_reward / ATTESTATION_REWARD_QUOTIENT
                reward += attestation_reward
            else:
                # Penalty for missing attestation
                attestation_penalty = base_reward / ATTESTATION_REWARD_QUOTIENT
                penalty += attestation_penalty
                
                # Track inactivity
                self.inactivity_scores[validator.address] = (
                    self.inactivity_scores.get(validator.address, 0) + 1
                )
            
            # Proposer reward
            if validator.address in proposer_addresses:
                attestations_included = proposer_attestation_counts.get(validator.address, 0)
                proposer_reward = base_reward * attestations_included / PROPOSER_REWARD_QUOTIENT
                reward += proposer_reward
            
            # Inactivity penalty (during finality delays)
            if self.finality_delay > 4:
                inactivity_score = self.inactivity_scores.get(validator.address, 0)
                inactivity_penalty = (
                    validator.effective_balance * inactivity_score / INACTIVITY_PENALTY_QUOTIENT
                )
                penalty += inactivity_penalty
            
            # Record results
            if reward > 0:
                result.rewards_by_validator[validator.address] = reward
                result.total_rewards += reward
            if penalty > 0:
                result.penalties_by_validator[validator.address] = penalty
                result.total_penalties += penalty
    
    async def _process_registry_updates(
        self,
        epoch: int,
        validators: List[ValidatorRecord],
        result: EpochProcessingResult,
    ):
        """
        Process validator activations and exits.
        
        Implements the activation queue with churn limiting.
        """
        activation_epoch = self.compute_activation_exit_epoch(epoch)
        
        # Process activation queue
        pending_activations = [
            v for v in validators
            if (v.activation_eligibility_epoch is not None and
                v.activation_eligibility_epoch <= epoch and
                v.activation_epoch is None)
        ]
        
        # Sort by eligibility epoch, then by address for determinism
        pending_activations.sort(
            key=lambda v: (v.activation_eligibility_epoch or 0, v.address)
        )
        
        # Activate up to churn limit
        activated_count = 0
        for validator in pending_activations:
            if activated_count >= self.churn_limit:
                break
            
            # Check if still meets minimum stake
            if validator.effective_balance >= self.min_stake:
                validator.activation_epoch = activation_epoch
                result.activated_validators.append(validator.address)
                activated_count += 1
                logger.info(
                    f"Validator {validator.address[:16]} scheduled for activation "
                    f"at epoch {activation_epoch}"
                )
        
        # Process exit queue
        pending_exits = [
            v for v in validators
            if v.exit_epoch == epoch
        ]
        
        exit_count = 0
        for validator in pending_exits:
            if exit_count >= self.churn_limit:
                break
            
            validator.withdrawable_epoch = epoch + WITHDRAWAL_DELAY_EPOCHS
            result.exited_validators.append(validator.address)
            exit_count += 1
            logger.info(f"Validator {validator.address[:16]} exited at epoch {epoch}")
    
    async def _process_slashings(
        self,
        epoch: int,
        validators: List[ValidatorRecord],
        result: EpochProcessingResult,
    ):
        """
        Process pending slashings.
        
        Slashed validators lose a portion of their stake.
        """
        slashed_validators = [v for v in validators if v.slashed and v.is_active]
        
        if not slashed_validators:
            return
        
        # Calculate total slashed balance
        total_slashed = sum(v.effective_balance for v in slashed_validators)
        total_balance = sum(
            v.effective_balance for v in validators if v.is_active
        )
        
        for validator in slashed_validators:
            # Proportional slashing penalty
            # More validators slashed = higher penalty (up to full stake)
            penalty_numerator = validator.effective_balance * total_slashed * 3
            penalty = min(
                validator.effective_balance * SLASHING_DOUBLE_SIGN,
                penalty_numerator / total_balance if total_balance > 0 else Decimal("0")
            )
            
            result.penalties_by_validator[validator.address] = (
                result.penalties_by_validator.get(validator.address, Decimal("0")) + penalty
            )
            result.total_penalties += penalty
            result.slashed_validators.append(validator.address)
            
            logger.warning(
                f"Slashing penalty applied to {validator.address[:16]}: {penalty:.2f} QRDX"
            )
    
    async def _update_effective_balances(
        self,
        validators: List[ValidatorRecord],
        result: EpochProcessingResult,
    ):
        """
        Update effective balances based on rewards/penalties.
        
        Effective balance is quantized to EFFECTIVE_BALANCE_INCREMENT.
        """
        for validator in validators:
            # Apply rewards
            reward = result.rewards_by_validator.get(validator.address, Decimal("0"))
            penalty = result.penalties_by_validator.get(validator.address, Decimal("0"))
            
            # Update balance (would be persisted to database)
            # new_balance = validator.effective_balance + reward - penalty
            
            # Quantize to increment (e.g., 1000 QRDX)
            # validator.effective_balance = min(
            #     MAX_EFFECTIVE_BALANCE,
            #     (new_balance // EFFECTIVE_BALANCE_INCREMENT) * EFFECTIVE_BALANCE_INCREMENT
            # )
            pass  # Actual update happens in database
    
    def _compute_next_randao(self, current_randao: bytes, epoch: int) -> bytes:
        """Compute RANDAO mix for next epoch."""
        seed_data = current_randao + epoch.to_bytes(8, 'little')
        return hashlib.sha256(seed_data).digest()
    
    async def _persist_epoch_data(
        self,
        epoch: int,
        result: EpochProcessingResult,
        randao_mix: bytes,
        database: Any,
    ):
        """Persist epoch processing results to database."""
        try:
            async with database.pool.acquire() as conn:
                # Update epoch record
                await conn.execute("""
                    INSERT INTO epochs (epoch, start_slot, end_slot, active_validators,
                                       total_stake, justified, finalized, randao_mix,
                                       total_rewards, total_penalties, started_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
                    ON CONFLICT (epoch) DO UPDATE SET
                        justified = EXCLUDED.justified,
                        finalized = EXCLUDED.finalized,
                        total_rewards = EXCLUDED.total_rewards,
                        total_penalties = EXCLUDED.total_penalties,
                        finalized_at = CASE WHEN EXCLUDED.finalized THEN NOW() ELSE epochs.finalized_at END
                """,
                    epoch,
                    epoch * self.slots_per_epoch,
                    (epoch + 1) * self.slots_per_epoch - 1,
                    len(result.activated_validators),
                    float(result.total_active_balance),
                    result.justified,
                    result.finalized,
                    randao_mix.hex(),
                    float(result.total_rewards),
                    float(result.total_penalties),
                )
                
                # Update validator rewards
                for address, reward in result.rewards_by_validator.items():
                    await conn.execute("""
                        INSERT INTO validator_rewards 
                        (validator_address, epoch, attestation_reward, net_reward)
                        VALUES ($1, $2, $3, $3)
                        ON CONFLICT (validator_address, epoch) DO UPDATE SET
                            attestation_reward = EXCLUDED.attestation_reward,
                            net_reward = EXCLUDED.net_reward
                    """, address, epoch, float(reward))
                
                # Update validator stakes
                for address, penalty in result.penalties_by_validator.items():
                    if penalty > 0:
                        await conn.execute("""
                            UPDATE validators SET
                                effective_stake = GREATEST(0, effective_stake - $1),
                                total_slashed = total_slashed + $1,
                                updated_at = NOW()
                            WHERE address = $2
                        """, float(penalty), address)
                
                for address, reward in result.rewards_by_validator.items():
                    if reward > 0:
                        await conn.execute("""
                            UPDATE validators SET
                                effective_stake = LEAST($3, effective_stake + $1),
                                total_rewards = total_rewards + $1,
                                updated_at = NOW()
                            WHERE address = $2
                        """, float(reward), address, float(MAX_EFFECTIVE_BALANCE))
                
                # Update activation/exit status
                for address in result.activated_validators:
                    await conn.execute("""
                        UPDATE validators SET
                            status = 'active',
                            activation_epoch = $1,
                            updated_at = NOW()
                        WHERE address = $2
                    """, epoch + ACTIVATION_DELAY_EPOCHS, address)
                
                for address in result.exited_validators:
                    await conn.execute("""
                        UPDATE validators SET
                            status = 'exited',
                            updated_at = NOW()
                        WHERE address = $1
                    """, address)
                
                logger.debug(f"Epoch {epoch} data persisted to database")
                
        except Exception as e:
            logger.error(f"Failed to persist epoch {epoch} data: {e}")


class ValidatorShuffling:
    """
    Implements deterministic validator shuffling for committee assignment.
    
    Uses swap-or-not shuffle algorithm for uniform randomness.
    """
    
    @staticmethod
    def compute_shuffled_index(
        index: int,
        index_count: int,
        seed: bytes,
        shuffle_round_count: int = 90,
    ) -> int:
        """
        Compute the shuffled position of a validator index.
        
        Uses the swap-or-not shuffle algorithm.
        """
        if index_count == 0:
            return index
        
        for current_round in range(shuffle_round_count):
            pivot_data = seed + current_round.to_bytes(1, 'little')
            pivot = int.from_bytes(
                hashlib.sha256(pivot_data).digest()[:8], 'little'
            ) % index_count
            
            flip = (pivot + index_count - index) % index_count
            position = max(index, flip)
            
            source_data = (
                seed +
                current_round.to_bytes(1, 'little') +
                (position // 256).to_bytes(4, 'little')
            )
            source = hashlib.sha256(source_data).digest()
            
            byte_index = (position % 256) // 8
            bit_index = (position % 256) % 8
            
            if (source[byte_index] >> bit_index) & 1:
                index = flip
        
        return index
    
    @staticmethod
    def compute_committee(
        validators: List[str],
        slot: int,
        committee_index: int,
        committees_per_slot: int,
        seed: bytes,
    ) -> List[str]:
        """
        Compute the committee for a specific slot and index.
        
        Args:
            validators: List of active validator addresses
            slot: Slot number
            committee_index: Index of committee within slot
            committees_per_slot: Number of committees per slot
            seed: Randomness seed for this epoch
            
        Returns:
            List of validator addresses in the committee
        """
        validator_count = len(validators)
        if validator_count == 0:
            return []
        
        # Compute start and end indices
        committees_in_epoch = SLOTS_PER_EPOCH * committees_per_slot
        committee_count_per_slot = committees_per_slot
        
        index_offset = slot * committee_count_per_slot + committee_index
        committee_size = validator_count // committees_in_epoch
        
        start_index = index_offset * committee_size
        end_index = start_index + committee_size
        
        if index_offset == committees_in_epoch - 1:
            end_index = validator_count
        
        # Get shuffled indices
        committee = []
        for i in range(start_index, end_index):
            shuffled_index = ValidatorShuffling.compute_shuffled_index(
                i, validator_count, seed
            )
            committee.append(validators[shuffled_index])
        
        return committee
    
    @staticmethod
    def get_beacon_proposer_index(
        validators: List[str],
        effective_balances: Dict[str, Decimal],
        slot: int,
        seed: bytes,
    ) -> str:
        """
        Select the block proposer for a slot.
        
        Uses effective balance weighting for selection.
        """
        if not validators:
            raise ValueError("No validators available")
        
        total_balance = sum(effective_balances.get(v, Decimal("0")) for v in validators)
        if total_balance == 0:
            # Fallback to deterministic seed-based selection (no economic
            # guarantee when all validators have zero balance).
            slot_seed = hashlib.sha256(seed + slot.to_bytes(8, 'little')).digest()
            index = int.from_bytes(slot_seed[:8], 'little') % len(validators)
            return validators[index]
        
        # Iterate through validators, weighted by effective balance
        slot_seed = hashlib.sha256(seed + slot.to_bytes(8, 'little')).digest()
        random_value = int.from_bytes(slot_seed[:8], 'little')
        
        max_random = 2**64
        
        for i, validator in enumerate(validators):
            effective_balance = effective_balances.get(validator, Decimal("0"))
            
            # Check if this validator is selected
            index_seed = hashlib.sha256(
                seed + slot.to_bytes(8, 'little') + i.to_bytes(8, 'little')
            ).digest()
            candidate_random = int.from_bytes(index_seed[:8], 'little')
            
            # Weighted random selection
            threshold = (effective_balance * max_random) / total_balance
            if candidate_random < int(threshold):
                return validator
        
        # Weighted loop exhausted without selecting — use seed-derived index
        # to avoid deterministic bias toward the first validator.
        fallback_seed = hashlib.sha256(
            seed + slot.to_bytes(8, 'little') + b'fallback'
        ).digest()
        return validators[
            int.from_bytes(fallback_seed[:8], 'little') % len(validators)
        ]
