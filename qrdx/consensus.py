# denaro/consensus.py
"""
Versioned Consensus Rules Management System

This module implements a professional, scalable system for managing blockchain
consensus rules across different versions/forks. It allows for clean separation
of concerns and easy addition of new consensus versions.

QRDX supports two consensus mechanisms:
- PoW (legacy, deprecated)
- PoS (Proof-of-Stake, mainnet)

PoS uses Quantum-Resistant signatures (CRYSTALS-Dilithium / ML-DSA-65).
"""

import hashlib
from decimal import Decimal
from typing import List, Union, Callable, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import IntEnum
from abc import ABC, abstractmethod

from .logger import get_logger

logger = get_logger(__name__)


class ConsensusVersion(IntEnum):
    """
    Consensus versions in chronological order.
    Each version represents a set of consensus rules.
    """
    CONSENSUS_V1 = 1      # Original PoW consensus (deprecated)
    CONSENSUS_V2_POS = 2  # PoS consensus (mainnet)


@dataclass
class ConsensusActivation:
    """
    Defines when a consensus version becomes active.
    """
    version: ConsensusVersion
    activation_height: int
    description: str
    is_hard_fork: bool  # True if incompatible with previous rules
    
    def is_active(self, block_height: int) -> bool:
        """Check if this consensus version is active at given height."""
        return block_height >= self.activation_height


class ConsensusSchedule:
    """
    Manages the activation schedule for consensus versions.
    This is the ONLY place where activation heights should be defined.
    """
    
    def __init__(self):
        self._activations: List[ConsensusActivation] = []
        self._initialize_schedule()
    
    def _initialize_schedule(self):
        """
        Define the consensus upgrade schedule.
        
        IMPORTANT: This is the single source of truth for all consensus changes.
        Modify this method to update activation heights before deployment.
        """
        self._activations = [
            ConsensusActivation(
                version=ConsensusVersion.CONSENSUS_V1,
                activation_height=0,
                description="Security fixes: proper Merkle trees, MTP timestamps, improved difficulty, coinbase validation",
                is_hard_fork=False
            ),
            ConsensusActivation(
                version=ConsensusVersion.CONSENSUS_V2_POS,
                activation_height=0,  # PoS from genesis for mainnet
                description="QR-PoS: Quantum-Resistant Proof-of-Stake with Dilithium signatures",
                is_hard_fork=True
            ),
        ]
        
        # Validate schedule (must be in order)
        for i in range(1, len(self._activations)):
            if self._activations[i].activation_height <= self._activations[i-1].activation_height:
                raise ValueError(f"Consensus activations must be in chronological order")
    
    def get_active_version(self, block_height: int) -> ConsensusVersion:
        """
        Determine which consensus version is active at a given block height.
        """
        active_version = ConsensusVersion.CONSENSUS_V1
        
        for activation in self._activations:
            if activation.is_active(block_height):
                active_version = activation.version
            else:
                break  # Activations are in order, so we can stop
        
        return active_version
    
    def get_activation_height(self, version: ConsensusVersion) -> int:
        """Get the activation height for a specific version."""
        for activation in self._activations:
            if activation.version == version:
                return activation.activation_height
        raise ValueError(f"Unknown consensus version: {version}")
    
    def is_hard_fork(self, version: ConsensusVersion) -> bool:
        """Check if a version is a hard fork."""
        for activation in self._activations:
            if activation.version == version:
                return activation.is_hard_fork
        return False
    
    def get_all_activations(self) -> List[ConsensusActivation]:
        """Get all scheduled consensus activations."""
        return self._activations.copy()


# Global consensus schedule instance
CONSENSUS_SCHEDULE = ConsensusSchedule()


class BaseConsensusRules(ABC):
    """
    Abstract base class defining the interface for consensus rules.
    It also contains rules common across all versions (soft forks).
    """

    @property
    @abstractmethod
    def version(self) -> ConsensusVersion:
        """The consensus version this class implements."""
        pass

    @abstractmethod
    def calculate_merkle_tree(self, transactions: List[Union[Any, str]]) -> str:
        """Calculate the Merkle tree root for a list of transactions."""
        pass

    @abstractmethod
    async def validate_timestamp(
        self,
        content_time: int,
        block_id: int,
        last_timestamp: int,
        current_time: int,
        get_median_time_past_func: Callable = None) -> bool:
        """Validate a block's timestamp."""
        pass

    @abstractmethod
    def calculate_new_difficulty(
        self,
        time_ratio: Decimal,
        current_difficulty: Decimal,
        legacy_hashrate_func: Callable = None) -> Decimal:
        """Calculate the new block difficulty."""
        pass

    @abstractmethod
    def validate_coinbase_transactions(self, transactions: List[Any]) -> bool:
        """Validate the coinbase transactions within a block."""
        pass

    def validate_field_ranges(self, random_value: int, difficulty: Decimal) -> bool:
        """
        Validate block field ranges (soft fork - all versions).
        """
        if random_value < 0 or random_value > 0xFFFFFFFF:
            logger.warning("Block rejected: random value out of range")
            return False
        
        if difficulty < 0 or difficulty > 6553.5:
            logger.warning("Block rejected: difficulty out of range")
            return False
        
        return True


class Consensus_V1(BaseConsensusRules):
    """
    Encapsulates all consensus rules for V1 (Security improvements and bug fixes).
    """
    @property
    def version(self) -> ConsensusVersion:
        return ConsensusVersion.CONSENSUS_V1
    
    def calculate_merkle_tree(self, transactions: List[Union[Any, str]]) -> str:
        """Proper binary Merkle tree implementation."""
        tx_hashes = []
        for tx in transactions:
            if isinstance(tx, str):
                tx_hashes.append(tx)
            else:
                tx_hashes.append(tx.hash())
        
        if not tx_hashes:
            return hashlib.sha256(b'').hexdigest()
        
        current_level = sorted(tx_hashes)
        
        while len(current_level) > 1:
            next_level = []
            
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                
                combined = left + right
                parent_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
                next_level.append(parent_hash)
            
            current_level = next_level
        
        return current_level[0]

    async def validate_timestamp(
        self,
        content_time: int,
        block_id: int,
        last_timestamp: int,
        current_time: int,
        get_median_time_past_func: Callable = None) -> bool:
        """Median Time Past (MTP) timestamp validation."""
        if get_median_time_past_func is None:
            raise ValueError("MTP function required for V1+ timestamp validation")
        
        median_time = await get_median_time_past_func(block_id - 1)
        
        if content_time <= median_time:
            logger.warning(f"Block rejected: timestamp {content_time} not greater than MTP {median_time}")
            return False
        
        if content_time > current_time + 60:  # Stricter future limit
            logger.warning("Block rejected: timestamp too far in future")
            return False
        
        return True
    
    def calculate_new_difficulty(
        self,
        time_ratio: Decimal,
        current_difficulty: Decimal,
        legacy_hashrate_func: Callable = None) -> Decimal:
        """
        Calculate the adjusted mining difficulty for the next period.
        
        Args:
            time_ratio: Ratio of target block time to actual average block time.
                       Values > 1.0 indicate blocks mined too slowly (increase difficulty).
                       Values < 1.0 indicate blocks mined too quickly (decrease difficulty).
                       Clamped between 0.25 and 4.0 for stability.
            current_difficulty: The current difficulty value before adjustment.
            legacy_hashrate_func: Optional legacy function for backward compatibility.
        
        Returns:
            The adjusted difficulty value, never below START_DIFFICULTY.
        
        The adjustment is calculated by converting difficulty to hashrate,
        applying the time adjustment ratio in hashrate space, and converting
        back to difficulty to maintain the proper logarithmic relationship.
        """
        from .constants import START_DIFFICULTY
        from .manager import difficulty_to_hashrate, hashrate_to_difficulty
        
        ratio = max(Decimal('0.25'), min(time_ratio, Decimal('4.0')))
        
        # Apply ratio to hashrate, not directly to difficulty
        current_hashrate = difficulty_to_hashrate(current_difficulty)
        new_estimated_hashrate = current_hashrate * ratio
        new_difficulty = hashrate_to_difficulty(new_estimated_hashrate)
        
        # Ensure difficulty doesn't drop below starting value
        new_difficulty = max(START_DIFFICULTY, new_difficulty)
        
        return new_difficulty
    
    def validate_coinbase_transactions(self, transactions: List[Any]) -> bool:
        """V1 validation: Forbids coinbase transactions in regular tx list."""
        from .transactions import CoinbaseTransaction
        
        coinbase_count = sum(
            1 for tx in transactions 
            if isinstance(tx, CoinbaseTransaction)
        )
        
        if coinbase_count > 0:
            logger.warning(f"Block rejected: {coinbase_count} coinbase in regular txs")
            return False
        
        return True


class Consensus_V2_PoS(BaseConsensusRules):
    """
    Proof-of-Stake consensus rules for QRDX mainnet.
    
    Key features:
    - Block proposer selection based on stake weight
    - Attestation-based finality (2/3+ threshold)
    - Quantum-resistant signatures (Dilithium3)
    - Slashing for misbehavior
    """
    
    def __init__(self):
        from .constants import (
            SLOT_DURATION, SLOTS_PER_EPOCH, ATTESTATION_THRESHOLD,
            MIN_VALIDATOR_STAKE, MAX_VALIDATORS
        )
        
        self.slot_duration = SLOT_DURATION
        self.slots_per_epoch = SLOTS_PER_EPOCH
        self.attestation_threshold = ATTESTATION_THRESHOLD
        self.min_validator_stake = MIN_VALIDATOR_STAKE
        self.max_validators = MAX_VALIDATORS
    
    @property
    def version(self) -> ConsensusVersion:
        return ConsensusVersion.CONSENSUS_V2_POS
    
    def calculate_merkle_tree(self, transactions: List[Union[Any, str]]) -> str:
        """Proper binary Merkle tree implementation (same as V1)."""
        tx_hashes = []
        for tx in transactions:
            if isinstance(tx, str):
                tx_hashes.append(tx)
            else:
                tx_hashes.append(tx.hash())
        
        if not tx_hashes:
            return hashlib.sha256(b'').hexdigest()
        
        current_level = sorted(tx_hashes)
        
        while len(current_level) > 1:
            next_level = []
            
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                
                combined = left + right
                parent_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
                next_level.append(parent_hash)
            
            current_level = next_level
        
        return current_level[0]
    
    async def validate_timestamp(
        self,
        content_time: int,
        block_id: int,
        last_timestamp: int,
        current_time: int,
        get_median_time_past_func: Callable = None) -> bool:
        """
        Slot-based timestamp validation for PoS.
        
        In PoS, blocks must be produced within their assigned slot.
        """
        # Calculate expected slot time
        slot = self._timestamp_to_slot(content_time)
        slot_start = self._slot_to_timestamp(slot)
        slot_end = slot_start + self.slot_duration
        
        # Block timestamp must be within the slot
        if content_time < slot_start or content_time >= slot_end:
            logger.warning(
                f"Block rejected: timestamp {content_time} not in slot {slot} "
                f"(expected {slot_start}-{slot_end})"
            )
            return False
        
        # Block timestamp must be greater than parent
        if content_time <= last_timestamp:
            logger.warning("Block rejected: timestamp not greater than parent")
            return False
        
        # Cannot be too far in the future (1 slot grace period)
        max_future = current_time + self.slot_duration
        if content_time > max_future:
            logger.warning("Block rejected: timestamp too far in future")
            return False
        
        return True
    
    def calculate_new_difficulty(
        self,
        time_ratio: Decimal,
        current_difficulty: Decimal,
        legacy_hashrate_func: Callable = None) -> Decimal:
        """
        PoS does not use difficulty adjustment.
        Returns a fixed value for compatibility.
        """
        return Decimal('1.0')
    
    def validate_coinbase_transactions(self, transactions: List[Any]) -> bool:
        """
        PoS validation: No coinbase in regular transactions.
        Rewards are handled through the staking system.
        """
        from .transactions import CoinbaseTransaction
        
        for tx in transactions:
            if isinstance(tx, CoinbaseTransaction):
                logger.warning("Block rejected: coinbase not allowed in PoS blocks")
                return False
        
        return True
    
    # =========================================================================
    # PoS-Specific Validation Methods
    # =========================================================================
    
    def validate_proposer_signature(
        self,
        block_hash: bytes,
        proposer_public_key: bytes,
        signature: bytes,
    ) -> bool:
        """
        Verify the proposer's Dilithium signature on the block.
        
        Args:
            block_hash: Hash of the block being signed
            proposer_public_key: Dilithium public key of the proposer
            signature: Dilithium signature
            
        Returns:
            True if signature is valid
        """
        try:
            from .crypto.pq import PQPublicKey, PQSignature, verify as pq_verify
            
            pk = PQPublicKey.from_bytes(proposer_public_key)
            sig = PQSignature.from_bytes(signature)
            
            return pq_verify(pk, block_hash, sig)
        except Exception as e:
            logger.error(f"Proposer signature verification failed: {e}")
            return False
    
    def validate_proposer_eligibility(
        self,
        proposer_address: str,
        slot: int,
        validators: List[Any],
        randao_mix: bytes,
    ) -> Tuple[bool, str]:
        """
        Verify the proposer is eligible for this slot.
        
        Args:
            proposer_address: Address of the block proposer
            slot: Slot number
            validators: List of active validators
            randao_mix: Current RANDAO mix for randomness
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not validators:
            return False, "No active validators"
        
        # Calculate expected proposer using deterministic selection
        expected_proposer = self._select_proposer(slot, validators, randao_mix)
        
        if expected_proposer is None:
            return False, "Failed to select proposer"
        
        if expected_proposer.address != proposer_address:
            return False, f"Wrong proposer: expected {expected_proposer.address}"
        
        return True, ""
    
    def _select_proposer(
        self,
        slot: int,
        validators: List[Any],
        randao_mix: bytes,
    ) -> Optional[Any]:
        """
        Select the proposer for a slot using weighted random selection.
        
        Uses stake-weighted selection with RANDAO-based randomness.
        """
        if not validators:
            return None
        
        # Filter active validators with sufficient stake
        active = [
            v for v in validators 
            if (hasattr(v, 'is_active') and v.is_active) or 
               (hasattr(v, 'status') and str(v.status) == 'active')
        ]
        
        if not active:
            # Fallback: use all validators
            active = validators
        
        # Compute selection seed
        seed_data = slot.to_bytes(8, 'little') + randao_mix
        seed = hashlib.sha256(seed_data).digest()
        
        # Calculate total effective stake
        total_stake = sum(
            getattr(v, 'effective_stake', getattr(v, 'stake', Decimal('1')))
            for v in active
        )
        
        if total_stake <= 0:
            return active[0] if active else None
        
        # Convert seed to selection point
        selection_point = int.from_bytes(seed[:8], 'little') % int(total_stake * 1000000)
        
        # Select validator
        cumulative = 0
        for validator in active:
            stake = getattr(validator, 'effective_stake', getattr(validator, 'stake', Decimal('1')))
            cumulative += int(stake * 1000000)
            if cumulative >= selection_point:
                return validator
        
        return active[-1]
    
    def validate_attestations(
        self,
        attestations: List[Any],
        block_slot: int,
        validators: Dict[str, bytes],  # address -> public_key
    ) -> Tuple[bool, List[str]]:
        """
        Validate attestations included in a block.
        
        Args:
            attestations: List of attestations
            block_slot: Slot of the block including these attestations
            validators: Map of validator addresses to public keys
            
        Returns:
            Tuple of (all_valid, list_of_errors)
        """
        from .constants import MAX_ATTESTATION_INCLUSION_DELAY
        
        errors = []
        
        for i, att in enumerate(attestations):
            # Check inclusion delay
            inclusion_delay = block_slot - att.slot
            if inclusion_delay < 1:
                errors.append(f"Attestation {i}: inclusion too soon")
                continue
            if inclusion_delay > MAX_ATTESTATION_INCLUSION_DELAY:
                errors.append(f"Attestation {i}: inclusion too late")
                continue
            
            # Verify signature
            validator_pk = validators.get(att.validator_address)
            if not validator_pk:
                errors.append(f"Attestation {i}: unknown validator")
                continue
            
            if hasattr(att, 'verify'):
                if not att.verify(validator_pk):
                    errors.append(f"Attestation {i}: invalid signature")
                    continue
        
        return len(errors) == 0, errors
    
    def check_finality(
        self,
        attestations: List[Any],
        block_hash: str,
        validators: List[Any],
    ) -> bool:
        """
        Check if a block has achieved finality.
        
        Finality requires attestations from validators holding >= 2/3 of stake.
        
        Args:
            attestations: Attestations for this block
            block_hash: Hash of the block
            validators: All active validators
            
        Returns:
            True if block is finalized
        """
        # Filter attestations for this block
        block_attestations = [
            a for a in attestations 
            if a.block_hash == block_hash
        ]
        
        # Calculate attesting stake
        attesting_addresses = {a.validator_address for a in block_attestations}
        attesting_stake = sum(
            getattr(v, 'effective_stake', getattr(v, 'stake', Decimal('0')))
            for v in validators
            if v.address in attesting_addresses
        )
        
        # Calculate total stake
        total_stake = sum(
            getattr(v, 'effective_stake', getattr(v, 'stake', Decimal('0')))
            for v in validators
        )
        
        if total_stake <= 0:
            return False
        
        # Check threshold
        ratio = attesting_stake / total_stake
        return ratio >= self.attestation_threshold
    
    def validate_randao_reveal(
        self,
        randao_reveal: bytes,
        slot: int,
        proposer_public_key: bytes,
    ) -> bool:
        """
        Validate the RANDAO reveal from the block proposer.
        
        The reveal should be a signature of the slot number.
        """
        try:
            from .crypto.pq import PQPublicKey, PQSignature, verify as pq_verify
            
            # RANDAO reveal is a signature of the slot
            message = slot.to_bytes(8, 'little') + b'RANDAO_REVEAL'
            
            pk = PQPublicKey.from_bytes(proposer_public_key)
            sig = PQSignature.from_bytes(randao_reveal)
            
            return pq_verify(pk, message, sig)
        except Exception as e:
            logger.error(f"RANDAO reveal validation failed: {e}")
            return False
    
    def compute_new_randao_mix(
        self,
        current_mix: bytes,
        randao_reveal: bytes,
    ) -> bytes:
        """
        Compute new RANDAO mix by combining current mix with reveal.
        """
        combined = hashlib.sha256(current_mix + randao_reveal).digest()
        return combined
    
    # =========================================================================
    # Helper Methods
    # =========================================================================
    
    def _timestamp_to_slot(self, timestamp: int, genesis_time: int = 0) -> int:
        """Convert a timestamp to slot number."""
        if timestamp <= genesis_time:
            return 0
        return (timestamp - genesis_time) // self.slot_duration
    
    def _slot_to_timestamp(self, slot: int, genesis_time: int = 0) -> int:
        """Convert a slot number to timestamp."""
        return genesis_time + (slot * self.slot_duration)
    
    def slot_to_epoch(self, slot: int) -> int:
        """Convert a slot number to epoch number."""
        return slot // self.slots_per_epoch
    
    def epoch_start_slot(self, epoch: int) -> int:
        """Get the first slot of an epoch."""
        return epoch * self.slots_per_epoch


class ConsensusEngine:
    """
    Main interface for consensus rule enforcement.
    Automatically selects the correct rules based on block height.
    """
    
    def __init__(self, schedule: ConsensusSchedule = None):
        self.schedule = schedule or CONSENSUS_SCHEDULE
        self._rules_cache: Dict[ConsensusVersion, BaseConsensusRules] = {}
        self._rules_map: Dict[ConsensusVersion, type[BaseConsensusRules]] = {
            ConsensusVersion.CONSENSUS_V1: Consensus_V1,
            ConsensusVersion.CONSENSUS_V2_POS: Consensus_V2_PoS,
        }
    
    def get_rules(self, block_height: int) -> BaseConsensusRules:
        """
        Get the appropriate consensus rules for a given block height.
        This acts as a factory for consensus rule objects.
        """
        version = self.schedule.get_active_version(block_height)
        
        if version not in self._rules_cache:
            rules_class = self._rules_map.get(version)
            if not rules_class:
                raise NotImplementedError(f"Consensus rules for version {version} not implemented.")
            self._rules_cache[version] = rules_class()
        
        return self._rules_cache[version]
    
    def is_hard_fork_active(self, block_height: int, fork_version: ConsensusVersion) -> bool:
        """
        Check if a specific hard fork is active at given height.
        """
        active_version = self.schedule.get_active_version(block_height)
        return active_version >= fork_version


# Global consensus engine instance
CONSENSUS_ENGINE = ConsensusEngine()


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_consensus_info() -> Dict[str, Any]:
    """
    Get information about all consensus versions and their activation heights.
    Useful for network coordination and debugging.
    """
    info = {
        "current_version": str(ConsensusVersion.CONSENSUS_V2_POS),
        "consensus_type": "proof_of_stake",
        "activations": []
    }
    
    for activation in CONSENSUS_SCHEDULE.get_all_activations():
        info["activations"].append({
            "version": str(activation.version),
            "height": activation.activation_height,
            "description": activation.description,
            "is_hard_fork": activation.is_hard_fork
        })
    
    return info


async def get_median_time_past(database: Any, block_id: int, lookback: int = 11) -> int:
    """
    Calculate median timestamp of last N blocks.
    Used for MTP timestamp validation.
    """
    if block_id < lookback:
        lookback = max(1, block_id)
    
    start_id = max(1, block_id - lookback + 1)
    timestamps = []
    
    for i in range(start_id, block_id + 1):
        block = await database.get_block_by_id(i)
        if block:
            timestamps.append(block['timestamp'])
    
    if not timestamps:
        return 0
    
    timestamps.sort()
    return timestamps[len(timestamps) // 2]


# ============================================================================
# PoS UTILITY FUNCTIONS
# ============================================================================

def get_pos_rules() -> Consensus_V2_PoS:
    """
    Get the PoS consensus rules instance.
    
    Convenience function for direct PoS rule access.
    """
    return CONSENSUS_ENGINE.get_rules(0)  # PoS is active from genesis


def is_pos_active(block_height: int = 0) -> bool:
    """
    Check if Proof-of-Stake consensus is active.
    
    For mainnet, PoS is active from genesis.
    """
    version = CONSENSUS_SCHEDULE.get_active_version(block_height)
    return version >= ConsensusVersion.CONSENSUS_V2_POS


async def validate_pos_block(
    block: Any,
    validators: List[Any],
    randao_mix: bytes,
    database: Any = None,
) -> Tuple[bool, str]:
    """
    Validate a PoS block against consensus rules.
    
    Args:
        block: The block to validate
        validators: List of active validators
        randao_mix: Current RANDAO mix
        database: Optional database for additional lookups
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    pos_rules = get_pos_rules()
    
    # 1. Validate proposer eligibility
    is_eligible, error = pos_rules.validate_proposer_eligibility(
        block.proposer_address,
        block.slot,
        validators,
        randao_mix,
    )
    if not is_eligible:
        return False, f"Proposer ineligible: {error}"
    
    # 2. Validate proposer signature
    if not pos_rules.validate_proposer_signature(
        block.signing_root if hasattr(block, 'signing_root') else bytes.fromhex(block.hash),
        block.proposer_public_key,
        block.proposer_signature,
    ):
        return False, "Invalid proposer signature"
    
    # 3. Validate RANDAO reveal
    if hasattr(block, 'randao_reveal') and block.randao_reveal:
        if not pos_rules.validate_randao_reveal(
            block.randao_reveal,
            block.slot,
            block.proposer_public_key,
        ):
            return False, "Invalid RANDAO reveal"
    
    # 4. Validate attestations if present
    if hasattr(block, 'attestations') and block.attestations:
        validator_pks = {v.address: v.public_key for v in validators}
        valid, errors = pos_rules.validate_attestations(
            block.attestations,
            block.slot,
            validator_pks,
        )
        if not valid:
            return False, f"Invalid attestations: {errors}"
    
    # 5. Validate transactions (no coinbase allowed)
    if hasattr(block, 'transactions') and block.transactions:
        if not pos_rules.validate_coinbase_transactions(block.transactions):
            return False, "Coinbase transactions not allowed in PoS"
    
    return True, ""


def calculate_block_reward(
    slot: int,
    total_stake: Decimal,
    attestation_count: int,
) -> Decimal:
    """
    Calculate block reward for PoS.
    
    Rewards in PoS depend on:
    - Total staked amount (affects base reward)
    - Number of attestations included (additional rewards)
    
    Args:
        slot: Slot number (for epoch calculation)
        total_stake: Total stake in the system
        attestation_count: Number of attestations in the block
        
    Returns:
        Total block reward in QRDX
    """
    from .constants import (
        BASE_REWARD_FACTOR,
        PROPOSER_REWARD_QUOTIENT,
        SLOTS_PER_EPOCH,
        INITIAL_REWARD,
    )
    
    # Calculate effective reward factor based on total stake
    # Higher stake = lower per-validator reward to control inflation
    if total_stake <= 0:
        return Decimal('0')
    
    # Base reward scales with square root of total stake
    import math
    stake_factor = Decimal(str(math.sqrt(float(total_stake))))
    base_reward = INITIAL_REWARD / (stake_factor / 1000)
    
    # Cap base reward
    base_reward = min(base_reward, INITIAL_REWARD)
    
    # Proposer reward includes share of attestation rewards
    attestation_bonus = (attestation_count * base_reward) / (PROPOSER_REWARD_QUOTIENT * 10)
    
    total_reward = base_reward + attestation_bonus
    
    return total_reward.quantize(Decimal('0.000001'))


def compute_epoch_state(
    epoch: int,
    validators: List[Any],
    blocks: List[Any],
    attestations: List[Any],
) -> Dict[str, Any]:
    """
    Compute the state at the end of an epoch.
    
    Used for finality checkpoints and reward distribution.
    
    Args:
        epoch: Epoch number
        validators: Active validators in this epoch
        blocks: Blocks proposed in this epoch
        attestations: All attestations in this epoch
        
    Returns:
        Dictionary containing epoch state summary
    """
    from .constants import SLOTS_PER_EPOCH, ATTESTATION_THRESHOLD
    
    # Calculate participation
    start_slot = epoch * SLOTS_PER_EPOCH
    end_slot = start_slot + SLOTS_PER_EPOCH
    
    # Count blocks proposed
    epoch_blocks = [b for b in blocks if start_slot <= b.slot < end_slot]
    
    # Count attestations
    epoch_attestations = [a for a in attestations if start_slot <= a.slot < end_slot]
    
    # Calculate participation rate
    attesting_validators = set(a.validator_address for a in epoch_attestations)
    total_validators = len(validators)
    
    if total_validators > 0:
        participation_rate = len(attesting_validators) / total_validators
    else:
        participation_rate = 0.0
    
    # Calculate total attesting stake
    total_stake = sum(
        getattr(v, 'effective_stake', getattr(v, 'stake', Decimal('0')))
        for v in validators
    )
    attesting_stake = sum(
        getattr(v, 'effective_stake', getattr(v, 'stake', Decimal('0')))
        for v in validators
        if v.address in attesting_validators
    )
    
    # Check finality
    if total_stake > 0:
        stake_ratio = attesting_stake / total_stake
        is_finalized = stake_ratio >= ATTESTATION_THRESHOLD
    else:
        stake_ratio = Decimal('0')
        is_finalized = False
    
    return {
        'epoch': epoch,
        'start_slot': start_slot,
        'end_slot': end_slot,
        'blocks_proposed': len(epoch_blocks),
        'blocks_expected': SLOTS_PER_EPOCH,
        'attestations': len(epoch_attestations),
        'unique_attesters': len(attesting_validators),
        'total_validators': total_validators,
        'participation_rate': float(participation_rate),
        'total_stake': str(total_stake),
        'attesting_stake': str(attesting_stake),
        'stake_ratio': float(stake_ratio),
        'is_finalized': is_finalized,
    }
