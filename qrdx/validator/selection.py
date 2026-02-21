"""
QRDX Validator Selection

Implements pseudo-random validator selection for block proposal and attestation committees.
Uses RANDAO-style randomness combined with stake weighting.
"""

import hashlib
import os
from decimal import Decimal
from typing import List, Optional, Tuple

from ..logger import get_logger
from .types import Validator, ValidatorSet

logger = get_logger(__name__)


class ValidatorSelector:
    """
    Selects validators for block proposal and attestation committees.
    
    Selection algorithm:
    1. Compute selection probability for each validator based on stake
    2. Use RANDAO mix (accumulated randomness from block signatures) as seed
    3. Apply deterministic shuffle based on seed
    4. Select proposer/committee based on shuffled order
    
    Security properties:
    - Selection is deterministic given the same inputs
    - Proposer cannot be predicted more than one epoch in advance
    - Stake-weighted selection ensures economic alignment
    """
    
    def __init__(self, seed: bytes = None):
        """
        Initialize validator selector.
        
        Args:
            seed: Initial random seed (uses os.urandom if not provided)
        """
        self.seed = seed or os.urandom(32)
    
    def select_proposer(
        self,
        slot: int,
        validators: List[Validator],
        randao_mix: bytes
    ) -> Optional[Validator]:
        """
        Select block proposer for a given slot.
        
        Args:
            slot: Slot number
            validators: List of active validators
            randao_mix: Current RANDAO mix for randomness
            
        Returns:
            Selected validator or None if no eligible validators
        """
        if not validators:
            logger.warning(f"No validators available for slot {slot}")
            return None
        
        # Filter to only eligible validators
        eligible = [v for v in validators if v.can_propose]
        if not eligible:
            logger.warning(f"No eligible validators for slot {slot}")
            return None
        
        # Compute selection seed for this slot
        seed = self._compute_slot_seed(slot, randao_mix)
        
        # Select proposer based on stake weight
        proposer = self._weighted_selection(eligible, seed)
        
        logger.debug(
            f"Selected proposer for slot {slot}: {proposer.address} "
            f"(stake: {proposer.effective_stake})"
        )
        
        return proposer
    
    def select_committee(
        self,
        slot: int,
        validators: List[Validator],
        committee_size: int,
        randao_mix: bytes
    ) -> List[Validator]:
        """
        Select attestation committee for a slot.
        
        Args:
            slot: Slot number
            validators: List of active validators
            committee_size: Desired committee size
            randao_mix: Current RANDAO mix
            
        Returns:
            List of validators in the committee
        """
        if not validators:
            return []
        
        # Filter to eligible validators
        eligible = [v for v in validators if v.can_attest]
        if not eligible:
            return []
        
        # Limit committee size
        actual_size = min(committee_size, len(eligible))
        
        # Compute selection seed
        seed = self._compute_slot_seed(slot, randao_mix, suffix=b'committee')
        
        # Shuffle validators deterministically
        shuffled = self._shuffle_validators(eligible, seed)
        
        # Take first N validators
        committee = shuffled[:actual_size]
        
        logger.debug(
            f"Selected committee for slot {slot}: {len(committee)} validators"
        )
        
        return committee
    
    def get_proposer_duties(
        self,
        epoch: int,
        slots_per_epoch: int,
        validators: List[Validator],
        randao_mix: bytes
    ) -> List[Tuple[int, Validator]]:
        """
        Get proposer duties for an entire epoch.
        
        Args:
            epoch: Epoch number
            slots_per_epoch: Number of slots per epoch
            validators: Active validator set
            randao_mix: RANDAO mix at epoch start
            
        Returns:
            List of (slot, validator) tuples
        """
        duties = []
        start_slot = epoch * slots_per_epoch
        
        for i in range(slots_per_epoch):
            slot = start_slot + i
            proposer = self.select_proposer(slot, validators, randao_mix)
            if proposer:
                duties.append((slot, proposer))
        
        return duties
    
    def get_committee_duties(
        self,
        epoch: int,
        slots_per_epoch: int,
        validators: List[Validator],
        committee_size: int,
        randao_mix: bytes
    ) -> List[Tuple[int, List[Validator]]]:
        """
        Get committee duties for an entire epoch.
        
        Args:
            epoch: Epoch number
            slots_per_epoch: Number of slots per epoch
            validators: Active validator set
            committee_size: Committee size per slot
            randao_mix: RANDAO mix at epoch start
            
        Returns:
            List of (slot, committee) tuples
        """
        duties = []
        start_slot = epoch * slots_per_epoch
        
        for i in range(slots_per_epoch):
            slot = start_slot + i
            committee = self.select_committee(slot, validators, committee_size, randao_mix)
            duties.append((slot, committee))
        
        return duties
    
    def _compute_slot_seed(
        self, 
        slot: int, 
        randao_mix: bytes,
        suffix: bytes = b''
    ) -> bytes:
        """
        Compute deterministic seed for a slot.
        
        Args:
            slot: Slot number
            randao_mix: RANDAO mix
            suffix: Optional suffix for different selection types
            
        Returns:
            32-byte seed
        """
        # Combine slot number with RANDAO mix
        data = slot.to_bytes(8, 'little') + randao_mix + suffix
        return hashlib.sha256(data).digest()
    
    def _weighted_selection(
        self,
        validators: List[Validator],
        seed: bytes
    ) -> Validator:
        """
        Select a single validator weighted by effective stake.
        
        Uses a deterministic algorithm that:
        1. Calculates cumulative stake distribution
        2. Uses seed to generate selection point
        3. Selects validator at that point in distribution
        
        Args:
            validators: List of validators
            seed: Random seed
            
        Returns:
            Selected validator
        """
        # Calculate total stake
        total_stake = sum(v.effective_stake for v in validators)
        
        if total_stake == 0:
            # All validators have zero effective stake — degrade to uniform
            # selection as a safety net, but log a warning.
            logger.warning(
                "Total effective stake is 0 across %d validators — falling "
                "back to uniform selection (no economic security guarantee)",
                len(validators),
            )
            index = int.from_bytes(seed[:4], 'little') % len(validators)
            return validators[index]
        
        # Generate selection value from seed
        selection_value = int.from_bytes(seed[:8], 'little')
        threshold = Decimal(selection_value % 10**18) / Decimal(10**18) * total_stake
        
        # Walk through cumulative distribution
        cumulative = Decimal("0")
        for validator in validators:
            cumulative += validator.effective_stake
            if cumulative >= threshold:
                return validator
        
        # Fallback (shouldn't reach here)
        return validators[-1]
    
    def _shuffle_validators(
        self,
        validators: List[Validator],
        seed: bytes
    ) -> List[Validator]:
        """
        Deterministically shuffle validators using Fisher-Yates algorithm.
        
        Args:
            validators: List of validators
            seed: Random seed
            
        Returns:
            Shuffled list (new list, original unchanged)
        """
        # Create a copy
        result = validators.copy()
        n = len(result)
        
        for i in range(n - 1, 0, -1):
            # Generate deterministic index
            round_seed = hashlib.sha256(seed + i.to_bytes(8, 'little')).digest()
            j = int.from_bytes(round_seed[:4], 'little') % (i + 1)
            
            # Swap
            result[i], result[j] = result[j], result[i]
        
        return result
    
    def update_randao(
        self,
        current_mix: bytes,
        reveal: bytes
    ) -> bytes:
        """
        Update RANDAO mix with a new reveal.
        
        RANDAO provides unbiased randomness by XORing validator signatures
        (reveals) into the mix.
        
        Args:
            current_mix: Current RANDAO mix (32 bytes)
            reveal: New reveal value (signature hash)
            
        Returns:
            Updated RANDAO mix
        """
        # Hash the reveal
        reveal_hash = hashlib.sha256(reveal).digest()
        
        # XOR with current mix
        new_mix = bytes(a ^ b for a, b in zip(current_mix, reveal_hash))
        
        return new_mix
    
    def compute_proposer_index(
        self,
        slot: int,
        validators: List[Validator],
        randao_mix: bytes
    ) -> int:
        """
        Compute the index of the proposer in the validator list.
        
        Args:
            slot: Slot number
            validators: Validator list
            randao_mix: RANDAO mix
            
        Returns:
            Proposer index (-1 if not found)
        """
        proposer = self.select_proposer(slot, validators, randao_mix)
        if proposer is None:
            return -1
        
        for i, v in enumerate(validators):
            if v.address == proposer.address:
                return i
        
        return -1
    
    def is_proposer(
        self,
        slot: int,
        validator_address: str,
        validators: List[Validator],
        randao_mix: bytes
    ) -> bool:
        """
        Check if a validator is the proposer for a slot.
        
        Args:
            slot: Slot number
            validator_address: Validator's address
            validators: Validator list
            randao_mix: RANDAO mix
            
        Returns:
            True if validator is the proposer
        """
        proposer = self.select_proposer(slot, validators, randao_mix)
        return proposer is not None and proposer.address == validator_address
    
    def is_in_committee(
        self,
        slot: int,
        validator_address: str,
        validators: List[Validator],
        committee_size: int,
        randao_mix: bytes
    ) -> bool:
        """
        Check if a validator is in the committee for a slot.
        
        Args:
            slot: Slot number
            validator_address: Validator's address
            validators: Validator list
            committee_size: Committee size
            randao_mix: RANDAO mix
            
        Returns:
            True if validator is in committee
        """
        committee = self.select_committee(slot, validators, committee_size, randao_mix)
        return any(v.address == validator_address for v in committee)


def compute_initial_randao(genesis_time: int, genesis_validators: List[str]) -> bytes:
    """
    Compute initial RANDAO mix for genesis.
    
    Args:
        genesis_time: Genesis timestamp
        genesis_validators: List of genesis validator addresses
        
    Returns:
        Initial RANDAO mix (32 bytes)
    """
    data = genesis_time.to_bytes(8, 'little')
    for address in sorted(genesis_validators):
        data += address.encode('utf-8')
    
    return hashlib.sha256(data).digest()
