"""
QRDX Attestation System

Handles attestation creation, verification, and aggregation for PoS consensus.
Attestations are signed votes from validators for a specific block.
"""

import asyncio
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

from ..logger import get_logger
from ..crypto.pq import PQPublicKey, PQSignature, verify as pq_verify
from .types import Validator, ValidatorError

logger = get_logger(__name__)


@dataclass
class Attestation:
    """
    Validator attestation for block finality.
    
    An attestation is a signed vote from a validator confirming
    that they have validated a block at a specific slot.
    
    Attributes:
        slot: Slot number being attested to
        epoch: Epoch containing the slot
        block_hash: Hash of the block being attested
        validator_address: PQ address of the attesting validator
        validator_index: Index in the validator set
        signature: Dilithium signature of the attestation data
        source_epoch: Source checkpoint epoch
        target_epoch: Target checkpoint epoch
    """
    slot: int
    epoch: int
    block_hash: str
    validator_address: str
    validator_index: int
    signature: bytes
    source_epoch: int = 0
    target_epoch: int = 0
    included_in_block: Optional[int] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def signing_root(self) -> bytes:
        """
        Compute the signing root for this attestation.
        
        This is what gets signed by the validator.
        """
        data = (
            self.slot.to_bytes(8, 'little') +
            self.epoch.to_bytes(8, 'little') +
            bytes.fromhex(self.block_hash) +
            self.source_epoch.to_bytes(8, 'little') +
            self.target_epoch.to_bytes(8, 'little')
        )
        return hashlib.sha256(data).digest()
    
    def verify(self, public_key: bytes) -> bool:
        """
        Verify the attestation signature.
        
        Args:
            public_key: Validator's Dilithium public key
            
        Returns:
            True if signature is valid
        """
        try:
            pk = PQPublicKey.from_bytes(public_key)
            sig = PQSignature.from_bytes(self.signature)
            return pq_verify(pk, self.signing_root, sig)
        except Exception as e:
            logger.warning(f"Attestation verification failed: {e}")
            return False
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            'slot': self.slot,
            'epoch': self.epoch,
            'block_hash': self.block_hash,
            'validator_address': self.validator_address,
            'validator_index': self.validator_index,
            'signature': self.signature.hex(),
            'source_epoch': self.source_epoch,
            'target_epoch': self.target_epoch,
            'included_in_block': self.included_in_block,
            'created_at': self.created_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Attestation':
        """Create from dictionary."""
        return cls(
            slot=data['slot'],
            epoch=data['epoch'],
            block_hash=data['block_hash'],
            validator_address=data['validator_address'],
            validator_index=data['validator_index'],
            signature=bytes.fromhex(data['signature']),
            source_epoch=data.get('source_epoch', 0),
            target_epoch=data.get('target_epoch', 0),
            included_in_block=data.get('included_in_block'),
            created_at=datetime.fromisoformat(data['created_at']) if 'created_at' in data else datetime.utcnow(),
        )
    
    @classmethod
    def create(
        cls,
        slot: int,
        epoch: int,
        block_hash: str,
        validator: Validator,
        private_key,  # PQPrivateKey
        source_epoch: int = 0,
        target_epoch: int = 0
    ) -> 'Attestation':
        """
        Create a new signed attestation.
        
        Args:
            slot: Slot number
            epoch: Epoch number
            block_hash: Block hash to attest to
            validator: Attesting validator
            private_key: Validator's Dilithium private key
            source_epoch: Source checkpoint epoch
            target_epoch: Target checkpoint epoch
            
        Returns:
            Signed attestation
        """
        # Create unsigned attestation
        attestation = cls(
            slot=slot,
            epoch=epoch,
            block_hash=block_hash,
            validator_address=validator.address,
            validator_index=validator.index or 0,
            signature=b'',  # Will be set below
            source_epoch=source_epoch,
            target_epoch=target_epoch,
        )
        
        # Sign the attestation
        signature = private_key.sign(attestation.signing_root)
        attestation.signature = signature.to_bytes()
        
        return attestation


class AttestationPool:
    """
    Pool for collecting and managing attestations.
    
    Responsibilities:
    - Collect attestations from validators
    - Verify attestation signatures
    - Track attestations per slot/block
    - Select attestations for block inclusion
    - Detect slashable attestations
    """
    
    def __init__(self, max_attestations_per_slot: int = 128):
        """
        Initialize attestation pool.
        
        Args:
            max_attestations_per_slot: Maximum attestations to track per slot
        """
        self.max_per_slot = max_attestations_per_slot
        
        # Attestations indexed by (slot, block_hash)
        self._attestations: Dict[Tuple[int, str], List[Attestation]] = defaultdict(list)
        
        # Track which validators have attested to which slots
        self._validator_slots: Dict[str, Set[int]] = defaultdict(set)
        
        # Public keys for signature verification
        self._public_keys: Dict[str, bytes] = {}
        
        self._lock = asyncio.Lock()
    
    def register_validator(self, address: str, public_key: bytes):
        """
        Register a validator's public key for verification.
        
        Args:
            address: Validator address
            public_key: Dilithium public key
        """
        self._public_keys[address] = public_key
    
    async def add_attestation(
        self, 
        attestation: Attestation,
        verify_signature: bool = True
    ) -> bool:
        """
        Add an attestation to the pool.
        
        Args:
            attestation: Attestation to add
            verify_signature: Whether to verify signature
            
        Returns:
            True if attestation was added
        """
        async with self._lock:
            # Check if validator already attested to this slot
            if attestation.slot in self._validator_slots[attestation.validator_address]:
                # Duplicate attestation - could be slashable if different block
                existing = await self._get_validator_attestation(
                    attestation.validator_address,
                    attestation.slot
                )
                if existing and existing.block_hash != attestation.block_hash:
                    logger.warning(
                        f"Double attestation detected: {attestation.validator_address} "
                        f"at slot {attestation.slot}"
                    )
                    # This is slashable evidence!
                    return False
                
                # Same attestation, ignore
                return False
            
            # Verify signature if requested
            if verify_signature:
                public_key = self._public_keys.get(attestation.validator_address)
                if not public_key:
                    logger.warning(
                        f"Unknown validator: {attestation.validator_address}"
                    )
                    return False
                
                if not attestation.verify(public_key):
                    logger.warning(
                        f"Invalid attestation signature: {attestation.validator_address}"
                    )
                    return False
            
            # Add to pool
            key = (attestation.slot, attestation.block_hash)
            
            if len(self._attestations[key]) >= self.max_per_slot:
                logger.debug(f"Attestation pool full for slot {attestation.slot}")
                return False
            
            self._attestations[key].append(attestation)
            self._validator_slots[attestation.validator_address].add(attestation.slot)
            
            logger.debug(
                f"Added attestation: slot={attestation.slot}, "
                f"validator={attestation.validator_address[:16]}..."
            )
            
            return True
    
    async def get_attestations_for_block(
        self,
        slot: int,
        block_hash: str
    ) -> List[Attestation]:
        """
        Get all attestations for a specific block.
        
        Args:
            slot: Slot number
            block_hash: Block hash
            
        Returns:
            List of attestations
        """
        async with self._lock:
            key = (slot, block_hash)
            return self._attestations.get(key, []).copy()
    
    async def get_attestations_for_slot(self, slot: int) -> List[Attestation]:
        """
        Get all attestations for a slot (any block).
        
        Args:
            slot: Slot number
            
        Returns:
            List of attestations
        """
        async with self._lock:
            result = []
            for (s, _), attestations in self._attestations.items():
                if s == slot:
                    result.extend(attestations)
            return result
    
    async def get_attestation_count(
        self,
        slot: int,
        block_hash: str
    ) -> int:
        """
        Get number of attestations for a block.
        
        Args:
            slot: Slot number
            block_hash: Block hash
            
        Returns:
            Number of attestations
        """
        attestations = await self.get_attestations_for_block(slot, block_hash)
        return len(attestations)
    
    async def get_attestation_stake(
        self,
        slot: int,
        block_hash: str,
        validators: List[Validator]
    ) -> Decimal:
        """
        Get total stake behind attestations for a block.
        
        Args:
            slot: Slot number
            block_hash: Block hash
            validators: Validator list for stake lookup
            
        Returns:
            Total attesting stake
        """
        attestations = await self.get_attestations_for_block(slot, block_hash)
        
        # Build address -> stake mapping
        stake_map = {v.address: v.effective_stake for v in validators}
        
        total_stake = Decimal("0")
        for attestation in attestations:
            stake = stake_map.get(attestation.validator_address, Decimal("0"))
            total_stake += stake
        
        return total_stake
    
    async def has_supermajority(
        self,
        slot: int,
        block_hash: str,
        validators: List[Validator],
        threshold: Decimal = Decimal("0.667")
    ) -> bool:
        """
        Check if block has supermajority (2/3+) attestations.
        
        Args:
            slot: Slot number
            block_hash: Block hash
            validators: Validator list
            threshold: Required stake fraction (default 2/3)
            
        Returns:
            True if supermajority achieved
        """
        attesting_stake = await self.get_attestation_stake(slot, block_hash, validators)
        total_stake = sum(v.effective_stake for v in validators)
        
        if total_stake == 0:
            return False
        
        ratio = attesting_stake / total_stake
        return ratio >= threshold
    
    async def select_attestations_for_inclusion(
        self,
        current_slot: int,
        max_attestations: int,
        max_inclusion_distance: int = 32
    ) -> List[Attestation]:
        """
        Select attestations to include in a block.
        
        Prioritizes:
        1. Older attestations (closer to inclusion deadline)
        2. Unique validators
        
        Args:
            current_slot: Current slot number
            max_attestations: Maximum attestations to include
            max_inclusion_distance: Maximum slots since attestation
            
        Returns:
            List of attestations to include
        """
        async with self._lock:
            # Collect eligible attestations
            eligible = []
            min_slot = current_slot - max_inclusion_distance
            
            for (slot, block_hash), attestations in self._attestations.items():
                if slot >= min_slot and slot < current_slot:
                    for attestation in attestations:
                        if attestation.included_in_block is None:
                            eligible.append(attestation)
            
            # Sort by slot (older first) and then by validator index
            eligible.sort(key=lambda a: (a.slot, a.validator_index))
            
            # Select up to max_attestations
            selected = eligible[:max_attestations]
            
            return selected
    
    async def mark_included(self, attestations: List[Attestation], block_number: int):
        """
        Mark attestations as included in a block.
        
        Args:
            attestations: Attestations that were included
            block_number: Block that included them
        """
        async with self._lock:
            for attestation in attestations:
                attestation.included_in_block = block_number
    
    async def _get_validator_attestation(
        self,
        validator_address: str,
        slot: int
    ) -> Optional[Attestation]:
        """Get a validator's attestation for a specific slot."""
        for (s, _), attestations in self._attestations.items():
            if s == slot:
                for attestation in attestations:
                    if attestation.validator_address == validator_address:
                        return attestation
        return None
    
    async def prune_old_attestations(self, current_slot: int, keep_slots: int = 1000):
        """
        Remove old attestations to free memory.
        
        Args:
            current_slot: Current slot
            keep_slots: Number of slots to keep
        """
        async with self._lock:
            min_slot = current_slot - keep_slots
            
            # Find keys to remove
            to_remove = [
                key for key in self._attestations.keys()
                if key[0] < min_slot
            ]
            
            for key in to_remove:
                del self._attestations[key]
            
            # Clean up validator slot tracking
            for address in list(self._validator_slots.keys()):
                self._validator_slots[address] = {
                    s for s in self._validator_slots[address]
                    if s >= min_slot
                }
                if not self._validator_slots[address]:
                    del self._validator_slots[address]
            
            logger.debug(
                f"Pruned attestations: removed {len(to_remove)} slot entries"
            )
    
    async def get_statistics(self) -> dict:
        """Get pool statistics."""
        async with self._lock:
            total_attestations = sum(
                len(atts) for atts in self._attestations.values()
            )
            
            return {
                'total_attestations': total_attestations,
                'slots_tracked': len(set(k[0] for k in self._attestations.keys())),
                'validators_seen': len(self._validator_slots),
                'registered_validators': len(self._public_keys),
            }


class AttestationAggregator:
    """
    Aggregates attestations for efficient block inclusion.
    
    In the future, this can implement BLS signature aggregation
    for more efficient verification. Currently uses individual
    Dilithium signatures.
    """
    
    @staticmethod
    def aggregate_attestations(
        attestations: List[Attestation]
    ) -> List[Attestation]:
        """
        Aggregate attestations for the same target.
        
        Currently returns attestations as-is since Dilithium
        doesn't support aggregation. Future versions may use
        BLS or other aggregatable signatures.
        
        Args:
            attestations: List of attestations
            
        Returns:
            Aggregated attestations (currently same as input)
        """
        # Group by (slot, block_hash, source_epoch, target_epoch)
        groups: Dict[Tuple, List[Attestation]] = defaultdict(list)
        
        for attestation in attestations:
            key = (
                attestation.slot,
                attestation.block_hash,
                attestation.source_epoch,
                attestation.target_epoch,
            )
            groups[key].append(attestation)
        
        # For now, return all attestations
        # Future: aggregate signatures within each group
        result = []
        for group in groups.values():
            result.extend(group)
        
        return result
