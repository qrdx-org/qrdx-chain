"""
QR-PoS Finality Module

Implements Casper FFG (Friendly Finality Gadget) for quantum-resistant proof of stake.
Provides economic finality through validator voting and slashing.
"""
from typing import Dict, List, Optional, Set

from eth_typing import Hash32
from eth_utils import encode_hex, ValidationError

from trinity.consensus.qrpos.constants import (
    SLOTS_PER_EPOCH,
    FINALITY_THRESHOLD,
    JUSTIFIED_CHECKPOINT_AGE,
)


class Checkpoint:
    """Represents a finality checkpoint (epoch boundary)"""
    
    def __init__(self, epoch: int, block_hash: Hash32):
        """
        Initialize a checkpoint.
        
        Args:
            epoch: Epoch number
            block_hash: Hash of the block at this checkpoint
        """
        self.epoch = epoch
        self.block_hash = block_hash
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Checkpoint):
            return False
        return self.epoch == other.epoch and self.block_hash == other.block_hash
    
    def __hash__(self) -> int:
        return hash((self.epoch, self.block_hash))
    
    def __repr__(self) -> str:
        return f"Checkpoint(epoch={self.epoch}, hash={encode_hex(self.block_hash)[:10]}...)"


class Attestation:
    """
    Represents a validator's attestation (vote) for finality.
    
    In Casper FFG, validators vote on checkpoint edges (source -> target).
    """
    
    def __init__(
        self,
        validator_pq_address: bytes,
        source_checkpoint: Checkpoint,
        target_checkpoint: Checkpoint,
        slot: int,
        signature: bytes,
    ):
        """
        Initialize an attestation.
        
        Args:
            validator_pq_address: 32-byte PQ address of the validator
            source_checkpoint: Source checkpoint (must be justified)
            target_checkpoint: Target checkpoint (being voted for)
            slot: Slot number when this attestation was created
            signature: Dilithium signature over the attestation data
        """
        self.validator_pq_address = validator_pq_address
        self.source_checkpoint = source_checkpoint
        self.target_checkpoint = target_checkpoint
        self.slot = slot
        self.signature = signature
    
    def is_slashable_with(self, other: 'Attestation') -> bool:
        """
        Check if this attestation is slashable when combined with another.
        
        Two attestations from the same validator are slashable if:
        1. Double vote: Different target epochs, same source
        2. Surround vote: One vote surrounds the other
        
        Args:
            other: Another attestation from the same validator
        
        Returns:
            True if the pair is slashable
        """
        if self.validator_pq_address != other.validator_pq_address:
            return False  # Different validators
        
        # Rule 1: Double vote (same target epoch, different blocks)
        if (self.target_checkpoint.epoch == other.target_checkpoint.epoch and
            self.target_checkpoint.block_hash != other.target_checkpoint.block_hash):
            return True
        
        # Rule 2: Surround vote
        # This vote surrounds the other
        if (self.source_checkpoint.epoch < other.source_checkpoint.epoch and
            self.target_checkpoint.epoch > other.target_checkpoint.epoch):
            return True
        
        # The other vote surrounds this one
        if (other.source_checkpoint.epoch < self.source_checkpoint.epoch and
            other.target_checkpoint.epoch > self.target_checkpoint.epoch):
            return True
        
        return False


class CasperFFG:
    """
    Casper FFG (Friendly Finality Gadget) implementation.
    
    Provides economic finality through checkpoint voting:
    - Validators vote on epoch boundaries (checkpoints)
    - Checkpoints with >2/3 support become justified
    - When the next epoch is justified, the previous one becomes finalized
    - Slashing conditions prevent conflicting votes
    """
    
    def __init__(self, genesis_checkpoint: Checkpoint):
        """
        Initialize Casper FFG.
        
        Args:
            genesis_checkpoint: Genesis checkpoint (epoch 0)
        """
        self.genesis_checkpoint = genesis_checkpoint
        
        # Justified checkpoints (have >2/3 support but not yet finalized)
        self._justified_checkpoints: Set[Checkpoint] = {genesis_checkpoint}
        
        # Finalized checkpoints (cannot be reverted)
        self._finalized_checkpoints: Set[Checkpoint] = {genesis_checkpoint}
        
        # Latest finalized checkpoint
        self._latest_finalized = genesis_checkpoint
        
        # Latest justified checkpoint
        self._latest_justified = genesis_checkpoint
        
        # Attestations by checkpoint
        self._attestations: Dict[Checkpoint, List[Attestation]] = {}
        
        # Validator attestation history (for slashing detection)
        self._validator_attestations: Dict[bytes, List[Attestation]] = {}
    
    def add_attestation(
        self,
        attestation: Attestation,
        current_epoch: int,
    ) -> None:
        """
        Add a validator attestation.
        
        Args:
            attestation: Validator's attestation
            current_epoch: Current epoch number
        
        Raises:
            ValidationError: If attestation is invalid or slashable
        """
        validator_addr = attestation.validator_pq_address
        target = attestation.target_checkpoint
        
        # Validate source is justified
        if attestation.source_checkpoint not in self._justified_checkpoints:
            raise ValidationError(
                f"Source checkpoint {attestation.source_checkpoint} is not justified"
            )
        
        # Validate target epoch is not too far in the past or future
        if abs(target.epoch - current_epoch) > JUSTIFIED_CHECKPOINT_AGE:
            raise ValidationError(
                f"Target epoch {target.epoch} too far from current epoch {current_epoch}"
            )
        
        # Check for slashing conditions
        if validator_addr in self._validator_attestations:
            for existing_attestation in self._validator_attestations[validator_addr]:
                if attestation.is_slashable_with(existing_attestation):
                    raise ValidationError(
                        f"Slashable attestation detected for validator {encode_hex(validator_addr)}: "
                        f"conflicts with existing attestation"
                    )
        
        # Store attestation
        if target not in self._attestations:
            self._attestations[target] = []
        self._attestations[target].append(attestation)
        
        # Track validator's attestations
        if validator_addr not in self._validator_attestations:
            self._validator_attestations[validator_addr] = []
        self._validator_attestations[validator_addr].append(attestation)
    
    def check_justification(
        self,
        checkpoint: Checkpoint,
        total_validator_weight: int,
    ) -> bool:
        """
        Check if a checkpoint has enough support to be justified (>2/3).
        
        Args:
            checkpoint: Checkpoint to check
            total_validator_weight: Total weight of all active validators
        
        Returns:
            True if checkpoint should be justified
        """
        if checkpoint not in self._attestations:
            return False
        
        # Sum weight of validators attesting to this checkpoint
        supporting_weight = 0
        attesting_validators = set()
        
        for attestation in self._attestations[checkpoint]:
            # Only count each validator once
            if attestation.validator_pq_address not in attesting_validators:
                # In production, we would look up validator weight from registry
                # For now, assume each validator has equal weight
                supporting_weight += 1
                attesting_validators.add(attestation.validator_pq_address)
        
        # Check if >2/3 threshold is met
        # supporting_weight / total_validator_weight > 2/3
        # supporting_weight * 3 > total_validator_weight * 2
        return supporting_weight * 3 > total_validator_weight * 2
    
    def justify_checkpoint(
        self,
        checkpoint: Checkpoint,
        total_validator_weight: int,
    ) -> bool:
        """
        Justify a checkpoint if it has >2/3 support.
        
        Args:
            checkpoint: Checkpoint to justify
            total_validator_weight: Total weight of all active validators
        
        Returns:
            True if checkpoint was newly justified
        """
        if checkpoint in self._justified_checkpoints:
            return False  # Already justified
        
        if self.check_justification(checkpoint, total_validator_weight):
            self._justified_checkpoints.add(checkpoint)
            
            # Update latest justified if newer
            if checkpoint.epoch > self._latest_justified.epoch:
                self._latest_justified = checkpoint
            
            return True
        
        return False
    
    def check_finalization(
        self,
        checkpoint: Checkpoint,
    ) -> bool:
        """
        Check if a checkpoint should be finalized.
        
        Casper FFG finalization rule:
        A checkpoint C is finalized if:
        1. C is justified
        2. The immediate next epoch checkpoint is also justified
        
        Args:
            checkpoint: Checkpoint to check
        
        Returns:
            True if checkpoint should be finalized
        """
        if checkpoint not in self._justified_checkpoints:
            return False  # Must be justified first
        
        if checkpoint in self._finalized_checkpoints:
            return False  # Already finalized
        
        # Check if next epoch checkpoint is justified
        next_epoch = checkpoint.epoch + 1
        for justified_checkpoint in self._justified_checkpoints:
            if justified_checkpoint.epoch == next_epoch:
                return True  # Next epoch is justified, so this one is finalized
        
        return False
    
    def finalize_checkpoint(self, checkpoint: Checkpoint) -> bool:
        """
        Finalize a checkpoint.
        
        Args:
            checkpoint: Checkpoint to finalize
        
        Returns:
            True if checkpoint was newly finalized
        """
        if checkpoint in self._finalized_checkpoints:
            return False  # Already finalized
        
        if not self.check_finalization(checkpoint):
            return False  # Not ready for finalization
        
        self._finalized_checkpoints.add(checkpoint)
        
        # Update latest finalized if newer
        if checkpoint.epoch > self._latest_finalized.epoch:
            self._latest_finalized = checkpoint
        
        return True
    
    def get_latest_finalized(self) -> Checkpoint:
        """
        Get the latest finalized checkpoint.
        
        Returns:
            Latest finalized checkpoint
        """
        return self._latest_finalized
    
    def get_latest_justified(self) -> Checkpoint:
        """
        Get the latest justified checkpoint.
        
        Returns:
            Latest justified checkpoint
        """
        return self._latest_justified
    
    def is_finalized(self, checkpoint: Checkpoint) -> bool:
        """
        Check if a checkpoint is finalized.
        
        Args:
            checkpoint: Checkpoint to check
        
        Returns:
            True if finalized
        """
        return checkpoint in self._finalized_checkpoints
    
    def is_justified(self, checkpoint: Checkpoint) -> bool:
        """
        Check if a checkpoint is justified.
        
        Args:
            checkpoint: Checkpoint to check
        
        Returns:
            True if justified
        """
        return checkpoint in self._justified_checkpoints
    
    def get_checkpoint_support(
        self,
        checkpoint: Checkpoint,
    ) -> List[Attestation]:
        """
        Get all attestations supporting a checkpoint.
        
        Args:
            checkpoint: Checkpoint to query
        
        Returns:
            List of attestations for this checkpoint
        """
        return self._attestations.get(checkpoint, [])
    
    def get_validator_attestations(
        self,
        validator_pq_address: bytes,
    ) -> List[Attestation]:
        """
        Get all attestations from a specific validator.
        
        Args:
            validator_pq_address: Validator's PQ address
        
        Returns:
            List of attestations from this validator
        """
        return self._validator_attestations.get(validator_pq_address, [])
    
    def prune_old_attestations(self, current_epoch: int, keep_epochs: int = 10) -> None:
        """
        Remove old attestations to save memory.
        
        Args:
            current_epoch: Current epoch number
            keep_epochs: Number of recent epochs to keep
        """
        cutoff_epoch = max(0, current_epoch - keep_epochs)
        
        # Remove old checkpoint attestations
        checkpoints_to_remove = []
        for checkpoint in self._attestations:
            if checkpoint.epoch < cutoff_epoch:
                checkpoints_to_remove.append(checkpoint)
        
        for checkpoint in checkpoints_to_remove:
            del self._attestations[checkpoint]
        
        # Prune validator attestation history
        for validator_addr in self._validator_attestations:
            self._validator_attestations[validator_addr] = [
                att for att in self._validator_attestations[validator_addr]
                if att.target_checkpoint.epoch >= cutoff_epoch
            ]
