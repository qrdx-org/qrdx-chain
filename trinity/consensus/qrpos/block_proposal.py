"""
QR-PoS Block Proposal Module

Handles quantum-resistant block creation with Dilithium signatures.
Implements block proposer selection and validation.
"""
from typing import Dict, List, Optional, Tuple

from eth_typing import Address, Hash32
from eth_utils import encode_hex, ValidationError

from trinity.crypto.pq.dilithium import DilithiumPrivateKey, verify_dilithium
from trinity.crypto.pq.blake3_hash import blake3_hash
from trinity.consensus.qrpos.constants import (
    DILITHIUM_SIGNATURE_SIZE,
    DILITHIUM_PUBKEY_SIZE,
    PROPOSER_REWARD_QUOTIENT,
    MAX_PROPOSER_SLASHINGS,
    MAX_ATTESTATIONS,
)
from trinity.consensus.qrpos.validator import Validator, ValidatorRegistry


class BlockProposal:
    """Represents a proposed block in QR-PoS"""
    
    def __init__(
        self,
        slot: int,
        proposer_pq_address: bytes,
        parent_hash: Hash32,
        state_root: Hash32,
        transactions_root: Hash32,
        receipts_root: Hash32,
        validator_pubkey: bytes,
        validator_signature: bytes,
        block_body_hash: Hash32,
    ):
        """
        Initialize a block proposal.
        
        Args:
            slot: Slot number for this block
            proposer_pq_address: 32-byte PQ address of the proposer
            parent_hash: Hash of the parent block
            state_root: Root hash of the state trie
            transactions_root: Root hash of transactions
            receipts_root: Root hash of receipts
            validator_pubkey: Dilithium public key (2592 bytes)
            validator_signature: Dilithium signature (4595 bytes)
            block_body_hash: Hash of the block body (for signature verification)
        """
        if len(proposer_pq_address) != 32:
            raise ValidationError(f"Invalid proposer address length: {len(proposer_pq_address)}")
        if len(validator_pubkey) != DILITHIUM_PUBKEY_SIZE:
            raise ValidationError(f"Invalid pubkey size: {len(validator_pubkey)}")
        if len(validator_signature) != DILITHIUM_SIGNATURE_SIZE:
            raise ValidationError(f"Invalid signature size: {len(validator_signature)}")
        
        self.slot = slot
        self.proposer_pq_address = proposer_pq_address
        self.parent_hash = parent_hash
        self.state_root = state_root
        self.transactions_root = transactions_root
        self.receipts_root = receipts_root
        self.validator_pubkey = validator_pubkey
        self.validator_signature = validator_signature
        self.block_body_hash = block_body_hash
    
    def get_signing_root(self) -> bytes:
        """
        Compute the signing root for this block proposal.
        This is what the validator signs with their Dilithium key.
        
        Returns:
            64-byte BLAKE3 hash of the block header
        """
        # Concatenate all header fields (excluding signature)
        header_data = b''.join([
            self.slot.to_bytes(8, 'big'),
            self.proposer_pq_address,
            self.parent_hash,
            self.state_root,
            self.transactions_root,
            self.receipts_root,
            self.validator_pubkey,
            self.block_body_hash,
        ])
        return blake3_hash(header_data)
    
    def verify_signature(self) -> bool:
        """
        Verify the Dilithium signature on this block proposal.
        
        Returns:
            True if signature is valid, False otherwise
        """
        signing_root = self.get_signing_root()
        try:
            # Dilithium verification
            return verify_dilithium(self.validator_pubkey, signing_root, self.validator_signature)
        except Exception:
            return False


class BlockProposer:
    """
    Block proposer for QR-PoS consensus.
    Handles block creation and signing with Dilithium keys.
    """
    
    def __init__(
        self,
        validator_registry: ValidatorRegistry,
        signer: Optional[DilithiumPrivateKey] = None,
    ):
        """
        Initialize the block proposer.
        
        Args:
            validator_registry: Validator registry for proposer selection
            signer: Dilithium signer (if this node is a validator)
        """
        self.validator_registry = validator_registry
        self.signer = signer
        self._proposed_blocks: Dict[int, bytes] = {}  # slot -> block_hash mapping
    
    def propose_block(
        self,
        slot: int,
        parent_hash: Hash32,
        state_root: Hash32,
        transactions_root: Hash32,
        receipts_root: Hash32,
        block_body_hash: Hash32,
    ) -> BlockProposal:
        """
        Propose a new block for the given slot.
        
        Args:
            slot: Slot number for this block
            parent_hash: Hash of the parent block
            state_root: Root hash of the state trie
            transactions_root: Root hash of transactions
            receipts_root: Root hash of receipts
            block_body_hash: Hash of the block body
        
        Returns:
            BlockProposal object with Dilithium signature
        
        Raises:
            ValidationError: If this node is not the proposer or has no signer
        """
        if self.signer is None:
            raise ValidationError("No signer configured - cannot propose blocks")
        
        # Check if we already proposed for this slot (slashing protection)
        if slot in self._proposed_blocks:
            raise ValidationError(
                f"Double proposal detected for slot {slot}! "
                f"Already proposed block {encode_hex(self._proposed_blocks[slot])}"
            )
        
        # Get current epoch from slot
        from trinity.consensus.qrpos.constants import SLOTS_PER_EPOCH
        epoch = slot // SLOTS_PER_EPOCH
        
        # Get active validators for this epoch
        active_validators = self.validator_registry.get_active_validators(epoch)
        
        # Verify we are the designated proposer
        expected_proposer = self.validator_registry.get_proposer(slot, epoch, active_validators)
        if expected_proposer != self.signer.pq_address:
            raise ValidationError(
                f"Not the designated proposer for slot {slot}. "
                f"Expected: {encode_hex(expected_proposer)}, "
                f"Actual: {encode_hex(self.signer.pq_address)}"
            )
        
        # Create proposal
        proposal = BlockProposal(
            slot=slot,
            proposer_pq_address=self.signer.pq_address,
            parent_hash=parent_hash,
            state_root=state_root,
            transactions_root=transactions_root,
            receipts_root=receipts_root,
            validator_pubkey=self.signer.public_key_bytes,
            validator_signature=b'',  # Will be filled after signing
            block_body_hash=block_body_hash,
        )
        
        # Sign the block
        signing_root = proposal.get_signing_root()
        signature = self.signer.sign(signing_root)
        proposal.validator_signature = signature
        
        # Record proposal (slashing protection)
        self._proposed_blocks[slot] = blake3_hash(signing_root)
        
        return proposal
    
    def validate_proposal(
        self,
        proposal: BlockProposal,
        current_epoch: int,
    ) -> None:
        """
        Validate a block proposal from another validator.
        
        Args:
            proposal: Block proposal to validate
            current_epoch: Current epoch number
        
        Raises:
            ValidationError: If proposal is invalid
        """
        # Get slot and epoch
        slot = proposal.slot
        epoch = slot // 32  # SLOTS_PER_EPOCH
        
        # Check epoch is not too far in the past or future
        if abs(epoch - current_epoch) > 2:
            raise ValidationError(
                f"Proposal epoch {epoch} too far from current epoch {current_epoch}"
            )
        
        # Get active validators
        active_validators = self.validator_registry.get_active_validators(epoch)
        
        # Verify proposer is the designated validator for this slot
        expected_proposer = self.validator_registry.get_proposer(slot, epoch, active_validators)
        if expected_proposer != proposal.proposer_pq_address:
            raise ValidationError(
                f"Invalid proposer for slot {slot}. "
                f"Expected: {encode_hex(expected_proposer)}, "
                f"Got: {encode_hex(proposal.proposer_pq_address)}"
            )
        
        # Get validator to check they are active
        validator = self.validator_registry.get_validator(proposal.proposer_pq_address)
        if validator is None:
            raise ValidationError(f"Unknown proposer: {encode_hex(proposal.proposer_pq_address)}")
        
        # Verify validator is active
        if not (validator.activation_epoch <= epoch < validator.exit_epoch):
            raise ValidationError(
                f"Proposer {encode_hex(proposal.proposer_pq_address)} not active in epoch {epoch}"
            )
        
        # Verify validator is not slashed
        if validator.slashed:
            raise ValidationError(
                f"Proposer {encode_hex(proposal.proposer_pq_address)} is slashed"
            )
        
        # Verify public key matches validator record
        if validator.pq_pubkey != proposal.validator_pubkey:
            raise ValidationError("Proposer public key mismatch")
        
        # Verify signature
        if not proposal.verify_signature():
            raise ValidationError("Invalid Dilithium signature on block proposal")
    
    def get_proposer_reward(self, attestation_count: int) -> int:
        """
        Calculate the block proposer reward.
        
        Args:
            attestation_count: Number of attestations included in the block
        
        Returns:
            Reward in wei
        """
        # Proposer gets 1/8 of the total attestation rewards
        from trinity.consensus.qrpos.rewards import calculate_base_reward
        
        base_reward = calculate_base_reward()
        attestation_rewards = base_reward * min(attestation_count, MAX_ATTESTATIONS)
        proposer_reward = attestation_rewards // PROPOSER_REWARD_QUOTIENT
        
        return proposer_reward
    
    def check_slashing_conditions(
        self,
        proposal1: BlockProposal,
        proposal2: BlockProposal,
    ) -> bool:
        """
        Check if two proposals constitute a slashable offense (double proposal).
        
        Args:
            proposal1: First block proposal
            proposal2: Second block proposal
        
        Returns:
            True if slashable (same slot, different blocks, same proposer)
        """
        # Double proposal: same slot, different blocks, same proposer
        if (proposal1.slot == proposal2.slot and
            proposal1.proposer_pq_address == proposal2.proposer_pq_address and
            proposal1.get_signing_root() != proposal2.get_signing_root()):
            return True
        
        return False


def create_genesis_block_proposal(
    genesis_state_root: Hash32,
    genesis_validators: List[Validator],
) -> BlockProposal:
    """
    Create the genesis block proposal for slot 0.
    
    Args:
        genesis_state_root: Root hash of the genesis state
        genesis_validators: List of genesis validators
    
    Returns:
        Genesis block proposal (unsigned, for initialization only)
    """
    # Genesis block has special properties
    return BlockProposal(
        slot=0,
        proposer_pq_address=b'\x00' * 32,  # No proposer for genesis
        parent_hash=Hash32(b'\x00' * 32),  # No parent
        state_root=genesis_state_root,
        transactions_root=Hash32(b'\x00' * 32),  # Empty transactions
        receipts_root=Hash32(b'\x00' * 32),  # Empty receipts
        validator_pubkey=b'\x00' * DILITHIUM_PUBKEY_SIZE,  # No validator
        validator_signature=b'\x00' * DILITHIUM_SIGNATURE_SIZE,  # No signature
        block_body_hash=blake3_hash(b'genesis'),
    )
