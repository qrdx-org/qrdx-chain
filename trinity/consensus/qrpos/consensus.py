"""
QR-PoS Consensus API Implementation

Implements the ConsensusAPI interface for quantum-resistant proof of stake,
integrating with Trinity's consensus framework.
"""
from typing import Iterable

from eth_typing import Address, Hash32
from eth_utils import ValidationError, encode_hex

from eth.abc import (
    AtomicDatabaseAPI,
    BlockHeaderAPI,
    ConsensusAPI,
    ConsensusContextAPI,
)

from trinity.consensus.qrpos.block_proposal import BlockProposal, BlockProposer
from trinity.consensus.qrpos.validator import ValidatorRegistry
from trinity.consensus.qrpos.fork_choice import LMDGHOSTForkChoice
from trinity.consensus.qrpos.finality import CasperFFG, Checkpoint
from trinity.consensus.qrpos.state import BeaconState


class QRPoSConsensusContext(ConsensusContextAPI):
    """
    Consensus context for QR-PoS.
    
    Maintains the beacon state and validator registry across VM runs.
    """
    
    def __init__(self, db: AtomicDatabaseAPI):
        """
        Initialize the QR-PoS consensus context.
        
        Args:
            db: Database for persistent storage
        """
        self.db = db
        
        # Initialize beacon state
        # In production, this would load from database or genesis config
        self.beacon_state = BeaconState(
            genesis_slot=0,
            genesis_validators=self._load_genesis_validators(),
            genesis_state_root=None,
        )
        
        # Fork choice rule
        genesis_hash = Hash32(b'\x00' * 32)  # Will be set properly from genesis block
        self.fork_choice = LMDGHOSTForkChoice(genesis_hash)
        
        # Block proposer (will be set when validator key is loaded)
        self.block_proposer = BlockProposer(
            validator_registry=self.beacon_state.validator_registry,
            signer=None,  # No signer by default (non-validator node)
        )
    
    def _load_genesis_validators(self) -> list:
        """
        Load genesis validators from configuration or database.
        
        For now, returns empty list. In production, this would:
        1. Check database for existing validators
        2. If empty, load from genesis config
        3. Create initial validator set
        
        Returns:
            List of genesis Validator objects
        """
        # TODO: Load from genesis configuration
        # For now, return empty list - validators can be added via staking contract
        return []


class QRPoSConsensus(ConsensusAPI):
    """
    QR-PoS Consensus implementation.
    
    Replaces Ethash PoW with quantum-resistant proof of stake using:
    - Dilithium signatures for block validation
    - LMD-GHOST fork choice
    - Casper FFG finality
    - Validator registry and staking
    """
    
    def __init__(self, context: QRPoSConsensusContext):
        """
        Initialize QR-PoS consensus.
        
        Args:
            context: QR-PoS consensus context
        """
        if not isinstance(context, QRPoSConsensusContext):
            raise TypeError(f"Expected QRPoSConsensusContext, got {type(context)}")
        
        self.context = context
    
    def validate_seal(self, header: BlockHeaderAPI) -> None:
        """
        Validate the seal (signature) on a block header.
        
        For QR-PoS, this validates the Dilithium signature without requiring
        parent blocks.
        
        Args:
            header: Block header to validate
        
        Raises:
            ValidationError: If seal is invalid
        """
        # Genesis block (block 0) doesn't need validation
        if header.block_number == 0:
            return
        
        # Extract QR-PoS specific fields from header
        # In production, these would be proper header fields
        
        # Get slot from header (replaces difficulty/block_number relationship)
        slot = self._get_slot_from_header(header)
        
        # Get proposer address
        proposer_address = self._get_proposer_from_header(header)
        
        # Get validator public key and signature
        validator_pubkey = self._get_validator_pubkey_from_header(header)
        validator_signature = self._get_validator_signature_from_header(header)
        
        # Verify signature size
        from trinity.consensus.qrpos.constants import (
            DILITHIUM_PUBKEY_SIZE,
            DILITHIUM_SIGNATURE_SIZE,
        )
        
        if len(validator_pubkey) != DILITHIUM_PUBKEY_SIZE:
            raise ValidationError(
                f"Invalid validator public key size: {len(validator_pubkey)}, "
                f"expected {DILITHIUM_PUBKEY_SIZE}"
            )
        
        if len(validator_signature) != DILITHIUM_SIGNATURE_SIZE:
            raise ValidationError(
                f"Invalid validator signature size: {len(validator_signature)}, "
                f"expected {DILITHIUM_SIGNATURE_SIZE}"
            )
        
        # Create block proposal for validation
        proposal = BlockProposal(
            slot=slot,
            proposer_pq_address=proposer_address,
            parent_hash=header.parent_hash,
            state_root=header.state_root,
            transactions_root=header.transaction_root,
            receipts_root=header.receipt_root,
            validator_pubkey=validator_pubkey,
            validator_signature=validator_signature,
            block_body_hash=header.hash,
        )
        
        # Verify Dilithium signature
        if not proposal.verify_signature():
            raise ValidationError(
                f"Invalid Dilithium signature on block at slot {slot} "
                f"from proposer {encode_hex(proposer_address)}"
            )
    
    def validate_seal_extension(
        self,
        header: BlockHeaderAPI,
        parents: Iterable[BlockHeaderAPI],
    ) -> None:
        """
        Validate the seal with parent context.
        
        For QR-PoS, this validates that the proposer was the designated
        validator for this slot.
        
        Args:
            header: Block header to validate
            parents: Parent headers for context
        
        Raises:
            ValidationError: If seal is invalid
        """
        # Genesis block (block 0) doesn't need validation
        if header.block_number == 0:
            return
        
        # First validate the signature
        self.validate_seal(header)
        
        # Get slot and epoch
        slot = self._get_slot_from_header(header)
        from trinity.consensus.qrpos.constants import SLOTS_PER_EPOCH
        epoch = slot // SLOTS_PER_EPOCH
        
        # Get proposer
        proposer_address = self._get_proposer_from_header(header)
        
        # Verify this was the designated proposer for this slot
        active_validators = self.context.beacon_state.validator_registry.get_active_validators(epoch)
        expected_proposer = self.context.beacon_state.validator_registry.get_proposer(
            slot, epoch, active_validators
        )
        
        if expected_proposer != proposer_address:
            raise ValidationError(
                f"Invalid proposer for slot {slot}. "
                f"Expected: {encode_hex(expected_proposer)}, "
                f"Got: {encode_hex(proposer_address)}"
            )
        
        # Verify proposer is active and not slashed
        validator = self.context.beacon_state.validator_registry.get_validator(proposer_address)
        if validator is None:
            raise ValidationError(f"Unknown proposer: {encode_hex(proposer_address)}")
        
        if not (validator.activation_epoch <= epoch < validator.exit_epoch):
            raise ValidationError(
                f"Proposer {encode_hex(proposer_address)} not active in epoch {epoch}"
            )
        
        if validator.slashed:
            raise ValidationError(
                f"Proposer {encode_hex(proposer_address)} is slashed"
            )
    
    @classmethod
    def get_fee_recipient(cls, header: BlockHeaderAPI) -> Address:
        """
        Get the address that should receive block rewards.
        
        For QR-PoS, this is the proposer's address.
        
        Args:
            header: Block header
        
        Returns:
            Fee recipient address (20 bytes)
        """
        # Get proposer PQ address (32 bytes)
        proposer_pq_address = cls._get_proposer_from_header(header)
        
        # Convert to 20-byte address for EVM compatibility
        # Use first 20 bytes of PQ address
        return Address(proposer_pq_address[:20])
    
    # Helper methods to extract QR-PoS fields from headers
    # In production, these would access proper header fields
    
    @staticmethod
    def _get_slot_from_header(header: BlockHeaderAPI) -> int:
        """
        Extract slot number from header.
        
        TODO: In production, this would be a proper header field.
        For now, we derive it from block number and timestamp.
        """
        # Temporary implementation until header structure is updated
        # Slot = block_number (1:1 mapping for now)
        return header.block_number
    
    @staticmethod
    def _get_proposer_from_header(header: BlockHeaderAPI) -> bytes:
        """
        Extract proposer PQ address from header.
        
        TODO: In production, this would be a proper header field.
        For now, we use coinbase (miner) field as placeholder.
        """
        # Temporary implementation
        # Pad coinbase address to 32 bytes for PQ address
        return bytes(header.coinbase).rjust(32, b'\x00')
    
    @staticmethod
    def _get_validator_pubkey_from_header(header: BlockHeaderAPI) -> bytes:
        """
        Extract validator public key from header.
        
        TODO: In production, this would be a proper header field.
        For now, we extract from extra_data.
        """
        # Temporary implementation
        # In production, header will have validator_pubkey field
        from trinity.consensus.qrpos.constants import DILITHIUM_PUBKEY_SIZE
        
        if len(header.extra_data) < DILITHIUM_PUBKEY_SIZE:
            # Return zero pubkey for genesis/testing
            return b'\x00' * DILITHIUM_PUBKEY_SIZE
        
        return header.extra_data[:DILITHIUM_PUBKEY_SIZE]
    
    @staticmethod
    def _get_validator_signature_from_header(header: BlockHeaderAPI) -> bytes:
        """
        Extract validator signature from header.
        
        TODO: In production, this would be a proper header field.
        For now, we extract from extra_data after pubkey.
        """
        # Temporary implementation
        from trinity.consensus.qrpos.constants import (
            DILITHIUM_PUBKEY_SIZE,
            DILITHIUM_SIGNATURE_SIZE,
        )
        
        if len(header.extra_data) < DILITHIUM_PUBKEY_SIZE + DILITHIUM_SIGNATURE_SIZE:
            # Return zero signature for genesis/testing
            return b'\x00' * DILITHIUM_SIGNATURE_SIZE
        
        return header.extra_data[DILITHIUM_PUBKEY_SIZE:DILITHIUM_PUBKEY_SIZE + DILITHIUM_SIGNATURE_SIZE]
