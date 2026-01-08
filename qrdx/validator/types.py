"""
QRDX Validator Types and Exceptions

Core data types for the validator system.
"""

from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from typing import Optional, List
from datetime import datetime


class ValidatorStatus(Enum):
    """Validator lifecycle status."""
    PENDING = "pending"           # Registered but not activated
    ACTIVE = "active"             # Active in validator set
    EXITING = "exiting"           # Requested exit, in unbonding
    EXITED = "exited"             # Fully exited
    SLASHED = "slashed"           # Slashed and removed


class ValidatorError(Exception):
    """Base exception for validator operations."""
    pass


class NotPQWalletError(ValidatorError):
    """Raised when attempting to use non-PQ wallet as validator."""
    def __init__(self, message: str = None):
        super().__init__(
            message or "Validators MUST use Post-Quantum (PQ) wallets. "
                       "Classical ECDSA wallets are not permitted."
        )


class InsufficientStakeError(ValidatorError):
    """Raised when stake amount is insufficient."""
    def __init__(self, required: Decimal, actual: Decimal):
        self.required = required
        self.actual = actual
        super().__init__(
            f"Insufficient stake: {actual} QRDX (required: {required} QRDX)"
        )


class InvalidValidatorError(ValidatorError):
    """Raised when validator is invalid or not found."""
    pass


class ValidatorNotActiveError(ValidatorError):
    """Raised when validator is not in active state."""
    pass


class SlashingProtectionError(ValidatorError):
    """Raised when slashing protection blocks an action."""
    pass


class AlreadyProposedError(SlashingProtectionError):
    """Raised when trying to propose twice for same slot."""
    def __init__(self, slot: int):
        self.slot = slot
        super().__init__(f"Already proposed block for slot {slot}")


class AlreadyAttestedError(SlashingProtectionError):
    """Raised when trying to attest twice for same slot."""
    def __init__(self, slot: int):
        self.slot = slot
        super().__init__(f"Already attested for slot {slot}")


@dataclass
class Validator:
    """
    Represents a validator in the network.
    
    Attributes:
        address: PQ wallet address (0xPQ...)
        public_key: Dilithium3 public key bytes
        stake: Total staked amount
        effective_stake: Stake available for validation (excludes pending withdrawals)
        status: Current validator status
        activation_epoch: Epoch when validator became active
        exit_epoch: Epoch when validator will exit (if exiting)
        slashed: Whether validator has been slashed
        uptime_score: Validator's uptime score (0.0 - 1.0)
        index: Validator index in the active set
    """
    address: str
    public_key: bytes
    stake: Decimal = Decimal("0")
    effective_stake: Decimal = Decimal("0")
    status: ValidatorStatus = ValidatorStatus.PENDING
    activation_epoch: Optional[int] = None
    exit_epoch: Optional[int] = None
    slashed: bool = False
    uptime_score: float = 1.0
    index: Optional[int] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def is_active(self) -> bool:
        """Check if validator is active."""
        return self.status == ValidatorStatus.ACTIVE
    
    @property
    def can_propose(self) -> bool:
        """Check if validator can propose blocks."""
        return self.is_active and not self.slashed
    
    @property
    def can_attest(self) -> bool:
        """Check if validator can attest."""
        return self.is_active and not self.slashed
    
    @property
    def public_key_hex(self) -> str:
        """Get public key as hex string."""
        return self.public_key.hex()
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            'address': self.address,
            'public_key': self.public_key_hex,
            'stake': str(self.stake),
            'effective_stake': str(self.effective_stake),
            'status': self.status.value,
            'activation_epoch': self.activation_epoch,
            'exit_epoch': self.exit_epoch,
            'slashed': self.slashed,
            'uptime_score': self.uptime_score,
            'index': self.index,
            'created_at': self.created_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Validator':
        """Create from dictionary."""
        return cls(
            address=data['address'],
            public_key=bytes.fromhex(data['public_key']),
            stake=Decimal(data['stake']),
            effective_stake=Decimal(data['effective_stake']),
            status=ValidatorStatus(data['status']),
            activation_epoch=data.get('activation_epoch'),
            exit_epoch=data.get('exit_epoch'),
            slashed=data.get('slashed', False),
            uptime_score=data.get('uptime_score', 1.0),
            index=data.get('index'),
            created_at=datetime.fromisoformat(data['created_at']) if 'created_at' in data else datetime.utcnow(),
        )


@dataclass
class ValidatorSet:
    """
    Represents the active validator set for an epoch.
    
    Attributes:
        epoch: Epoch number
        validators: List of active validators
        total_stake: Total stake in the set
        randao_mix: Randomness for this epoch
    """
    epoch: int
    validators: List[Validator]
    total_stake: Decimal = Decimal("0")
    randao_mix: bytes = field(default_factory=lambda: b'\x00' * 32)
    
    def __post_init__(self):
        """Calculate total stake if not set."""
        if self.total_stake == Decimal("0"):
            self.total_stake = sum(v.effective_stake for v in self.validators)
    
    def get_validator_by_address(self, address: str) -> Optional[Validator]:
        """Get validator by address."""
        for v in self.validators:
            if v.address == address:
                return v
        return None
    
    def get_validator_by_index(self, index: int) -> Optional[Validator]:
        """Get validator by index."""
        if 0 <= index < len(self.validators):
            return self.validators[index]
        return None
    
    @property
    def size(self) -> int:
        """Number of validators in set."""
        return len(self.validators)


@dataclass 
class EpochInfo:
    """
    Information about an epoch.
    
    Attributes:
        epoch: Epoch number
        start_slot: First slot of epoch
        end_slot: Last slot of epoch
        randao_mix: Randomness accumulated during epoch
        finalized: Whether epoch is finalized
        total_stake: Total stake at epoch start
    """
    epoch: int
    start_slot: int
    end_slot: int
    randao_mix: bytes = field(default_factory=lambda: b'\x00' * 32)
    finalized: bool = False
    total_stake: Decimal = Decimal("0")
    
    @property
    def slot_count(self) -> int:
        """Number of slots in epoch."""
        return self.end_slot - self.start_slot + 1


@dataclass
class SlotInfo:
    """
    Information about a slot.
    
    Attributes:
        slot: Slot number
        epoch: Epoch containing this slot
        proposer_index: Index of assigned proposer
        block_proposed: Whether block was proposed
        attestation_count: Number of attestations received
    """
    slot: int
    epoch: int
    proposer_index: int
    block_proposed: bool = False
    attestation_count: int = 0
