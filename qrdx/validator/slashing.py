"""
QRDX Slashing System

Implements slashing conditions and enforcement for validator misbehavior.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import List, Optional, Dict, Tuple

from ..logger import get_logger
from .types import Validator, ValidatorError

logger = get_logger(__name__)


class SlashingConditions(Enum):
    """Types of slashable offenses."""
    
    DOUBLE_SIGN = "double_sign"
    """Proposing two blocks at the same height."""
    
    INVALID_ATTESTATION = "invalid_attestation"
    """Attesting to a provably invalid block."""
    
    SURROUND_VOTE = "surround_vote"
    """Casting conflicting attestation votes (Casper FFG)."""
    
    DOWNTIME = "downtime"
    """Missing too many attestation duties."""
    
    BRIDGE_FRAUD = "bridge_fraud"
    """Submitting fraudulent bridge proofs."""


# Slashing penalties as fraction of stake
SLASHING_PENALTIES: Dict[SlashingConditions, Decimal] = {
    SlashingConditions.DOUBLE_SIGN: Decimal("0.50"),          # 50% stake
    SlashingConditions.INVALID_ATTESTATION: Decimal("0.30"),  # 30% stake
    SlashingConditions.SURROUND_VOTE: Decimal("0.50"),        # 50% stake
    SlashingConditions.DOWNTIME: Decimal("0.05"),             # 5% stake
    SlashingConditions.BRIDGE_FRAUD: Decimal("1.00"),         # 100% stake
}


@dataclass
class SlashingEvidence:
    """
    Evidence for a slashable offense.
    
    Attributes:
        condition: Type of slashing offense
        validator_address: Address of offending validator
        slot: Slot where offense occurred
        epoch: Epoch where offense occurred
        evidence_data: Serialized proof of offense
        discovered_at: When evidence was discovered
        processed: Whether slashing has been executed
    """
    condition: SlashingConditions
    validator_address: str
    slot: int
    epoch: int
    evidence_data: Dict
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    processed: bool = False
    
    def to_dict(self) -> dict:
        return {
            'condition': self.condition.value,
            'validator_address': self.validator_address,
            'slot': self.slot,
            'epoch': self.epoch,
            'evidence_data': self.evidence_data,
            'discovered_at': self.discovered_at.isoformat(),
            'processed': self.processed,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'SlashingEvidence':
        return cls(
            condition=SlashingConditions(data['condition']),
            validator_address=data['validator_address'],
            slot=data['slot'],
            epoch=data['epoch'],
            evidence_data=data['evidence_data'],
            discovered_at=datetime.fromisoformat(data['discovered_at']),
            processed=data.get('processed', False),
        )


@dataclass
class DoubleSignEvidence:
    """Evidence of double-signing (two blocks at same slot)."""
    slot: int
    block1_hash: str
    block1_signature: bytes
    block2_hash: str
    block2_signature: bytes
    
    def to_dict(self) -> dict:
        return {
            'type': 'double_sign',
            'slot': self.slot,
            'block1_hash': self.block1_hash,
            'block1_signature': self.block1_signature.hex(),
            'block2_hash': self.block2_hash,
            'block2_signature': self.block2_signature.hex(),
        }


@dataclass
class SurroundVoteEvidence:
    """Evidence of surround voting (conflicting attestations)."""
    source_epoch_1: int
    target_epoch_1: int
    signature_1: bytes
    source_epoch_2: int
    target_epoch_2: int
    signature_2: bytes
    
    def to_dict(self) -> dict:
        return {
            'type': 'surround_vote',
            'source_epoch_1': self.source_epoch_1,
            'target_epoch_1': self.target_epoch_1,
            'signature_1': self.signature_1.hex(),
            'source_epoch_2': self.source_epoch_2,
            'target_epoch_2': self.target_epoch_2,
            'signature_2': self.signature_2.hex(),
        }
    
    def is_surround(self) -> bool:
        """
        Check if votes constitute a surround violation.
        
        A surround vote occurs when:
        - Vote 1 surrounds Vote 2: source_1 < source_2 < target_2 < target_1
        - Vote 2 surrounds Vote 1: source_2 < source_1 < target_1 < target_2
        """
        # Check if vote 1 surrounds vote 2
        if (self.source_epoch_1 < self.source_epoch_2 and 
            self.target_epoch_2 < self.target_epoch_1):
            return True
        
        # Check if vote 2 surrounds vote 1
        if (self.source_epoch_2 < self.source_epoch_1 and 
            self.target_epoch_1 < self.target_epoch_2):
            return True
        
        return False


class SlashingExecutor:
    """
    Detects and executes slashing for validator misbehavior.
    
    Responsibilities:
    - Monitor for slashable offenses
    - Collect and verify slashing evidence
    - Execute slashing penalties
    - Report slashing to network
    """
    
    def __init__(self):
        """Initialize slashing executor."""
        self._pending_evidence: List[SlashingEvidence] = []
        self._processed_evidence: List[SlashingEvidence] = []
        self._lock = asyncio.Lock()
        
        # Track proposals and attestations for detection
        self._proposals: Dict[Tuple[str, int], List[str]] = {}  # (validator, slot) -> [block_hashes]
        self._attestations: Dict[Tuple[str, int], List[Tuple[int, int]]] = {}  # (validator, epoch) -> [(source, target)]
    
    # =========================================================================
    # EVIDENCE DETECTION
    # =========================================================================
    
    async def check_double_sign(
        self,
        validator_address: str,
        slot: int,
        block_hash: str,
        signature: bytes
    ) -> Optional[SlashingEvidence]:
        """
        Check for double-signing violation.
        
        Args:
            validator_address: Validator's address
            slot: Slot number
            block_hash: Block hash
            signature: Block signature
            
        Returns:
            SlashingEvidence if violation detected, None otherwise
        """
        async with self._lock:
            key = (validator_address, slot)
            
            if key in self._proposals:
                existing_hashes = self._proposals[key]
                
                # Check if proposing different block at same slot
                for existing_hash in existing_hashes:
                    if existing_hash != block_hash:
                        # Double sign detected!
                        logger.warning(
                            f"Double-sign detected: {validator_address} at slot {slot}"
                        )
                        
                        evidence = SlashingEvidence(
                            condition=SlashingConditions.DOUBLE_SIGN,
                            validator_address=validator_address,
                            slot=slot,
                            epoch=slot // 32,  # Assuming 32 slots per epoch
                            evidence_data={
                                'slot': slot,
                                'block1_hash': existing_hash,
                                'block2_hash': block_hash,
                                'signature': signature.hex(),
                            }
                        )
                        
                        self._pending_evidence.append(evidence)
                        return evidence
            
            # Record this proposal
            if key not in self._proposals:
                self._proposals[key] = []
            self._proposals[key].append(block_hash)
            
            return None
    
    async def check_surround_vote(
        self,
        validator_address: str,
        source_epoch: int,
        target_epoch: int,
        signature: bytes
    ) -> Optional[SlashingEvidence]:
        """
        Check for surround vote violation (Casper FFG).
        
        A surround vote occurs when a validator makes two attestations
        where one vote surrounds the other.
        
        Args:
            validator_address: Validator's address
            source_epoch: Source checkpoint epoch
            target_epoch: Target checkpoint epoch
            signature: Attestation signature
            
        Returns:
            SlashingEvidence if violation detected
        """
        async with self._lock:
            key = (validator_address, target_epoch)
            
            # Check existing attestations from this validator
            for (addr, epoch), votes in self._attestations.items():
                if addr != validator_address:
                    continue
                
                for existing_source, existing_target in votes:
                    # Check for surround: new vote surrounds existing
                    if (source_epoch < existing_source and 
                        existing_target < target_epoch):
                        logger.warning(
                            f"Surround vote detected: {validator_address} "
                            f"({source_epoch},{target_epoch}) surrounds "
                            f"({existing_source},{existing_target})"
                        )
                        
                        evidence = SlashingEvidence(
                            condition=SlashingConditions.SURROUND_VOTE,
                            validator_address=validator_address,
                            slot=target_epoch * 32,  # Approximate slot
                            epoch=target_epoch,
                            evidence_data={
                                'vote1': {
                                    'source': existing_source,
                                    'target': existing_target,
                                },
                                'vote2': {
                                    'source': source_epoch,
                                    'target': target_epoch,
                                    'signature': signature.hex(),
                                },
                            }
                        )
                        
                        self._pending_evidence.append(evidence)
                        return evidence
                    
                    # Check for surround: existing surrounds new
                    if (existing_source < source_epoch and 
                        target_epoch < existing_target):
                        logger.warning(
                            f"Surround vote detected: {validator_address} "
                            f"({existing_source},{existing_target}) surrounds "
                            f"({source_epoch},{target_epoch})"
                        )
                        
                        evidence = SlashingEvidence(
                            condition=SlashingConditions.SURROUND_VOTE,
                            validator_address=validator_address,
                            slot=target_epoch * 32,
                            epoch=target_epoch,
                            evidence_data={
                                'vote1': {
                                    'source': existing_source,
                                    'target': existing_target,
                                },
                                'vote2': {
                                    'source': source_epoch,
                                    'target': target_epoch,
                                    'signature': signature.hex(),
                                },
                            }
                        )
                        
                        self._pending_evidence.append(evidence)
                        return evidence
            
            # Record this attestation
            if key not in self._attestations:
                self._attestations[key] = []
            self._attestations[key].append((source_epoch, target_epoch))
            
            return None
    
    async def check_downtime(
        self,
        validator_address: str,
        epoch: int,
        expected_attestations: int,
        actual_attestations: int,
        threshold: float = 0.1
    ) -> Optional[SlashingEvidence]:
        """
        Check for downtime violation.
        
        Args:
            validator_address: Validator's address
            epoch: Epoch being checked
            expected_attestations: Expected attestation count
            actual_attestations: Actual attestation count
            threshold: Maximum allowed miss rate (default 10%)
            
        Returns:
            SlashingEvidence if violation detected
        """
        if expected_attestations == 0:
            return None
        
        miss_rate = 1 - (actual_attestations / expected_attestations)
        
        if miss_rate > threshold:
            logger.warning(
                f"Downtime detected: {validator_address} missed "
                f"{miss_rate * 100:.1f}% of attestations in epoch {epoch}"
            )
            
            evidence = SlashingEvidence(
                condition=SlashingConditions.DOWNTIME,
                validator_address=validator_address,
                slot=epoch * 32,
                epoch=epoch,
                evidence_data={
                    'expected': expected_attestations,
                    'actual': actual_attestations,
                    'miss_rate': float(miss_rate),
                    'threshold': threshold,
                }
            )
            
            self._pending_evidence.append(evidence)
            return evidence
        
        return None
    
    async def submit_evidence(self, evidence: SlashingEvidence) -> bool:
        """
        Submit external slashing evidence.
        
        Args:
            evidence: Slashing evidence to submit
            
        Returns:
            True if evidence was accepted
        """
        async with self._lock:
            # Verify evidence is not duplicate
            for existing in self._pending_evidence + self._processed_evidence:
                if (existing.validator_address == evidence.validator_address and
                    existing.slot == evidence.slot and
                    existing.condition == evidence.condition):
                    logger.debug(f"Duplicate evidence rejected")
                    return False
            
            self._pending_evidence.append(evidence)
            logger.info(
                f"Slashing evidence submitted: {evidence.condition.value} "
                f"for {evidence.validator_address}"
            )
            return True
    
    # =========================================================================
    # SLASHING EXECUTION
    # =========================================================================
    
    async def execute_pending_slashings(self, stake_manager) -> List[Tuple[str, Decimal]]:
        """
        Execute all pending slashings.
        
        Args:
            stake_manager: StakeManager instance for executing slashes
            
        Returns:
            List of (validator_address, amount_slashed) tuples
        """
        results = []
        
        async with self._lock:
            for evidence in self._pending_evidence:
                if evidence.processed:
                    continue
                
                try:
                    # Get penalty percentage
                    penalty_pct = SLASHING_PENALTIES.get(
                        evidence.condition,
                        Decimal("0.10")  # Default 10%
                    )
                    
                    # Execute slash
                    amount = await stake_manager.slash(
                        validator_address=evidence.validator_address,
                        percentage=penalty_pct,
                        reason=evidence.condition.value,
                        evidence=str(evidence.evidence_data),
                    )
                    
                    evidence.processed = True
                    self._processed_evidence.append(evidence)
                    results.append((evidence.validator_address, amount))
                    
                    logger.info(
                        f"Slashing executed: {evidence.validator_address} "
                        f"lost {amount} QRDX for {evidence.condition.value}"
                    )
                    
                except Exception as e:
                    logger.error(
                        f"Failed to execute slashing for {evidence.validator_address}: {e}"
                    )
            
            # Remove processed evidence from pending
            self._pending_evidence = [
                e for e in self._pending_evidence if not e.processed
            ]
        
        return results
    
    async def get_pending_evidence(self) -> List[SlashingEvidence]:
        """Get all pending slashing evidence."""
        async with self._lock:
            return self._pending_evidence.copy()
    
    async def get_slashing_history(
        self,
        validator_address: str = None
    ) -> List[SlashingEvidence]:
        """
        Get slashing history.
        
        Args:
            validator_address: Optional filter by validator
            
        Returns:
            List of processed slashing evidence
        """
        async with self._lock:
            if validator_address:
                return [
                    e for e in self._processed_evidence
                    if e.validator_address == validator_address
                ]
            return self._processed_evidence.copy()
    
    # =========================================================================
    # CLEANUP
    # =========================================================================
    
    async def prune_old_data(self, current_epoch: int, keep_epochs: int = 100):
        """
        Clean up old tracking data.
        
        Args:
            current_epoch: Current epoch
            keep_epochs: Number of epochs to keep
        """
        async with self._lock:
            min_epoch = current_epoch - keep_epochs
            min_slot = min_epoch * 32
            
            # Clean proposals
            self._proposals = {
                k: v for k, v in self._proposals.items()
                if k[1] >= min_slot
            }
            
            # Clean attestations
            self._attestations = {
                k: v for k, v in self._attestations.items()
                if k[1] >= min_epoch
            }
            
            logger.debug(
                f"Pruned slashing data: keeping epochs >= {min_epoch}"
            )


class SlashingProtectionDB:
    """
    Local database for slashing protection.
    
    Prevents the validator from signing slashable messages
    by tracking previously signed data.
    """
    
    def __init__(self, db_path: str):
        """
        Initialize slashing protection database.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._conn = None
    
    async def initialize(self):
        """Initialize database tables."""
        import aiosqlite
        
        self._conn = await aiosqlite.connect(self.db_path)
        
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS signed_blocks (
                validator_address TEXT,
                slot INTEGER,
                block_hash TEXT,
                PRIMARY KEY (validator_address, slot)
            )
        """)
        
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS signed_attestations (
                validator_address TEXT,
                source_epoch INTEGER,
                target_epoch INTEGER,
                PRIMARY KEY (validator_address, target_epoch)
            )
        """)
        
        await self._conn.commit()
    
    async def can_sign_block(
        self,
        validator_address: str,
        slot: int
    ) -> bool:
        """Check if it's safe to sign a block at this slot."""
        async with self._conn.execute(
            "SELECT block_hash FROM signed_blocks WHERE validator_address = ? AND slot = ?",
            (validator_address, slot)
        ) as cursor:
            row = await cursor.fetchone()
            return row is None
    
    async def record_block_signature(
        self,
        validator_address: str,
        slot: int,
        block_hash: str
    ):
        """Record that a block was signed."""
        await self._conn.execute(
            "INSERT OR REPLACE INTO signed_blocks VALUES (?, ?, ?)",
            (validator_address, slot, block_hash)
        )
        await self._conn.commit()
    
    async def can_sign_attestation(
        self,
        validator_address: str,
        source_epoch: int,
        target_epoch: int
    ) -> bool:
        """Check if it's safe to sign an attestation."""
        # Check for existing attestation at same target
        async with self._conn.execute(
            "SELECT source_epoch FROM signed_attestations "
            "WHERE validator_address = ? AND target_epoch = ?",
            (validator_address, target_epoch)
        ) as cursor:
            row = await cursor.fetchone()
            if row is not None:
                return False
        
        # Check for surround violations
        async with self._conn.execute(
            "SELECT source_epoch, target_epoch FROM signed_attestations "
            "WHERE validator_address = ?",
            (validator_address,)
        ) as cursor:
            async for row in cursor:
                existing_source, existing_target = row
                
                # Would new vote surround existing?
                if source_epoch < existing_source and existing_target < target_epoch:
                    return False
                
                # Would existing surround new?
                if existing_source < source_epoch and target_epoch < existing_target:
                    return False
        
        return True
    
    async def record_attestation_signature(
        self,
        validator_address: str,
        source_epoch: int,
        target_epoch: int
    ):
        """Record that an attestation was signed."""
        await self._conn.execute(
            "INSERT OR REPLACE INTO signed_attestations VALUES (?, ?, ?)",
            (validator_address, source_epoch, target_epoch)
        )
        await self._conn.commit()
    
    async def close(self):
        """Close database connection."""
        if self._conn:
            await self._conn.close()
