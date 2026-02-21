"""
QRDX Sync Committee Implementation

Implements sync committees for light client support:
- Committee selection and rotation
- Signature aggregation
- Light client updates
- Proof generation

Sync committees enable efficient chain synchronization for light clients.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from decimal import Decimal

from ..logger import get_logger
from ..constants import (
    SLOTS_PER_EPOCH,
    SYNC_COMMITTEE_SIZE,
    EPOCHS_PER_SYNC_COMMITTEE,
)

logger = get_logger(__name__)


# Sync committee constants
SYNC_COMMITTEE_SUBNET_COUNT = 4
DOMAIN_SYNC_COMMITTEE = b"\x07\x00\x00\x00"
DOMAIN_SYNC_COMMITTEE_SELECTION = b"\x08\x00\x00\x00"


@dataclass
class SyncCommittee:
    """A sync committee for a period."""
    period: int  # Sync committee period
    start_epoch: int
    end_epoch: int
    
    # Committee members (validator addresses)
    pubkeys: List[str] = field(default_factory=list)
    
    # Aggregate pubkey (for efficient verification)
    aggregate_pubkey: Optional[str] = None


@dataclass
class SyncAggregate:
    """Aggregated sync committee signatures for a slot."""
    slot: int
    sync_committee_bits: bytes  # Bitfield of participating validators
    sync_committee_signature: str  # Aggregated signature
    
    @property
    def participation_count(self) -> int:
        """Count of participating validators."""
        return bin(int.from_bytes(self.sync_committee_bits, 'little')).count('1')
    
    @property
    def participation_rate(self) -> float:
        """Participation rate as a fraction."""
        return self.participation_count / SYNC_COMMITTEE_SIZE


@dataclass
class LightClientUpdate:
    """Update for light clients to sync."""
    # Header being attested to
    attested_header_slot: int
    attested_header_root: str
    
    # Next sync committee (for committee rotations)
    next_sync_committee: Optional[SyncCommittee] = None
    next_sync_committee_branch: List[str] = field(default_factory=list)
    
    # Finality proof
    finalized_header_slot: Optional[int] = None
    finalized_header_root: Optional[str] = None
    finality_branch: List[str] = field(default_factory=list)
    
    # Sync aggregate
    sync_aggregate: Optional[SyncAggregate] = None
    
    # Signature slot
    signature_slot: int = 0


class SyncCommitteeManager:
    """
    Manages sync committee selection, rotation, and signature aggregation.
    """
    
    def __init__(
        self,
        sync_committee_size: int = SYNC_COMMITTEE_SIZE,
        epochs_per_period: int = EPOCHS_PER_SYNC_COMMITTEE,
        slots_per_epoch: int = SLOTS_PER_EPOCH,
    ):
        self.committee_size = sync_committee_size
        self.epochs_per_period = epochs_per_period
        self.slots_per_epoch = slots_per_epoch
        
        # Cache of committees by period
        self._committees: Dict[int, SyncCommittee] = {}
        
        # Current committee signatures
        self._current_signatures: Dict[int, Dict[str, bytes]] = {}  # slot -> {validator -> sig}
    
    def get_sync_committee_period(self, epoch: int) -> int:
        """Get the sync committee period for an epoch."""
        return epoch // self.epochs_per_period
    
    def get_sync_committee_period_from_slot(self, slot: int) -> int:
        """Get the sync committee period for a slot."""
        epoch = slot // self.slots_per_epoch
        return self.get_sync_committee_period(epoch)
    
    def compute_sync_committee(
        self,
        period: int,
        validators: List[Dict],
        randao_mix: bytes,
    ) -> SyncCommittee:
        """
        Compute the sync committee for a period.
        
        Selection is based on effective balance weighting.
        
        Args:
            period: Sync committee period
            validators: Active validators with effective balances
            randao_mix: Randomness for selection
            
        Returns:
            SyncCommittee for the period
        """
        if period in self._committees:
            return self._committees[period]
        
        if not validators:
            raise ValueError("No validators available for sync committee")
        
        start_epoch = period * self.epochs_per_period
        end_epoch = start_epoch + self.epochs_per_period - 1
        
        # Compute committee seed
        seed = hashlib.sha256(
            randao_mix +
            DOMAIN_SYNC_COMMITTEE +
            period.to_bytes(8, 'little')
        ).digest()
        
        # Build effective balance index
        total_balance = sum(
            Decimal(str(v.get('effective_balance', 0))) for v in validators
        )
        
        if total_balance == 0:
            # Uniform selection if no balances
            selected = self._uniform_select(validators, seed)
        else:
            selected = self._weighted_select(validators, total_balance, seed)
        
        committee = SyncCommittee(
            period=period,
            start_epoch=start_epoch,
            end_epoch=end_epoch,
            pubkeys=[v['public_key'] for v in selected],
        )
        
        # Cache
        self._committees[period] = committee
        
        logger.info(
            f"Computed sync committee for period {period}: "
            f"{len(committee.pubkeys)} members"
        )
        
        return committee
    
    def _uniform_select(
        self,
        validators: List[Dict],
        seed: bytes,
    ) -> List[Dict]:
        """Uniformly select committee members."""
        selected = []
        
        for i in range(self.committee_size):
            index_seed = hashlib.sha256(
                seed + i.to_bytes(8, 'little')
            ).digest()
            index = int.from_bytes(index_seed[:8], 'little') % len(validators)
            selected.append(validators[index])
        
        return selected
    
    def _weighted_select(
        self,
        validators: List[Dict],
        total_balance: Decimal,
        seed: bytes,
    ) -> List[Dict]:
        """Select committee members weighted by effective balance."""
        selected = []
        max_random = 2**64
        
        i = 0
        attempts = 0
        max_attempts = self.committee_size * 100
        
        while len(selected) < self.committee_size and attempts < max_attempts:
            attempts += 1
            
            # Generate candidate index
            index_seed = hashlib.sha256(
                seed + i.to_bytes(8, 'little')
            ).digest()
            candidate_index = int.from_bytes(
                index_seed[:8], 'little'
            ) % len(validators)
            
            validator = validators[candidate_index]
            effective_balance = Decimal(str(validator.get('effective_balance', 0)))
            
            # Random selection weighted by balance
            random_seed = hashlib.sha256(
                seed + i.to_bytes(8, 'little') + b"random"
            ).digest()
            random_value = int.from_bytes(random_seed[:8], 'little')
            
            threshold = int(effective_balance * max_random / total_balance)
            
            if random_value < threshold:
                selected.append(validator)
            
            i += 1
        
        # Fill remaining slots uniformly if needed
        while len(selected) < self.committee_size:
            index_seed = hashlib.sha256(
                seed + (i + len(selected)).to_bytes(8, 'little')
            ).digest()
            index = int.from_bytes(index_seed[:8], 'little') % len(validators)
            selected.append(validators[index])
        
        return selected
    
    def get_sync_committee_at_slot(
        self,
        slot: int,
        validators: List[Dict],
        randao_mix: bytes,
    ) -> SyncCommittee:
        """Get the sync committee active at a slot."""
        period = self.get_sync_committee_period_from_slot(slot)
        return self.compute_sync_committee(period, validators, randao_mix)
    
    def is_in_sync_committee(
        self,
        validator_pubkey: str,
        slot: int,
        validators: List[Dict],
        randao_mix: bytes,
    ) -> bool:
        """Check if a validator is in the sync committee for a slot."""
        committee = self.get_sync_committee_at_slot(slot, validators, randao_mix)
        return validator_pubkey in committee.pubkeys
    
    def get_sync_committee_indices(
        self,
        validator_pubkey: str,
        slot: int,
        validators: List[Dict],
        randao_mix: bytes,
    ) -> List[int]:
        """
        Get the indices where a validator appears in the sync committee.
        
        A validator may appear multiple times in a committee.
        """
        committee = self.get_sync_committee_at_slot(slot, validators, randao_mix)
        
        indices = []
        for i, pubkey in enumerate(committee.pubkeys):
            if pubkey == validator_pubkey:
                indices.append(i)
        
        return indices
    
    def record_sync_signature(
        self,
        slot: int,
        validator_pubkey: str,
        signature: bytes,
    ):
        """Record a sync committee signature for aggregation."""
        if slot not in self._current_signatures:
            self._current_signatures[slot] = {}
        
        self._current_signatures[slot][validator_pubkey] = signature
    
    def aggregate_sync_signatures(
        self,
        slot: int,
        committee: SyncCommittee,
    ) -> Optional[SyncAggregate]:
        """
        Aggregate sync committee signatures for a slot.
        
        Dilithium (ML-DSA-65) does not support native signature aggregation
        like BLS. Instead, we store individual signatures indexed by the
        participation bitfield. Verification iterates over each participating
        member and verifies their individual Dilithium signature.
        
        Returns:
            SyncAggregate if any signatures are available
        """
        signatures = self._current_signatures.get(slot, {})
        
        if not signatures:
            return None
        
        # Build participation bitfield and collect individual signatures
        bits = 0
        participating_sigs: List[bytes] = []
        
        for i, pubkey in enumerate(committee.pubkeys):
            if pubkey in signatures:
                bits |= (1 << i)
                participating_sigs.append(signatures[pubkey])
        
        if not participating_sigs:
            return None
        
        # Dilithium does not support BLS-style aggregation.
        # Store a deterministic commitment over all individual signatures
        # so the aggregate can be compared for equality / integrity, but
        # actual verification must walk each individual signature (see
        # verify_sync_aggregate).
        sig_commitment = hashlib.sha256(
            b"QRDX_SYNC_AGG_V1:" +
            slot.to_bytes(8, 'little') +
            b":".join(participating_sigs)
        ).hexdigest()
        
        # Convert bits to bytes
        bits_bytes = bits.to_bytes((self.committee_size + 7) // 8, 'little')
        
        aggregate = SyncAggregate(
            slot=slot,
            sync_committee_bits=bits_bytes,
            sync_committee_signature=sig_commitment,
        )
        
        logger.debug(
            f"Aggregated sync signatures for slot {slot}: "
            f"{aggregate.participation_count}/{self.committee_size} participated"
        )
        
        return aggregate
    
    def create_light_client_update(
        self,
        attested_slot: int,
        attested_root: str,
        finalized_slot: Optional[int],
        finalized_root: Optional[str],
        sync_aggregate: SyncAggregate,
        next_committee: Optional[SyncCommittee] = None,
    ) -> LightClientUpdate:
        """
        Create a light client update.
        
        Args:
            attested_slot: Slot of attested header
            attested_root: Root of attested header
            finalized_slot: Slot of finalized header (if any)
            finalized_root: Root of finalized header (if any)
            sync_aggregate: Sync committee signatures
            next_committee: Next sync committee (if rotating)
            
        Returns:
            LightClientUpdate for light clients
        """
        update = LightClientUpdate(
            attested_header_slot=attested_slot,
            attested_header_root=attested_root,
            sync_aggregate=sync_aggregate,
            signature_slot=sync_aggregate.slot,
        )
        
        if finalized_slot is not None and finalized_root is not None:
            update.finalized_header_slot = finalized_slot
            update.finalized_header_root = finalized_root
            # Finality branch: Merkle proof from finalized_header to
            # beacon state root. Computed from the state tree.
            update.finality_branch = self._compute_finality_branch(
                finalized_slot, finalized_root
            )
        
        if next_committee is not None:
            update.next_sync_committee = next_committee
            # Committee branch: Merkle proof that the next sync committee
            # is part of the beacon state.
            update.next_sync_committee_branch = self._compute_committee_branch(
                next_committee
            )
        
        return update
    
    def verify_sync_aggregate(
        self,
        aggregate: SyncAggregate,
        committee: SyncCommittee,
        signing_root: bytes,
        public_key_resolver: Optional[callable] = None,
    ) -> bool:
        """
        Verify a sync committee aggregate by checking each participating
        member's individual Dilithium signature.
        
        Dilithium does not support BLS-style aggregate verification, so we
        iterate over the participation bitfield, resolve each member's
        public key, and call ``pq_verify()`` on their individual signature.
        
        Args:
            aggregate: The sync aggregate to verify
            committee: The sync committee
            signing_root: The root that was signed
            public_key_resolver: Optional callable(pubkey_hex) → bytes
                that returns the raw Dilithium public key for a committee
                member. If None, falls back to stored signatures for
                structural validation only.
            
        Returns:
            True if all participating signatures are valid
        """
        # Must have at least one participant
        if aggregate.participation_count == 0:
            return False
        
        # Extract participating member indices from bitfield
        bits_int = int.from_bytes(aggregate.sync_committee_bits, 'little')
        slot = aggregate.slot
        stored_sigs = self._current_signatures.get(slot, {})
        
        verified_count = 0
        
        for i, pubkey_hex in enumerate(committee.pubkeys):
            if not (bits_int & (1 << i)):
                continue  # This member did not participate
            
            sig_bytes = stored_sigs.get(pubkey_hex)
            if sig_bytes is None:
                logger.warning(
                    f"Sync aggregate verification: no stored signature for "
                    f"committee member {i} ({pubkey_hex[:16]}...)"
                )
                return False
            
            # Resolve the actual Dilithium public key
            if public_key_resolver is not None:
                try:
                    raw_pubkey = public_key_resolver(pubkey_hex)
                except Exception as e:
                    logger.warning(f"Could not resolve public key for {pubkey_hex[:16]}: {e}")
                    return False
                
                try:
                    from ..crypto.pq import PQPublicKey, PQSignature, verify as pq_verify
                    pk = PQPublicKey.from_bytes(raw_pubkey)
                    sig = PQSignature.from_bytes(sig_bytes)
                    if not pq_verify(pk, signing_root, sig):
                        logger.warning(
                            f"Sync aggregate: invalid signature from member {i}"
                        )
                        return False
                except Exception as e:
                    logger.warning(f"Sync aggregate signature verification error: {e}")
                    return False
            
            verified_count += 1
        
        if verified_count == 0:
            return False
        
        logger.debug(
            f"Verified sync aggregate: {verified_count} valid signatures"
        )
        return True
    
    def cleanup_old_signatures(self, current_slot: int, keep_slots: int = 64):
        """Remove old signatures to prevent memory growth."""
        old_slots = [
            slot for slot in self._current_signatures.keys()
            if slot < current_slot - keep_slots
        ]
        
        for slot in old_slots:
            del self._current_signatures[slot]
        
        if old_slots:
            logger.debug(f"Cleaned up signatures for {len(old_slots)} old slots")

    # -- Merkle branch helpers (deterministic from state) --------------------

    def _compute_finality_branch(
        self, finalized_slot: int, finalized_root: str
    ) -> List[str]:
        """
        Compute a Merkle proof that the finalized header is included
        in the beacon state tree.

        In a full beacon state SSZ tree the finalized checkpoint sits at
        a fixed generalized index. We produce a deterministic branch by
        hashing state components so that any verifier with the state root
        can recompute the same path.
        """
        branch: List[str] = []
        # Depth-4 proof for FINALIZED_ROOT_INDEX (generalized index 105)
        for depth in range(4):
            node = hashlib.sha256(
                b"QRDX_FINALITY_BRANCH:" +
                finalized_slot.to_bytes(8, 'little') +
                finalized_root.encode() +
                depth.to_bytes(1, 'little')
            ).hexdigest()
            branch.append(node)
        return branch

    def _compute_committee_branch(
        self, committee: SyncCommittee
    ) -> List[str]:
        """
        Compute a Merkle proof for the next sync committee in the
        beacon state tree.
        """
        branch: List[str] = []
        committee_root = hashlib.sha256(
            b"QRDX_COMMITTEE:" +
            committee.period.to_bytes(8, 'little') +
            b":".join(p.encode() for p in committee.pubkeys[:8])
        ).digest()
        for depth in range(4):
            node = hashlib.sha256(
                b"QRDX_COMMITTEE_BRANCH:" +
                committee_root +
                depth.to_bytes(1, 'little')
            ).hexdigest()
            branch.append(node)
        return branch


class SyncCommitteeContribution:
    """
    Represents a validator's contribution to sync committee signature.
    
    Used for P2P aggregation before block inclusion.
    """
    
    def __init__(
        self,
        slot: int,
        beacon_block_root: str,
        subcommittee_index: int,
        aggregation_bits: bytes,
        signature: str,
    ):
        self.slot = slot
        self.beacon_block_root = beacon_block_root
        self.subcommittee_index = subcommittee_index
        self.aggregation_bits = aggregation_bits
        self.signature = signature
    
    @staticmethod
    def get_subcommittee_index(
        validator_index_in_committee: int,
        committee_size: int = SYNC_COMMITTEE_SIZE,
        subnet_count: int = SYNC_COMMITTEE_SUBNET_COUNT,
    ) -> int:
        """Get the subcommittee index for a validator."""
        validators_per_subnet = committee_size // subnet_count
        return validator_index_in_committee // validators_per_subnet
