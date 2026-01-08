"""
QRDX Validator Manager

Main coordinator for all validator operations in the QR-PoS consensus.

CRITICAL: Validators MUST use Post-Quantum (PQ) wallets.
"""

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

from ..logger import get_logger
from ..wallet_v2 import PQWallet, WalletType
from ..crypto.pq import PQPrivateKey, is_available as pq_available

from .types import (
    Validator,
    ValidatorSet,
    ValidatorStatus,
    EpochInfo,
    SlotInfo,
    ValidatorError,
    NotPQWalletError,
    InsufficientStakeError,
    ValidatorNotActiveError,
    AlreadyProposedError,
    AlreadyAttestedError,
)
from .config import ValidatorConfig, POS_CONSTANTS
from .stake import StakeManager, StakeDeposit, StakeWithdrawal
from .selection import ValidatorSelector, compute_initial_randao
from .attestation import Attestation, AttestationPool
from .slashing import (
    SlashingExecutor,
    SlashingProtectionDB,
    SlashingEvidence,
    SlashingConditions,
    SLASHING_PENALTIES,
)

logger = get_logger(__name__)


@dataclass
class PoSBlock:
    """
    PoS Block structure.
    
    Replaces the PoW block structure with validator-signed blocks.
    """
    # Header
    number: int
    parent_hash: str
    state_root: str
    transactions_root: str
    timestamp: int
    
    # Validator Info (PQ signatures)
    proposer_address: str           # PQ address
    proposer_public_key: bytes      # Dilithium public key
    proposer_signature: bytes       # Dilithium signature
    
    # Consensus Data
    slot: int
    epoch: int
    randao_reveal: bytes            # For randomness accumulation
    
    # Attestations from previous slot(s)
    attestations: List[Attestation] = field(default_factory=list)
    
    # Transactions
    transactions: List[Any] = field(default_factory=list)
    
    # Graffiti (optional message from proposer)
    graffiti: str = ""
    
    @property
    def hash(self) -> str:
        """Compute block hash."""
        data = (
            self.number.to_bytes(8, 'little') +
            bytes.fromhex(self.parent_hash) +
            bytes.fromhex(self.state_root) +
            bytes.fromhex(self.transactions_root) +
            self.timestamp.to_bytes(8, 'little') +
            self.slot.to_bytes(8, 'little') +
            self.proposer_address.encode('utf-8')
        )
        return hashlib.sha256(data).hexdigest()
    
    @property
    def signing_root(self) -> bytes:
        """Compute the signing root for proposer signature."""
        data = (
            self.number.to_bytes(8, 'little') +
            bytes.fromhex(self.parent_hash) +
            bytes.fromhex(self.state_root) +
            bytes.fromhex(self.transactions_root) +
            self.timestamp.to_bytes(8, 'little') +
            self.slot.to_bytes(8, 'little') +
            self.epoch.to_bytes(8, 'little') +
            self.randao_reveal
        )
        return hashlib.sha256(data).digest()
    
    def to_dict(self) -> dict:
        return {
            'number': self.number,
            'parent_hash': self.parent_hash,
            'state_root': self.state_root,
            'transactions_root': self.transactions_root,
            'timestamp': self.timestamp,
            'proposer_address': self.proposer_address,
            'proposer_public_key': self.proposer_public_key.hex(),
            'proposer_signature': self.proposer_signature.hex(),
            'slot': self.slot,
            'epoch': self.epoch,
            'randao_reveal': self.randao_reveal.hex(),
            'attestations': [a.to_dict() for a in self.attestations],
            'graffiti': self.graffiti,
            'hash': self.hash,
        }


class ValidatorManager:
    """
    Main coordinator for validator operations.
    
    Responsibilities:
    - Validator registration and lifecycle management
    - Block proposal coordination
    - Attestation creation and collection
    - Slashing detection and execution
    - Reward distribution
    
    CRITICAL: Requires a Post-Quantum (PQ) wallet for all signing operations.
    """
    
    def __init__(
        self,
        wallet: PQWallet,
        config: ValidatorConfig,
        stake_manager: StakeManager = None,
        selector: ValidatorSelector = None,
        attestation_pool: AttestationPool = None,
        slashing_executor: SlashingExecutor = None,
    ):
        """
        Initialize validator manager.
        
        Args:
            wallet: PQ wallet for signing (MUST be Post-Quantum type)
            config: Validator configuration
            stake_manager: Optional stake manager instance
            selector: Optional validator selector instance
            attestation_pool: Optional attestation pool instance
            slashing_executor: Optional slashing executor instance
        """
        # Validate PQ wallet requirement
        if wallet.wallet_type != WalletType.POST_QUANTUM:
            raise NotPQWalletError()
        
        if not pq_available():
            raise ValidatorError(
                "liboqs is required for validator operations but not available"
            )
        
        self.wallet = wallet
        self.config = config
        
        # Components
        self.stake_manager = stake_manager or StakeManager(config)
        self.selector = selector or ValidatorSelector()
        self.attestation_pool = attestation_pool or AttestationPool(
            max_attestations_per_slot=config.attestation.max_attestations_per_block
        )
        self.slashing_executor = slashing_executor or SlashingExecutor()
        
        # Slashing protection database
        self.slashing_protection: Optional[SlashingProtectionDB] = None
        
        # State
        self._validator: Optional[Validator] = None
        self._validator_set: Optional[ValidatorSet] = None
        self._current_epoch: int = 0
        self._current_slot: int = 0
        self._randao_mix: bytes = b'\x00' * 32
        
        # Task handles
        self._running = False
        self._duties_task: Optional[asyncio.Task] = None
        self._attestation_task: Optional[asyncio.Task] = None
        
        logger.info(f"ValidatorManager initialized with PQ wallet: {wallet.address}")
    
    # =========================================================================
    # FACTORY METHODS
    # =========================================================================
    
    @classmethod
    async def create(cls, config: ValidatorConfig) -> 'ValidatorManager':
        """
        Create and initialize a ValidatorManager from configuration.
        
        Args:
            config: Validator configuration
            
        Returns:
            Initialized ValidatorManager
            
        Raises:
            ValidatorError: If initialization fails
        """
        # Validate configuration
        config.validate()
        
        # Load PQ wallet
        wallet_path = Path(config.pq_wallet_path)
        if not wallet_path.exists():
            raise ValidatorError(f"PQ wallet file not found: {wallet_path}")
        
        wallet = PQWallet.load(wallet_path, config.pq_wallet_password)
        
        # Verify wallet type
        if wallet.wallet_type != WalletType.POST_QUANTUM:
            raise NotPQWalletError()
        
        # Create manager
        manager = cls(wallet, config)
        
        # Initialize slashing protection
        if config.slashing_protection.enabled:
            manager.slashing_protection = SlashingProtectionDB(
                config.slashing_protection.db_path
            )
            await manager.slashing_protection.initialize()
        
        return manager
    
    # =========================================================================
    # LIFECYCLE
    # =========================================================================
    
    async def start(self):
        """
        Start validator operations.
        
        Begins block proposal and attestation duties.
        """
        if self._running:
            logger.warning("ValidatorManager already running")
            return
        
        logger.info("Starting ValidatorManager...")
        
        # Check stake requirement
        stake = await self.stake_manager.get_effective_stake(self.wallet.address)
        min_stake = self.config.staking.min_validator_stake
        
        if stake < min_stake:
            raise InsufficientStakeError(required=min_stake, actual=stake)
        
        # Load validator info
        await self._load_validator()
        
        # Start duty loops
        self._running = True
        self._duties_task = asyncio.create_task(self._duties_loop())
        self._attestation_task = asyncio.create_task(self._attestation_loop())
        
        logger.info(
            f"ValidatorManager started: {self.wallet.address} "
            f"(stake: {stake} QRDX)"
        )
    
    async def stop(self):
        """Stop validator operations."""
        logger.info("Stopping ValidatorManager...")
        
        self._running = False
        
        if self._duties_task:
            self._duties_task.cancel()
            try:
                await self._duties_task
            except asyncio.CancelledError:
                pass
        
        if self._attestation_task:
            self._attestation_task.cancel()
            try:
                await self._attestation_task
            except asyncio.CancelledError:
                pass
        
        if self.slashing_protection:
            await self.slashing_protection.close()
        
        logger.info("ValidatorManager stopped")
    
    async def _load_validator(self):
        """Load validator information from database."""
        from .. import Database
        
        database = Database.instance
        if database:
            async with database.pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM validators WHERE address = $1",
                    self.wallet.address
                )
                
                if row:
                    self._validator = Validator(
                        address=row['address'],
                        public_key=bytes.fromhex(row['public_key']),
                        stake=Decimal(str(row['stake'])),
                        effective_stake=Decimal(str(row['effective_stake'])),
                        status=ValidatorStatus(row['status']),
                        activation_epoch=row.get('activation_epoch'),
                        exit_epoch=row.get('exit_epoch'),
                        slashed=row.get('slashed', False),
                    )
                    return
        
        # Create new validator entry
        self._validator = Validator(
            address=self.wallet.address,
            public_key=self.wallet.public_key,
            status=ValidatorStatus.PENDING,
        )
    
    # =========================================================================
    # REGISTRATION
    # =========================================================================
    
    async def register_validator(
        self,
        initial_stake: Decimal = None
    ) -> bool:
        """
        Register as a validator on the network.
        
        Args:
            initial_stake: Initial stake amount (uses min if not specified)
            
        Returns:
            True if registration successful
        """
        min_stake = self.config.staking.min_validator_stake
        stake_amount = initial_stake or min_stake
        
        if stake_amount < min_stake:
            raise InsufficientStakeError(required=min_stake, actual=stake_amount)
        
        # Check wallet balance (would need integration with balance checking)
        # For now, assume sufficient balance
        
        from .. import Database
        
        database = Database.instance
        if not database:
            raise ValidatorError("Database not initialized")
        
        try:
            async with database.pool.acquire() as conn:
                # Insert validator record
                await conn.execute("""
                    INSERT INTO validators 
                    (address, public_key, stake, effective_stake, status)
                    VALUES ($1, $2, $3, $3, 'pending')
                    ON CONFLICT (address) DO UPDATE SET
                        public_key = EXCLUDED.public_key,
                        stake = validators.stake + EXCLUDED.stake,
                        effective_stake = validators.effective_stake + EXCLUDED.stake
                """, 
                    self.wallet.address,
                    self.wallet.public_key_hex,
                    float(stake_amount),
                )
                
                logger.info(
                    f"Validator registered: {self.wallet.address} "
                    f"with {stake_amount} QRDX"
                )
                
                return True
                
        except Exception as e:
            logger.error(f"Failed to register validator: {e}")
            raise ValidatorError(f"Registration failed: {e}")
    
    async def request_exit(self) -> bool:
        """
        Request to exit the validator set.
        
        Starts the unbonding process.
        """
        if not self._validator:
            raise ValidatorError("Validator not loaded")
        
        if self._validator.status != ValidatorStatus.ACTIVE:
            raise ValidatorNotActiveError(
                f"Cannot exit: validator status is {self._validator.status.value}"
            )
        
        from .. import Database
        
        database = Database.instance
        if database:
            async with database.pool.acquire() as conn:
                await conn.execute("""
                    UPDATE validators 
                    SET status = 'exiting', exit_epoch = $1
                    WHERE address = $2
                """,
                    self._current_epoch + self.config.staking.unbonding_epochs,
                    self.wallet.address,
                )
        
        self._validator.status = ValidatorStatus.EXITING
        logger.info(f"Validator exit requested: {self.wallet.address}")
        
        return True
    
    # =========================================================================
    # BLOCK PROPOSAL
    # =========================================================================
    
    async def propose_block(
        self,
        slot: int,
        parent_hash: str,
        transactions: List[Any],
        state_root: str = None,
    ) -> Optional[PoSBlock]:
        """
        Propose a block if selected for this slot.
        
        Args:
            slot: Slot number
            parent_hash: Hash of parent block
            transactions: Transactions to include
            state_root: Optional state root (computed if not provided)
            
        Returns:
            Proposed block or None if not selected
        """
        if not self._validator or not self._validator.can_propose:
            return None
        
        # Check if we're the proposer for this slot
        validators = self._validator_set.validators if self._validator_set else [self._validator]
        
        if not self.selector.is_proposer(
            slot, 
            self.wallet.address, 
            validators,
            self._randao_mix
        ):
            logger.debug(f"Not proposer for slot {slot}")
            return None
        
        # Slashing protection check
        if self.slashing_protection:
            if not await self.slashing_protection.can_sign_block(
                self.wallet.address, slot
            ):
                raise AlreadyProposedError(slot)
        
        # Calculate epoch
        slots_per_epoch = POS_CONSTANTS['SLOTS_PER_EPOCH']
        epoch = slot // slots_per_epoch
        
        # Generate RANDAO reveal
        randao_domain = b'RANDAO_REVEAL'
        randao_message = slot.to_bytes(8, 'little') + randao_domain
        randao_reveal = self._sign_message(randao_message)
        
        # Compute transactions root
        transactions_root = self._compute_transactions_root(transactions)
        
        # Use provided state root or compute placeholder
        if not state_root:
            state_root = '0' * 64  # Placeholder
        
        # Get attestations to include
        attestations = await self.attestation_pool.select_attestations_for_inclusion(
            slot,
            self.config.attestation.max_attestations_per_block,
            self.config.attestation.max_inclusion_distance,
        )
        
        # Create unsigned block
        block = PoSBlock(
            number=slot,  # In PoS, block number often equals slot
            parent_hash=parent_hash,
            state_root=state_root,
            transactions_root=transactions_root,
            timestamp=int(time.time()),
            proposer_address=self.wallet.address,
            proposer_public_key=self.wallet.public_key,
            proposer_signature=b'',  # Will be set below
            slot=slot,
            epoch=epoch,
            randao_reveal=randao_reveal,
            attestations=attestations,
            transactions=transactions,
            graffiti=self.config.graffiti,
        )
        
        # Sign the block
        block.proposer_signature = self._sign_message(block.signing_root)
        
        # Record in slashing protection
        if self.slashing_protection:
            await self.slashing_protection.record_block_signature(
                self.wallet.address,
                slot,
                block.hash,
            )
        
        # Check for double-signing (should not happen with protection)
        await self.slashing_executor.check_double_sign(
            self.wallet.address,
            slot,
            block.hash,
            block.proposer_signature,
        )
        
        # Mark attestations as included
        await self.attestation_pool.mark_included(attestations, slot)
        
        logger.info(
            f"Block proposed: slot={slot}, hash={block.hash[:16]}..., "
            f"txs={len(transactions)}, attestations={len(attestations)}"
        )
        
        return block
    
    def _sign_message(self, message: bytes) -> bytes:
        """Sign a message with the validator's PQ key."""
        return self.wallet.sign(message)
    
    def _compute_transactions_root(self, transactions: List[Any]) -> str:
        """Compute Merkle root of transactions."""
        if not transactions:
            return '0' * 64
        
        # Simple hash of all transaction hashes
        tx_hashes = []
        for tx in transactions:
            if hasattr(tx, 'hash'):
                tx_hashes.append(tx.hash())
            else:
                tx_hashes.append(hashlib.sha256(str(tx).encode()).hexdigest())
        
        combined = ''.join(sorted(tx_hashes))
        return hashlib.sha256(combined.encode()).hexdigest()
    
    # =========================================================================
    # ATTESTATION
    # =========================================================================
    
    async def create_attestation(
        self,
        slot: int,
        block_hash: str,
        source_epoch: int = None,
        target_epoch: int = None,
    ) -> Optional[Attestation]:
        """
        Create an attestation for a block.
        
        Args:
            slot: Slot number
            block_hash: Hash of block to attest to
            source_epoch: Source checkpoint (uses current if not provided)
            target_epoch: Target checkpoint (uses current if not provided)
            
        Returns:
            Created attestation or None
        """
        if not self._validator or not self._validator.can_attest:
            return None
        
        slots_per_epoch = POS_CONSTANTS['SLOTS_PER_EPOCH']
        epoch = slot // slots_per_epoch
        
        source = source_epoch if source_epoch is not None else max(0, epoch - 1)
        target = target_epoch if target_epoch is not None else epoch
        
        # Slashing protection check
        if self.slashing_protection:
            if not await self.slashing_protection.can_sign_attestation(
                self.wallet.address,
                source,
                target,
            ):
                raise AlreadyAttestedError(slot)
        
        # Create attestation
        attestation = Attestation(
            slot=slot,
            epoch=epoch,
            block_hash=block_hash,
            validator_address=self.wallet.address,
            validator_index=self._validator.index or 0,
            signature=b'',  # Will be set below
            source_epoch=source,
            target_epoch=target,
        )
        
        # Sign attestation
        attestation.signature = self._sign_message(attestation.signing_root)
        
        # Record in slashing protection
        if self.slashing_protection:
            await self.slashing_protection.record_attestation_signature(
                self.wallet.address,
                source,
                target,
            )
        
        # Check for surround votes
        await self.slashing_executor.check_surround_vote(
            self.wallet.address,
            source,
            target,
            attestation.signature,
        )
        
        logger.debug(
            f"Attestation created: slot={slot}, block={block_hash[:16]}..."
        )
        
        return attestation
    
    async def submit_attestation(self, attestation: Attestation) -> bool:
        """
        Submit an attestation to the pool.
        
        Args:
            attestation: Attestation to submit
            
        Returns:
            True if accepted
        """
        # Add to local pool
        accepted = await self.attestation_pool.add_attestation(
            attestation,
            verify_signature=False,  # We just created it
        )
        
        if accepted:
            # Broadcast to network (would be handled by node)
            pass
        
        return accepted
    
    # =========================================================================
    # BLOCK VALIDATION
    # =========================================================================
    
    async def validate_block(self, block: PoSBlock) -> Tuple[bool, str]:
        """
        Validate a proposed block.
        
        Args:
            block: Block to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check proposer is valid for this slot
        validators = self._validator_set.validators if self._validator_set else []
        
        if validators:
            expected_proposer = self.selector.select_proposer(
                block.slot,
                validators,
                self._randao_mix,
            )
            
            if expected_proposer and expected_proposer.address != block.proposer_address:
                return False, f"Invalid proposer: expected {expected_proposer.address}"
        
        # Verify proposer signature
        from ..crypto.pq import PQPublicKey, PQSignature, verify as pq_verify
        
        try:
            pk = PQPublicKey.from_bytes(block.proposer_public_key)
            sig = PQSignature.from_bytes(block.proposer_signature)
            
            if not pq_verify(pk, block.signing_root, sig):
                return False, "Invalid proposer signature"
        except Exception as e:
            return False, f"Signature verification failed: {e}"
        
        # Check for double-signing
        evidence = await self.slashing_executor.check_double_sign(
            block.proposer_address,
            block.slot,
            block.hash,
            block.proposer_signature,
        )
        
        if evidence:
            return False, "Double-signing detected"
        
        # Validate attestations
        for attestation in block.attestations:
            validator_pk = self._get_validator_public_key(attestation.validator_address)
            if validator_pk and not attestation.verify(validator_pk):
                return False, f"Invalid attestation from {attestation.validator_address}"
        
        return True, ""
    
    def _get_validator_public_key(self, address: str) -> Optional[bytes]:
        """Get validator's public key by address."""
        if self._validator_set:
            validator = self._validator_set.get_validator_by_address(address)
            if validator:
                return validator.public_key
        return None
    
    # =========================================================================
    # FINALITY
    # =========================================================================
    
    async def check_finality(
        self,
        slot: int,
        block_hash: str,
    ) -> bool:
        """
        Check if a block has achieved finality.
        
        Finality requires 2/3+ of stake to have attested.
        
        Args:
            slot: Slot number
            block_hash: Block hash
            
        Returns:
            True if block is finalized
        """
        validators = self._validator_set.validators if self._validator_set else []
        
        threshold = POS_CONSTANTS['ATTESTATION_THRESHOLD']
        
        return await self.attestation_pool.has_supermajority(
            slot,
            block_hash,
            validators,
            threshold,
        )
    
    # =========================================================================
    # DUTY LOOPS
    # =========================================================================
    
    async def _duties_loop(self):
        """Main loop for block proposal duties."""
        slot_duration = POS_CONSTANTS['SLOT_DURATION']
        
        while self._running:
            try:
                # Calculate current slot
                # In production, this would use genesis time
                current_time = int(time.time())
                self._current_slot = current_time // slot_duration
                self._current_epoch = self._current_slot // POS_CONSTANTS['SLOTS_PER_EPOCH']
                
                # Check if we should propose
                # (Block proposal logic would be triggered here)
                
                # Sleep until next slot
                next_slot_time = (self._current_slot + 1) * slot_duration
                sleep_time = max(0.1, next_slot_time - time.time())
                await asyncio.sleep(sleep_time)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in duties loop: {e}")
                await asyncio.sleep(1)
    
    async def _attestation_loop(self):
        """Loop for attestation duties."""
        slot_duration = POS_CONSTANTS['SLOT_DURATION']
        attestation_delay = self.config.attestation.aggregation_delay
        
        while self._running:
            try:
                # Wait for attestation timing within slot
                await asyncio.sleep(attestation_delay)
                
                # Attestation logic would be triggered here
                # when we receive a block to attest to
                
                # Sleep until next slot
                await asyncio.sleep(slot_duration - attestation_delay)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in attestation loop: {e}")
                await asyncio.sleep(1)
    
    # =========================================================================
    # STATUS & INFO
    # =========================================================================
    
    async def get_status(self) -> dict:
        """Get validator status information."""
        stake = await self.stake_manager.get_effective_stake(self.wallet.address)
        
        return {
            'address': self.wallet.address,
            'public_key': self.wallet.public_key_hex,
            'stake': str(stake),
            'status': self._validator.status.value if self._validator else 'unknown',
            'is_active': self._validator.is_active if self._validator else False,
            'current_slot': self._current_slot,
            'current_epoch': self._current_epoch,
            'running': self._running,
            'config': {
                'min_stake': str(self.config.staking.min_validator_stake),
                'graffiti': self.config.graffiti,
            }
        }
    
    async def get_duties(self, epoch: int = None) -> dict:
        """
        Get validator duties for an epoch.
        
        Args:
            epoch: Epoch to get duties for (current if not specified)
            
        Returns:
            Dictionary of duties
        """
        epoch = epoch or self._current_epoch
        slots_per_epoch = POS_CONSTANTS['SLOTS_PER_EPOCH']
        
        validators = self._validator_set.validators if self._validator_set else [self._validator]
        
        # Get proposal duties
        proposal_duties = self.selector.get_proposer_duties(
            epoch,
            slots_per_epoch,
            validators,
            self._randao_mix,
        )
        
        my_proposals = [
            slot for slot, v in proposal_duties 
            if v and v.address == self.wallet.address
        ]
        
        # Get committee duties
        committee_duties = self.selector.get_committee_duties(
            epoch,
            slots_per_epoch,
            validators,
            len(validators),  # Committee size = all validators for now
            self._randao_mix,
        )
        
        my_attestations = [
            slot for slot, committee in committee_duties
            if any(v.address == self.wallet.address for v in committee)
        ]
        
        return {
            'epoch': epoch,
            'proposal_slots': my_proposals,
            'attestation_slots': my_attestations,
        }
