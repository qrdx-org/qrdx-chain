"""
QRDX Validator Manager

Main coordinator for all validator operations in the QR-PoS consensus.

CRITICAL: Validators MUST use Post-Quantum (PQ) wallets.
"""

import asyncio
import hashlib
import time
import os
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
        database=None,
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
            database: Database instance for persistence
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
        self.database = database
        
        # Components
        self.stake_manager = stake_manager or StakeManager(config, database)
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
        
        # Load stakes from database
        await self.stake_manager.load_from_database()
        
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
        
        # Enforce minimum stake requirement (Ethereum-grade security)
        current_stake = await self.stake_manager.get_effective_stake(self.wallet.address)
        min_required = self.config.staking.min_validator_stake
        if current_stake < min_required:
            logger.error(f"Insufficient stake for block proposal: {current_stake} < {min_required} QRDX")
            return None
        
        # Check if we're the proposer for this slot
        validators = self._validator_set.validators if self._validator_set else [self._validator]
        
        logger.info(f"Checking proposer for slot {slot}: validator_set has {len(validators)} validators")
        
        if not self.selector.is_proposer(
            slot, 
            self.wallet.address, 
            validators,
            self._randao_mix
        ):
            logger.info(f"Not proposer for slot {slot} - selected another validator")
            return None
        
        logger.info(f"🎯 Selected as proposer for slot {slot}!")
        
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
        
        # CRITICAL: Execute contract transactions BEFORE creating block
        # This sets gas_used on each transaction for validation
        await self._execute_contract_transactions(transactions, parent_hash)
        
        # Compute transactions root
        transactions_root = self._compute_transactions_root(transactions)
        
        # Use provided state root or compute from consensus state
        if not state_root:
            state_root = await self._compute_state_root(transactions_root)
        
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

    async def _compute_state_root(self, transactions_root: str) -> str:
        """
        Compute a deterministic state root for block proposal.

        Combines:
          1. UTXO set hash from the database
          2. Exchange engine state root (pools, order books, oracles, perps)
          3. Transactions root of the proposed block
        """
        hasher = hashlib.sha256()

        # 1. UTXO state hash from database
        utxo_hash = '0' * 64
        try:
            if self.database is not None:
                utxo_hash = await self.database.get_unspent_outputs_hash()
        except Exception as e:
            logger.debug(f"Could not get UTXO hash for state root: {e}")

        hasher.update(utxo_hash.encode())

        # 2. Exchange engine state root
        exchange_root = '0' * 64
        try:
            from ..exchange.state_manager import ExchangeStateManager
            mgr = ExchangeStateManager.get_instance()
            if mgr is not None:
                exchange_root = mgr.compute_state_root()
        except Exception as e:
            logger.debug(f"Could not get exchange state root: {e}")

        hasher.update(exchange_root.encode())

        # 3. Transactions root
        hasher.update(transactions_root.encode())

        return hasher.hexdigest()
    
    async def _execute_contract_transactions(
        self,
        transactions: List[Any],
        parent_hash: str,
    ) -> None:
        """
        Execute contract transactions with full state synchronization.
        
        This MUST be called before creating a block to ensure:
        1. Balances are synced from native to EVM state
        2. gas_used is set on each contract transaction
        3. Contract state is computed correctly
        4. Block validation will pass
        
        Args:
            transactions: List of transactions to execute
            parent_hash: Parent block hash for state lookup
        """
        try:
            from qrdx.contracts import QRDXEVMExecutor
            from qrdx.contracts.state import ContractStateManager
            from qrdx.contracts.state_sync import StateSyncManager, ExecutionContext
            from eth_utils import to_canonical_address, decode_hex, encode_hex
            
            # Identify contract transactions
            contract_txs = []
            for tx in transactions:
                is_contract = (
                    hasattr(tx, 'is_contract_transaction') and tx.is_contract_transaction() or
                    hasattr(tx, 'data') and tx.data and len(tx.data) > 0
                )
                if is_contract:
                    contract_txs.append(tx)
            
            if not contract_txs:
                return  # No contracts to execute
            
            # Initialize contract state manager with database
            db = self.database if hasattr(self, 'database') else None
            if not db:
                logger.error("No database available for contract state - cannot execute contracts")
                # Remove all contract transactions if no database
                for tx in contract_txs:
                    transactions.remove(tx)
                return
            
            # Load state from parent block
            state_manager = ContractStateManager(db)
            
            # Load existing state from parent block if available
            if parent_hash and parent_hash != '0' * 64:
                try:
                    # Query parent block state from database
                    parent_state = await db.get_block_state(parent_hash)
                    if parent_state:
                        # Restore state manager from parent state
                        await state_manager.load_state(parent_state)
                        logger.debug(f"Loaded contract state from parent block {parent_hash[:16]}...")
                except Exception as e:
                    logger.warning(f"Could not load parent state, using fresh state: {e}")
            
            evm = QRDXEVMExecutor(state_manager)
            
            # Create state sync manager
            sync_manager = StateSyncManager(db, state_manager)
            await sync_manager.ensure_tables_exist()
            
            # Get current block info for determinism
            current_block = await db.get_last_block()
            block_height = current_block.block_height + 1  # Next block
            block_hash = parent_hash  # Use parent hash as reference
            block_timestamp = int(time.time())  # This will be overwritten by actual block timestamp
            
            logger.info(f"Pre-executing {len(contract_txs)} contract transactions for block proposal at height {block_height}")
            
            # Execute each contract transaction with state sync
            for tx in contract_txs:
                try:
                    # Get sender address
                    sender_addr = getattr(tx, 'sender', getattr(tx, 'address', None))
                    if isinstance(sender_addr, str):
                        sender = to_canonical_address(sender_addr)
                        sender_hex = sender_addr
                    else:
                        sender = sender_addr
                        sender_hex = encode_hex(sender)
                    
                    # Get recipient (None for contract creation)
                    to = None
                    if hasattr(tx, 'recipient') and tx.recipient:
                        to = to_canonical_address(tx.recipient)
                    
                    # Parse transaction data
                    data = b''
                    if hasattr(tx, 'data') and tx.data:
                        if isinstance(tx.data, bytes):
                            data = tx.data
                        elif isinstance(tx.data, str):
                            data = decode_hex(tx.data)
                    
                    # Get gas parameters
                    gas_limit = getattr(tx, 'gas_limit', getattr(tx, 'gas', 1_000_000))
                    gas_price = getattr(tx, 'gas_price', 1_000_000_000)
                    value = getattr(tx, 'value', 0)
                    
                    # Generate transaction hash for audit trail
                    tx_hash = getattr(tx, 'tx_hash', getattr(tx, 'hash', encode_hex(os.urandom(32))))
                    
                    # Create execution context for this transaction
                    context = ExecutionContext(
                        block_height=block_height,
                        block_hash=block_hash,
                        block_timestamp=block_timestamp,
                        db=db,
                        evm_state=state_manager,
                        sync_manager=sync_manager
                    )
                    
                    # Prepare execution (sync balance from native to EVM)
                    await context.prepare_execution(sender_hex)
                    
                    # Execute contract
                    try:
                        result = evm.execute(
                            sender=sender,
                            to=to,
                            value=value,
                            data=data,
                            gas=gas_limit,
                            gas_price=gas_price,
                        )
                        
                        # Finalize execution (commit or revert)
                        await context.finalize_execution(
                            sender=sender_hex,
                            tx_hash=tx_hash,
                            success=result.success,
                            gas_used=result.gas_used,
                            gas_price=gas_price,
                            value=value
                        )
                        
                        if not result.success:
                            logger.warning(f"Contract execution failed during proposal: {result.error}")
                            # Don't include failed contracts in the block
                            transactions.remove(tx)
                            continue
                        
                        # CRITICAL: Set gas_used on transaction
                        tx.gas_used = result.gas_used
                        
                        # Set contract address if deployment
                        if result.created_address and hasattr(tx, 'contract_address'):
                            tx.contract_address = encode_hex(result.created_address)
                        
                        logger.debug(f"Contract executed with state sync: gas_used={result.gas_used}")
                        
                    except Exception as e:
                        # Ensure rollback on exception
                        await context.finalize_execution(
                            sender=sender_hex,
                            tx_hash=tx_hash,
                            success=False,
                            gas_used=0,
                            gas_price=0,
                            value=0
                        )
                        raise
                    
                except Exception as e:
                    logger.error(f"Failed to execute contract transaction: {e}", exc_info=True)
                    # Remove failed transaction from block
                    transactions.remove(tx)
            
            # Create state checkpoint after all executions
            if contract_txs:
                combined_state_root = await sync_manager.create_state_checkpoint(
                    block_height=block_height,
                    block_hash=block_hash
                )
                logger.info(f"Created state checkpoint for block {block_height}: {combined_state_root[:16]}...")
            
            logger.info(f"Successfully pre-executed {len(contract_txs)} contract transactions with state sync")
            
        except ImportError as e:
            logger.warning(f"Contract execution not available: {e}")
            # Remove all contract transactions if EVM not available
            for tx in transactions[:]:
                if hasattr(tx, 'is_contract_transaction') and tx.is_contract_transaction():
                    transactions.remove(tx)
        except Exception as e:
            logger.error(f"Error in contract pre-execution: {e}", exc_info=True)
            # Remove contract transactions on error
            for tx in transactions[:]:
                if hasattr(tx, 'is_contract_transaction') and tx.is_contract_transaction():
                    transactions.remove(tx)
    
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
        
        # Enforce minimum stake requirement (Ethereum-grade security)
        current_stake = await self.stake_manager.get_effective_stake(self.wallet.address)
        min_required = self.config.staking.min_validator_stake
        if current_stake < min_required:
            logger.error(f"Insufficient stake for attestation: {current_stake} < {min_required} QRDX")
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
