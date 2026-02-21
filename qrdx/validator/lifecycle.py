"""
QRDX Validator Lifecycle Manager

Manages the complete validator lifecycle:
- Deposit and activation queue
- Voluntary exits
- Forced exits (slashing)
- Withdrawal processing

Implements proper delays and churn limiting for network stability.
"""

import asyncio
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime
from enum import Enum, auto

from ..logger import get_logger
from ..constants import (
    MIN_VALIDATOR_STAKE,
    MAX_VALIDATORS,
    ACTIVATION_DELAY_EPOCHS,
    WITHDRAWAL_DELAY_EPOCHS,
    UNBONDING_PERIOD_EPOCHS,
)

logger = get_logger(__name__)


class LifecycleState(Enum):
    """Validator lifecycle states."""
    PENDING_DEPOSIT = auto()      # Deposit submitted, awaiting inclusion
    PENDING_ACTIVATION = auto()   # In activation queue
    ACTIVE = auto()               # Active and attesting
    PENDING_EXIT = auto()         # Exit requested, in exit queue
    EXITED = auto()              # Exited but stake locked
    WITHDRAWABLE = auto()         # Can withdraw stake
    WITHDRAWN = auto()           # Fully withdrawn


@dataclass
class DepositRequest:
    """A pending validator deposit."""
    validator_address: str
    public_key: str
    amount: Decimal
    withdrawal_address: str
    signature: str
    submitted_at: datetime
    included_slot: Optional[int] = None
    included_epoch: Optional[int] = None
    
    @property
    def is_included(self) -> bool:
        return self.included_slot is not None


@dataclass
class ExitRequest:
    """A voluntary exit request."""
    validator_address: str
    exit_epoch: int
    signature: str
    submitted_at: datetime
    processed: bool = False


@dataclass
class WithdrawalRequest:
    """A stake withdrawal request."""
    validator_address: str
    withdrawal_address: str
    amount: Decimal
    withdrawable_epoch: int
    requested_at: datetime
    processed: bool = False
    tx_hash: Optional[str] = None


@dataclass
class ValidatorLifecycle:
    """Tracks a validator's lifecycle state."""
    address: str
    public_key: str
    
    # State
    state: LifecycleState = LifecycleState.PENDING_DEPOSIT
    
    # Balances
    deposit_amount: Decimal = Decimal("0")
    effective_balance: Decimal = Decimal("0")
    withdrawable_balance: Decimal = Decimal("0")
    
    # Epochs
    deposit_epoch: Optional[int] = None
    activation_eligibility_epoch: Optional[int] = None
    activation_epoch: Optional[int] = None
    exit_epoch: Optional[int] = None
    withdrawable_epoch: Optional[int] = None
    
    # Queue positions
    activation_queue_position: Optional[int] = None
    exit_queue_position: Optional[int] = None
    
    # Timestamps
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def update_state(self, new_state: LifecycleState):
        """Update lifecycle state."""
        self.state = new_state
        self.updated_at = datetime.utcnow()


class ValidatorActivationQueue:
    """
    Manages the validator activation queue.
    
    Implements FIFO ordering with eligibility epoch sorting.
    """
    
    def __init__(self, churn_limit: int = 4):
        self.churn_limit = churn_limit
        
        # Queue: list of (eligibility_epoch, address)
        self._queue: List[Tuple[int, str]] = []
        
        # Validators pending activation
        self._pending: Dict[str, ValidatorLifecycle] = {}
    
    @property
    def length(self) -> int:
        return len(self._queue)
    
    def add_to_queue(
        self,
        validator: ValidatorLifecycle,
        eligibility_epoch: int,
    ):
        """Add validator to activation queue."""
        if validator.address in self._pending:
            logger.warning(f"Validator {validator.address[:16]} already in queue")
            return
        
        validator.activation_eligibility_epoch = eligibility_epoch
        validator.state = LifecycleState.PENDING_ACTIVATION
        
        # Insert maintaining sorted order
        entry = (eligibility_epoch, validator.address)
        
        # Binary insert
        left, right = 0, len(self._queue)
        while left < right:
            mid = (left + right) // 2
            if self._queue[mid] < entry:
                left = mid + 1
            else:
                right = mid
        
        self._queue.insert(left, entry)
        self._pending[validator.address] = validator
        validator.activation_queue_position = left
        
        logger.info(
            f"Validator {validator.address[:16]} added to activation queue "
            f"at position {left}, eligibility epoch {eligibility_epoch}"
        )
    
    def get_validators_to_activate(self, current_epoch: int) -> List[ValidatorLifecycle]:
        """Get validators ready to activate this epoch."""
        to_activate = []
        
        for eligibility_epoch, address in self._queue[:]:
            if eligibility_epoch > current_epoch:
                break
            
            if len(to_activate) >= self.churn_limit:
                break
            
            validator = self._pending.get(address)
            if validator:
                to_activate.append(validator)
        
        return to_activate
    
    def activate_validators(
        self,
        validators: List[ValidatorLifecycle],
        activation_epoch: int,
    ):
        """Mark validators as activated."""
        for validator in validators:
            validator.activation_epoch = activation_epoch
            validator.state = LifecycleState.ACTIVE
            
            # Remove from queue
            entry = (validator.activation_eligibility_epoch, validator.address)
            if entry in self._queue:
                self._queue.remove(entry)
            
            if validator.address in self._pending:
                del self._pending[validator.address]
            
            validator.activation_queue_position = None
            
            logger.info(
                f"Validator {validator.address[:16]} activated at epoch {activation_epoch}"
            )
    
    def get_estimated_wait_time(self, address: str, current_epoch: int) -> Optional[int]:
        """Estimate epochs until activation."""
        if address not in self._pending:
            return None
        
        position = None
        for i, (_, addr) in enumerate(self._queue):
            if addr == address:
                position = i
                break
        
        if position is None:
            return None
        
        # Epochs to process = position / churn_limit
        epochs_to_wait = (position + self.churn_limit - 1) // self.churn_limit
        
        return epochs_to_wait + ACTIVATION_DELAY_EPOCHS


class ValidatorExitQueue:
    """
    Manages the validator exit queue.
    
    Processes voluntary and forced exits with proper delays.
    """
    
    def __init__(self, churn_limit: int = 4):
        self.churn_limit = churn_limit
        
        # Queue: list of (exit_epoch, address)
        self._queue: List[Tuple[int, str]] = []
        
        # Validators pending exit
        self._pending: Dict[str, ValidatorLifecycle] = {}
    
    @property
    def length(self) -> int:
        return len(self._queue)
    
    def request_exit(
        self,
        validator: ValidatorLifecycle,
        exit_epoch: int,
    ):
        """Add validator to exit queue."""
        if validator.address in self._pending:
            logger.warning(f"Validator {validator.address[:16]} already exiting")
            return
        
        validator.exit_epoch = exit_epoch
        validator.state = LifecycleState.PENDING_EXIT
        
        entry = (exit_epoch, validator.address)
        
        # Binary insert
        left, right = 0, len(self._queue)
        while left < right:
            mid = (left + right) // 2
            if self._queue[mid] < entry:
                left = mid + 1
            else:
                right = mid
        
        self._queue.insert(left, entry)
        self._pending[validator.address] = validator
        validator.exit_queue_position = left
        
        logger.info(
            f"Validator {validator.address[:16]} added to exit queue, "
            f"exit epoch {exit_epoch}"
        )
    
    def get_validators_to_exit(self, current_epoch: int) -> List[ValidatorLifecycle]:
        """Get validators ready to exit this epoch."""
        to_exit = []
        
        for exit_epoch, address in self._queue[:]:
            if exit_epoch > current_epoch:
                break
            
            if len(to_exit) >= self.churn_limit:
                break
            
            validator = self._pending.get(address)
            if validator:
                to_exit.append(validator)
        
        return to_exit
    
    def process_exits(
        self,
        validators: List[ValidatorLifecycle],
        current_epoch: int,
    ):
        """Mark validators as exited."""
        for validator in validators:
            validator.state = LifecycleState.EXITED
            validator.withdrawable_epoch = current_epoch + WITHDRAWAL_DELAY_EPOCHS
            
            # Remove from queue
            entry = (validator.exit_epoch, validator.address)
            if entry in self._queue:
                self._queue.remove(entry)
            
            if validator.address in self._pending:
                del self._pending[validator.address]
            
            validator.exit_queue_position = None
            
            logger.info(
                f"Validator {validator.address[:16]} exited, "
                f"withdrawable at epoch {validator.withdrawable_epoch}"
            )


class LifecycleManager:
    """
    Comprehensive validator lifecycle manager.
    
    Coordinates deposits, activations, exits, and withdrawals.
    All state is persisted to an aiosqlite database so that restarts
    do not lose in-flight deposits, exits, or withdrawal requests.
    """
    
    # SQLite schema for lifecycle persistence
    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS lifecycle_validators (
        address TEXT PRIMARY KEY,
        public_key TEXT NOT NULL,
        state TEXT NOT NULL,
        deposit_amount TEXT NOT NULL DEFAULT '0',
        effective_balance TEXT NOT NULL DEFAULT '0',
        withdrawable_balance TEXT NOT NULL DEFAULT '0',
        deposit_epoch INTEGER,
        activation_eligibility_epoch INTEGER,
        activation_epoch INTEGER,
        exit_epoch INTEGER,
        withdrawable_epoch INTEGER,
        activation_queue_position INTEGER,
        exit_queue_position INTEGER,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS lifecycle_deposits (
        validator_address TEXT PRIMARY KEY,
        public_key TEXT NOT NULL,
        amount TEXT NOT NULL,
        withdrawal_address TEXT NOT NULL,
        signature TEXT NOT NULL,
        submitted_at TEXT NOT NULL,
        included_slot INTEGER,
        included_epoch INTEGER
    );
    CREATE TABLE IF NOT EXISTS lifecycle_exits (
        validator_address TEXT PRIMARY KEY,
        exit_epoch INTEGER NOT NULL,
        signature TEXT NOT NULL,
        submitted_at TEXT NOT NULL,
        processed INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS lifecycle_withdrawals (
        validator_address TEXT PRIMARY KEY,
        withdrawal_address TEXT NOT NULL,
        amount TEXT NOT NULL,
        withdrawable_epoch INTEGER NOT NULL,
        requested_at TEXT NOT NULL,
        processed INTEGER NOT NULL DEFAULT 0,
        tx_hash TEXT
    );
    """

    def __init__(
        self,
        min_stake: Decimal = MIN_VALIDATOR_STAKE,
        max_validators: int = MAX_VALIDATORS,
        churn_limit: int = 4,
        db_path: Optional[str] = None,
    ):
        self.min_stake = min_stake
        self.max_validators = max_validators
        self.churn_limit = churn_limit
        self._db_path = db_path
        self._db = None  # aiosqlite connection, set by open_db()
        
        # Queues
        self.activation_queue = ValidatorActivationQueue(churn_limit)
        self.exit_queue = ValidatorExitQueue(churn_limit)
        
        # All validators by state
        self._validators: Dict[str, ValidatorLifecycle] = {}
        
        # Pending operations
        self._pending_deposits: Dict[str, DepositRequest] = {}
        self._pending_exits: Dict[str, ExitRequest] = {}
        self._pending_withdrawals: Dict[str, WithdrawalRequest] = {}
        
        # Current counts
        self._active_count = 0
    
    # =========================================================================
    # DATABASE PERSISTENCE
    # =========================================================================

    async def open_db(self, db_path: Optional[str] = None):
        """
        Open the lifecycle SQLite database and create tables if needed.

        Args:
            db_path: Optional override for database path.
        """
        import aiosqlite

        path = db_path or self._db_path
        if not path:
            logger.warning("No db_path provided – lifecycle state is in-memory only")
            return

        self._db = await aiosqlite.connect(path)
        self._db.row_factory = aiosqlite.Row
        for stmt in self._SCHEMA.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                await self._db.execute(stmt)
        await self._db.commit()
        logger.info(f"Lifecycle DB opened: {path}")

    async def close_db(self):
        """Close the lifecycle database."""
        if self._db:
            await self._db.close()
            self._db = None

    async def load_from_db(self):
        """
        Restore full in-memory state from the lifecycle database.

        Must be called after ``open_db()`` and before processing any epochs.
        """
        if not self._db:
            logger.warning("load_from_db called with no database connection")
            return

        # -- validators -------------------------------------------------------
        cursor = await self._db.execute("SELECT * FROM lifecycle_validators")
        rows = await cursor.fetchall()
        for r in rows:
            lc = ValidatorLifecycle(
                address=r["address"],
                public_key=r["public_key"],
                state=LifecycleState[r["state"]],
                deposit_amount=Decimal(r["deposit_amount"]),
                effective_balance=Decimal(r["effective_balance"]),
                withdrawable_balance=Decimal(r["withdrawable_balance"]),
                deposit_epoch=r["deposit_epoch"],
                activation_eligibility_epoch=r["activation_eligibility_epoch"],
                activation_epoch=r["activation_epoch"],
                exit_epoch=r["exit_epoch"],
                withdrawable_epoch=r["withdrawable_epoch"],
                activation_queue_position=r["activation_queue_position"],
                exit_queue_position=r["exit_queue_position"],
                created_at=datetime.fromisoformat(r["created_at"]),
                updated_at=datetime.fromisoformat(r["updated_at"]),
            )
            self._validators[lc.address] = lc

            if lc.state == LifecycleState.ACTIVE:
                self._active_count += 1
            elif lc.state == LifecycleState.PENDING_ACTIVATION:
                self.activation_queue._pending[lc.address] = lc
                self.activation_queue._queue.append(
                    (lc.activation_eligibility_epoch, lc.address)
                )
            elif lc.state == LifecycleState.PENDING_EXIT:
                self.exit_queue._pending[lc.address] = lc
                self.exit_queue._queue.append((lc.exit_epoch, lc.address))

        # Sort queues after bulk insert
        self.activation_queue._queue.sort()
        self.exit_queue._queue.sort()

        # -- pending deposits -------------------------------------------------
        cursor = await self._db.execute("SELECT * FROM lifecycle_deposits")
        rows = await cursor.fetchall()
        for r in rows:
            dep = DepositRequest(
                validator_address=r["validator_address"],
                public_key=r["public_key"],
                amount=Decimal(r["amount"]),
                withdrawal_address=r["withdrawal_address"],
                signature=r["signature"],
                submitted_at=datetime.fromisoformat(r["submitted_at"]),
                included_slot=r["included_slot"],
                included_epoch=r["included_epoch"],
            )
            self._pending_deposits[dep.validator_address] = dep

        # -- pending exits ----------------------------------------------------
        cursor = await self._db.execute(
            "SELECT * FROM lifecycle_exits WHERE processed = 0"
        )
        rows = await cursor.fetchall()
        for r in rows:
            ex = ExitRequest(
                validator_address=r["validator_address"],
                exit_epoch=r["exit_epoch"],
                signature=r["signature"],
                submitted_at=datetime.fromisoformat(r["submitted_at"]),
                processed=bool(r["processed"]),
            )
            self._pending_exits[ex.validator_address] = ex

        # -- pending withdrawals ----------------------------------------------
        cursor = await self._db.execute(
            "SELECT * FROM lifecycle_withdrawals WHERE processed = 0"
        )
        rows = await cursor.fetchall()
        for r in rows:
            wr = WithdrawalRequest(
                validator_address=r["validator_address"],
                withdrawal_address=r["withdrawal_address"],
                amount=Decimal(r["amount"]),
                withdrawable_epoch=r["withdrawable_epoch"],
                requested_at=datetime.fromisoformat(r["requested_at"]),
                processed=bool(r["processed"]),
                tx_hash=r["tx_hash"],
            )
            self._pending_withdrawals[wr.validator_address] = wr

        logger.info(
            f"Lifecycle state restored: {len(self._validators)} validators, "
            f"{len(self._pending_deposits)} pending deposits, "
            f"{len(self._pending_exits)} pending exits, "
            f"{len(self._pending_withdrawals)} pending withdrawals"
        )

    async def _persist_validator(self, lc: ValidatorLifecycle):
        """Upsert a single validator lifecycle record."""
        if not self._db:
            return
        await self._db.execute("""
            INSERT INTO lifecycle_validators (
                address, public_key, state, deposit_amount, effective_balance,
                withdrawable_balance, deposit_epoch, activation_eligibility_epoch,
                activation_epoch, exit_epoch, withdrawable_epoch,
                activation_queue_position, exit_queue_position,
                created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(address) DO UPDATE SET
                state=excluded.state,
                effective_balance=excluded.effective_balance,
                withdrawable_balance=excluded.withdrawable_balance,
                activation_eligibility_epoch=excluded.activation_eligibility_epoch,
                activation_epoch=excluded.activation_epoch,
                exit_epoch=excluded.exit_epoch,
                withdrawable_epoch=excluded.withdrawable_epoch,
                activation_queue_position=excluded.activation_queue_position,
                exit_queue_position=excluded.exit_queue_position,
                updated_at=excluded.updated_at
        """, (
            lc.address, lc.public_key, lc.state.name,
            str(lc.deposit_amount), str(lc.effective_balance),
            str(lc.withdrawable_balance),
            lc.deposit_epoch, lc.activation_eligibility_epoch,
            lc.activation_epoch, lc.exit_epoch, lc.withdrawable_epoch,
            lc.activation_queue_position, lc.exit_queue_position,
            lc.created_at.isoformat(), lc.updated_at.isoformat(),
        ))
        await self._db.commit()

    async def _persist_deposit(self, dep: DepositRequest):
        """Upsert a pending deposit request."""
        if not self._db:
            return
        await self._db.execute("""
            INSERT INTO lifecycle_deposits (
                validator_address, public_key, amount, withdrawal_address,
                signature, submitted_at, included_slot, included_epoch
            ) VALUES (?,?,?,?,?,?,?,?)
            ON CONFLICT(validator_address) DO UPDATE SET
                included_slot=excluded.included_slot,
                included_epoch=excluded.included_epoch
        """, (
            dep.validator_address, dep.public_key, str(dep.amount),
            dep.withdrawal_address, dep.signature,
            dep.submitted_at.isoformat(),
            dep.included_slot, dep.included_epoch,
        ))
        await self._db.commit()

    async def _remove_deposit(self, validator_address: str):
        """Remove a deposit record after inclusion."""
        if not self._db:
            return
        await self._db.execute(
            "DELETE FROM lifecycle_deposits WHERE validator_address = ?",
            (validator_address,)
        )
        await self._db.commit()

    async def _persist_exit(self, ex: ExitRequest):
        """Upsert a pending exit request."""
        if not self._db:
            return
        await self._db.execute("""
            INSERT INTO lifecycle_exits (
                validator_address, exit_epoch, signature, submitted_at, processed
            ) VALUES (?,?,?,?,?)
            ON CONFLICT(validator_address) DO UPDATE SET
                processed=excluded.processed
        """, (
            ex.validator_address, ex.exit_epoch, ex.signature,
            ex.submitted_at.isoformat(), int(ex.processed),
        ))
        await self._db.commit()

    async def _persist_withdrawal(self, wr: WithdrawalRequest):
        """Upsert a pending withdrawal request."""
        if not self._db:
            return
        await self._db.execute("""
            INSERT INTO lifecycle_withdrawals (
                validator_address, withdrawal_address, amount,
                withdrawable_epoch, requested_at, processed, tx_hash
            ) VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(validator_address) DO UPDATE SET
                processed=excluded.processed,
                tx_hash=excluded.tx_hash
        """, (
            wr.validator_address, wr.withdrawal_address, str(wr.amount),
            wr.withdrawable_epoch, wr.requested_at.isoformat(),
            int(wr.processed), wr.tx_hash,
        ))
        await self._db.commit()
    
    @property
    def active_validator_count(self) -> int:
        return self._active_count
    
    @property
    def total_validator_count(self) -> int:
        return len(self._validators)
    
    def update_churn_limit(self, active_count: int):
        """Update churn limit based on validator set size."""
        self.churn_limit = max(4, active_count // 65536)
        self.activation_queue.churn_limit = self.churn_limit
        self.exit_queue.churn_limit = self.churn_limit
    
    async def submit_deposit(
        self,
        validator_address: str,
        public_key: str,
        amount: Decimal,
        withdrawal_address: str,
        signature: str,
    ) -> Tuple[bool, str]:
        """
        Submit a new validator deposit.
        
        Returns:
            Tuple of (success, message)
        """
        # Validate amount
        if amount < self.min_stake:
            return False, f"Minimum stake is {self.min_stake} QRDX"
        
        # Check max validators
        if self.total_validator_count >= self.max_validators:
            return False, f"Maximum validators ({self.max_validators}) reached"
        
        # Check for existing
        if validator_address in self._validators:
            return False, "Validator already registered"
        
        if validator_address in self._pending_deposits:
            return False, "Deposit already pending"
        
        # Create deposit request
        deposit = DepositRequest(
            validator_address=validator_address,
            public_key=public_key,
            amount=amount,
            withdrawal_address=withdrawal_address,
            signature=signature,
            submitted_at=datetime.utcnow(),
        )
        
        self._pending_deposits[validator_address] = deposit
        await self._persist_deposit(deposit)
        
        logger.info(f"Deposit submitted for {validator_address[:16]}: {amount} QRDX")
        
        return True, "Deposit submitted successfully"
    
    async def process_deposit_inclusion(
        self,
        validator_address: str,
        inclusion_slot: int,
        current_epoch: int,
    ) -> bool:
        """Process a deposit after it's included in a block."""
        deposit = self._pending_deposits.get(validator_address)
        if not deposit:
            logger.error(f"No pending deposit for {validator_address[:16]}")
            return False
        
        # Mark as included
        deposit.included_slot = inclusion_slot
        deposit.included_epoch = current_epoch
        
        # Create validator lifecycle
        lifecycle = ValidatorLifecycle(
            address=validator_address,
            public_key=deposit.public_key,
            deposit_amount=deposit.amount,
            effective_balance=deposit.amount,
            deposit_epoch=current_epoch,
        )
        
        # Add to activation queue
        eligibility_epoch = current_epoch + 1  # Eligible next epoch
        self.activation_queue.add_to_queue(lifecycle, eligibility_epoch)
        
        # Store
        self._validators[validator_address] = lifecycle
        del self._pending_deposits[validator_address]
        await self._persist_validator(lifecycle)
        await self._remove_deposit(validator_address)
        
        logger.info(
            f"Deposit included for {validator_address[:16]} at slot {inclusion_slot}"
        )
        
        return True
    
    async def request_voluntary_exit(
        self,
        validator_address: str,
        signature: str,
        current_epoch: int,
    ) -> Tuple[bool, str]:
        """
        Submit a voluntary exit request.
        
        Returns:
            Tuple of (success, message)
        """
        lifecycle = self._validators.get(validator_address)
        if not lifecycle:
            return False, "Validator not found"
        
        if lifecycle.state != LifecycleState.ACTIVE:
            return False, f"Validator not active (state: {lifecycle.state.name})"
        
        if validator_address in self._pending_exits:
            return False, "Exit already pending"
        
        # Calculate exit epoch
        exit_epoch = current_epoch + 1  # Can exit next epoch
        
        # Create exit request
        exit_request = ExitRequest(
            validator_address=validator_address,
            exit_epoch=exit_epoch,
            signature=signature,
            submitted_at=datetime.utcnow(),
        )
        
        self._pending_exits[validator_address] = exit_request
        await self._persist_exit(exit_request)
        
        # Add to exit queue
        self.exit_queue.request_exit(lifecycle, exit_epoch)
        
        self._active_count -= 1
        await self._persist_validator(lifecycle)
        
        logger.info(f"Voluntary exit requested for {validator_address[:16]}")
        
        return True, f"Exit scheduled for epoch {exit_epoch}"
    
    async def force_exit(
        self,
        validator_address: str,
        reason: str,
        current_epoch: int,
    ):
        """Force a validator to exit (e.g., due to slashing)."""
        lifecycle = self._validators.get(validator_address)
        if not lifecycle:
            logger.error(f"Cannot force exit: {validator_address[:16]} not found")
            return
        
        if lifecycle.state not in [LifecycleState.ACTIVE, LifecycleState.PENDING_EXIT]:
            logger.warning(f"Validator {validator_address[:16]} already exited/exiting")
            return
        
        # Immediate exit
        was_active = lifecycle.state == LifecycleState.ACTIVE
        lifecycle.exit_epoch = current_epoch
        lifecycle.state = LifecycleState.EXITED
        lifecycle.withdrawable_epoch = current_epoch + WITHDRAWAL_DELAY_EPOCHS
        
        if was_active:
            self._active_count -= 1
        
        await self._persist_validator(lifecycle)
        logger.warning(f"Validator {validator_address[:16]} force-exited: {reason}")
    
    async def process_epoch(self, current_epoch: int):
        """Process lifecycle changes at epoch boundary."""
        # Update churn limit
        self.update_churn_limit(self._active_count)
        
        # Process activations
        to_activate = self.activation_queue.get_validators_to_activate(current_epoch)
        activation_epoch = current_epoch + ACTIVATION_DELAY_EPOCHS
        
        if to_activate:
            self.activation_queue.activate_validators(to_activate, activation_epoch)
            self._active_count += len(to_activate)
            for v in to_activate:
                await self._persist_validator(v)
        
        # Process exits
        to_exit = self.exit_queue.get_validators_to_exit(current_epoch)
        
        if to_exit:
            self.exit_queue.process_exits(to_exit, current_epoch)
            for v in to_exit:
                await self._persist_validator(v)
        
        # Check for withdrawable validators
        for lifecycle in self._validators.values():
            if (lifecycle.state == LifecycleState.EXITED and
                lifecycle.withdrawable_epoch is not None and
                lifecycle.withdrawable_epoch <= current_epoch):
                lifecycle.state = LifecycleState.WITHDRAWABLE
                lifecycle.withdrawable_balance = lifecycle.effective_balance
                await self._persist_validator(lifecycle)
                logger.info(
                    f"Validator {lifecycle.address[:16]} now withdrawable"
                )
        
        logger.debug(
            f"Epoch {current_epoch}: activated={len(to_activate)}, "
            f"exited={len(to_exit)}, active={self._active_count}"
        )
    
    async def process_withdrawal(
        self,
        validator_address: str,
        current_epoch: int,
    ) -> Tuple[bool, Optional[Decimal]]:
        """
        Process a withdrawal for an exited validator.
        
        Returns:
            Tuple of (success, withdrawn_amount)
        """
        lifecycle = self._validators.get(validator_address)
        if not lifecycle:
            return False, None
        
        if lifecycle.state != LifecycleState.WITHDRAWABLE:
            return False, None
        
        amount = lifecycle.withdrawable_balance
        lifecycle.withdrawable_balance = Decimal("0")
        lifecycle.effective_balance = Decimal("0")
        lifecycle.state = LifecycleState.WITHDRAWN
        await self._persist_validator(lifecycle)
        
        logger.info(
            f"Withdrawal processed for {validator_address[:16]}: {amount} QRDX"
        )
        
        return True, amount
    
    def get_validator_status(self, address: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive validator status."""
        lifecycle = self._validators.get(address)
        if not lifecycle:
            # Check pending
            deposit = self._pending_deposits.get(address)
            if deposit:
                return {
                    'address': address,
                    'state': 'PENDING_DEPOSIT',
                    'deposit_amount': str(deposit.amount),
                    'submitted_at': deposit.submitted_at.isoformat(),
                }
            return None
        
        return {
            'address': lifecycle.address,
            'state': lifecycle.state.name,
            'deposit_amount': str(lifecycle.deposit_amount),
            'effective_balance': str(lifecycle.effective_balance),
            'withdrawable_balance': str(lifecycle.withdrawable_balance),
            'deposit_epoch': lifecycle.deposit_epoch,
            'activation_eligibility_epoch': lifecycle.activation_eligibility_epoch,
            'activation_epoch': lifecycle.activation_epoch,
            'exit_epoch': lifecycle.exit_epoch,
            'withdrawable_epoch': lifecycle.withdrawable_epoch,
            'activation_queue_position': lifecycle.activation_queue_position,
            'exit_queue_position': lifecycle.exit_queue_position,
            'created_at': lifecycle.created_at.isoformat(),
            'updated_at': lifecycle.updated_at.isoformat(),
        }
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """Get activation and exit queue statistics."""
        return {
            'activation_queue_length': self.activation_queue.length,
            'exit_queue_length': self.exit_queue.length,
            'churn_limit': self.churn_limit,
            'active_validators': self._active_count,
            'total_validators': self.total_validator_count,
            'pending_deposits': len(self._pending_deposits),
            'pending_exits': len(self._pending_exits),
            'pending_withdrawals': len(self._pending_withdrawals),
        }
