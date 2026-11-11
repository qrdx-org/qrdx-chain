"""
QRDX Stake Manager

Manages stake deposits, withdrawals, and tracking for validators.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Dict, List, Optional

from ..database_sqlite import _now
from ..logger import get_logger
from .config import ValidatorConfig
from .types import InsufficientStakeError, ValidatorError

logger = get_logger(__name__)

# Stake records are stored in 10⁻⁸ QRDX.
_UNIT = Decimal("100000000")


class WithdrawalStatus(Enum):
    """Status of stake withdrawal request."""

    PENDING = "pending"  # In unbonding queue
    READY = "ready"  # Unbonding complete, ready to withdraw
    COMPLETED = "completed"  # Withdrawal executed
    CANCELLED = "cancelled"  # Withdrawal cancelled


@dataclass
class StakeDeposit:
    """
    Record of a stake deposit.

    Attributes:
        validator_address: Validator's PQ address
        amount: Amount deposited
        tx_hash: Transaction hash of deposit
        block_number: Block where deposit was included
        epoch: Epoch of deposit
        created_at: Timestamp
    """

    validator_address: str
    amount: Decimal
    tx_hash: str
    block_number: int
    epoch: int
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "validator_address": self.validator_address,
            "amount": str(self.amount),
            "tx_hash": self.tx_hash,
            "block_number": self.block_number,
            "epoch": self.epoch,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class StakeWithdrawal:
    """
    Record of a stake withdrawal request.

    Attributes:
        id: Unique withdrawal ID
        validator_address: Validator's PQ address
        amount: Amount requested for withdrawal
        request_epoch: Epoch when withdrawal was requested
        completion_epoch: Epoch when unbonding completes
        status: Current withdrawal status
        tx_hash: Transaction hash when completed
        created_at: Request timestamp
    """

    id: int
    validator_address: str
    amount: Decimal
    request_epoch: int
    completion_epoch: int
    status: WithdrawalStatus = WithdrawalStatus.PENDING
    tx_hash: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def is_ready(self) -> bool:
        """Check if withdrawal can be executed."""
        return self.status == WithdrawalStatus.READY

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "validator_address": self.validator_address,
            "amount": str(self.amount),
            "request_epoch": self.request_epoch,
            "completion_epoch": self.completion_epoch,
            "status": self.status.value,
            "tx_hash": self.tx_hash,
            "created_at": self.created_at.isoformat(),
        }


class StakeManager:
    """
    Manages stake deposits and withdrawals for validators.

    Responsibilities:
    - Process stake deposits
    - Handle withdrawal requests and unbonding
    - Track effective stake
    - Calculate validator rewards
    - Process delegation (future feature)
    """

    def __init__(self, config: Optional[ValidatorConfig] = None, database=None):
        """
        Initialize stake manager.

        Args:
            config: Validator configuration
            database: Database instance for persistence
        """
        self.config = config or ValidatorConfig()
        self.database = database
        self._lock = asyncio.Lock()

        # In-memory cache (backed by database)
        self._stakes: Dict[str, Decimal] = {}
        self._pending_withdrawals: Dict[str, List[StakeWithdrawal]] = {}
        self._deposits: List[StakeDeposit] = []
        self._withdrawal_counter = 0

    async def load_from_database(self):
        """
        Load all validator stakes, pending withdrawals, and deposit history
        from database into memory cache.

        Must be called during initialization to restore state after restart.
        """
        store = self._store()
        if store is None:
            logger.warning("No database available for stake loading")
            return

        try:
            async with self._lock:
                # -- 1. Load stakes -----------------------------------------
                for row in store["validator_stakes"].scan():
                    self._stakes[row.validator_address] = Decimal(str(row.stake)) / _UNIT

                logger.info(f"Loaded {len(self._stakes)} validator stakes from database")

                # -- 2. Load pending withdrawals (and the highest id given, so the counter
                # never collides) --------------------------------------------------------
                max_id = 0
                for row in store["stake_withdrawals"].scan():
                    max_id = max(max_id, int(row.id))
                    if row.status not in ("pending", "ready"):
                        continue
                    withdrawal = StakeWithdrawal(
                        id=int(row.id),
                        validator_address=row.validator_address,
                        amount=Decimal(str(row.amount)) / _UNIT,
                        request_epoch=row.request_epoch,
                        completion_epoch=row.completion_epoch,
                        status=WithdrawalStatus(row.status),
                    )
                    self._pending_withdrawals.setdefault(withdrawal.validator_address, []).append(
                        withdrawal
                    )
                self._withdrawal_counter = max_id

                pending_count = sum(len(ws) for ws in self._pending_withdrawals.values())
                logger.info(
                    f"Loaded {pending_count} pending withdrawals from database "
                    f"(counter={self._withdrawal_counter})"
                )

                # -- 3. Load deposit history --------------------------------
                for row in store["stake_deposits"].scan():
                    self._deposits.append(
                        StakeDeposit(
                            validator_address=row.validator_address,
                            amount=Decimal(str(row.amount)) / _UNIT,
                            tx_hash=row.tx_hash or "",
                            block_number=row.block_number or 0,
                            epoch=row.epoch or 0,
                        )
                    )

                logger.info(f"Loaded {len(self._deposits)} deposit records from database")

        except Exception as e:
            logger.error(f"Failed to load stakes from database: {e}")

    # =========================================================================
    # STAKE QUERIES
    # =========================================================================

    async def get_stake(self, validator_address: str) -> Decimal:
        """
        Get total stake for a validator.

        Args:
            validator_address: Validator's PQ address

        Returns:
            Total stake amount
        """
        async with self._lock:
            # Query database via unified SQLite backend
            row = await self._query_stake(self.database, validator_address)
            if row:
                return Decimal(str(row["stake"]))

            # Fallback to cache
            return self._stakes.get(validator_address, Decimal("0"))

    async def get_effective_stake(self, validator_address: str) -> Decimal:
        """
        Get effective stake (total stake minus pending withdrawals).

        Args:
            validator_address: Validator's PQ address

        Returns:
            Effective stake available for validation
        """
        total_stake = await self.get_stake(validator_address)
        pending_withdrawals = await self.get_pending_withdrawal_amount(validator_address)

        effective = total_stake - pending_withdrawals
        return max(Decimal("0"), effective)

    async def get_pending_withdrawal_amount(self, validator_address: str) -> Decimal:
        """
        Get total amount in pending withdrawals.

        Args:
            validator_address: Validator's PQ address

        Returns:
            Total pending withdrawal amount
        """
        withdrawals = self._pending_withdrawals.get(validator_address, [])
        return sum(
            (w.amount for w in withdrawals if w.status == WithdrawalStatus.PENDING), Decimal("0")
        )

    async def get_pending_withdrawals(self, validator_address: str) -> List[StakeWithdrawal]:
        """
        Get pending withdrawal requests for a validator.

        Args:
            validator_address: Validator's PQ address

        Returns:
            List of pending withdrawals
        """
        return [
            w
            for w in self._pending_withdrawals.get(validator_address, [])
            if w.status == WithdrawalStatus.PENDING
        ]

    async def get_total_staked(self) -> Decimal:
        """
        Get total stake across all validators.

        Returns:
            Total network stake
        """
        from .. import Database

        database = Database.instance
        if database:
            async with database.pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT COALESCE(SUM(stake), 0) as total FROM validators "
                    "WHERE status IN ('active', 'exiting')"
                )
                if row:
                    return Decimal(str(row["total"]))

        return sum(self._stakes.values(), Decimal("0"))

    # =========================================================================
    # STAKE OPERATIONS
    # =========================================================================

    async def deposit(
        self, validator_address: str, amount: Decimal, tx_hash: str, block_number: int, epoch: int
    ) -> StakeDeposit:
        """
        Process a stake deposit.

        Args:
            validator_address: Validator's PQ address
            amount: Amount to deposit
            tx_hash: Deposit transaction hash
            block_number: Block containing deposit
            epoch: Current epoch

        Returns:
            StakeDeposit record

        Raises:
            ValidatorError: If deposit fails
        """
        if amount <= 0:
            raise ValidatorError("Deposit amount must be positive")

        # SECURITY: Prevent unrealistic stake amounts (overflow protection)
        MAX_SAFE_STAKE = Decimal("92233720368")  # ~92B QRDX (max int64 / 1e8)
        if amount > MAX_SAFE_STAKE:
            raise ValidatorError(
                f"Deposit amount {amount} QRDX exceeds maximum safe value {MAX_SAFE_STAKE} QRDX"
            )

        async with self._lock:
            # Create deposit record
            deposit = StakeDeposit(
                validator_address=validator_address,
                amount=amount,
                tx_hash=tx_hash,
                block_number=block_number,
                epoch=epoch,
            )

            # Update stake
            current_stake = self._stakes.get(validator_address, Decimal("0"))
            new_stake = current_stake + amount

            # SECURITY: Additional overflow check on total stake
            if new_stake > MAX_SAFE_STAKE:
                raise ValidatorError(
                    f"Total stake {new_stake} QRDX would exceed maximum safe value {MAX_SAFE_STAKE} QRDX"
                )

            self._stakes[validator_address] = new_stake

            # Persist to database
            await self._save_deposit(deposit, new_stake)

            self._deposits.append(deposit)

            logger.info(
                f"Stake deposit: {validator_address} deposited {amount} QRDX "
                f"(total: {new_stake} QRDX)"
            )

            return deposit

    async def request_withdrawal(
        self, validator_address: str, amount: Decimal, current_epoch: int
    ) -> StakeWithdrawal:
        """
        Request stake withdrawal (starts unbonding).

        Args:
            validator_address: Validator's PQ address
            amount: Amount to withdraw
            current_epoch: Current epoch

        Returns:
            StakeWithdrawal record

        Raises:
            InsufficientStakeError: If withdrawal would leave insufficient stake
        """
        effective_stake = await self.get_effective_stake(validator_address)
        min_stake = self.config.staking.min_validator_stake

        # Check if withdrawal would leave sufficient stake
        remaining = effective_stake - amount
        if remaining < min_stake and remaining > 0:
            raise InsufficientStakeError(required=min_stake, actual=remaining)

        if amount > effective_stake:
            raise InsufficientStakeError(required=amount, actual=effective_stake)

        async with self._lock:
            self._withdrawal_counter += 1

            # Calculate completion epoch (after unbonding period)
            unbonding_epochs = self.config.staking.unbonding_epochs
            completion_epoch = current_epoch + unbonding_epochs

            withdrawal = StakeWithdrawal(
                id=self._withdrawal_counter,
                validator_address=validator_address,
                amount=amount,
                request_epoch=current_epoch,
                completion_epoch=completion_epoch,
                status=WithdrawalStatus.PENDING,
            )

            # Add to pending withdrawals
            if validator_address not in self._pending_withdrawals:
                self._pending_withdrawals[validator_address] = []
            self._pending_withdrawals[validator_address].append(withdrawal)

            # Persist to database
            await self._save_withdrawal(withdrawal)

            logger.info(
                f"Withdrawal requested: {validator_address} requested {amount} QRDX "
                f"(completion: epoch {completion_epoch})"
            )

            return withdrawal

    async def process_unbonding(self, current_epoch: int) -> List[StakeWithdrawal]:
        """
        Process unbonding queue - mark ready withdrawals.

        Args:
            current_epoch: Current epoch

        Returns:
            List of withdrawals that became ready
        """
        ready_withdrawals = []

        async with self._lock:
            for address, withdrawals in self._pending_withdrawals.items():
                for withdrawal in withdrawals:
                    if (
                        withdrawal.status == WithdrawalStatus.PENDING
                        and current_epoch >= withdrawal.completion_epoch
                    ):
                        withdrawal.status = WithdrawalStatus.READY
                        ready_withdrawals.append(withdrawal)

                        logger.info(
                            f"Withdrawal ready: {address} can withdraw " f"{withdrawal.amount} QRDX"
                        )

        return ready_withdrawals

    async def complete_withdrawal(self, withdrawal_id: int, tx_hash: str) -> bool:
        """
        Complete a ready withdrawal.

        Args:
            withdrawal_id: Withdrawal ID
            tx_hash: Transaction hash of withdrawal execution

        Returns:
            True if successful

        Raises:
            ValidatorError: If withdrawal cannot be completed
            InsufficientStakeError: If withdrawal would violate minimum stake
        """
        async with self._lock:
            for address, withdrawals in self._pending_withdrawals.items():
                for withdrawal in withdrawals:
                    if withdrawal.id == withdrawal_id:
                        if withdrawal.status != WithdrawalStatus.READY:
                            raise ValidatorError(f"Withdrawal {withdrawal_id} is not ready")

                        # SECURITY: Check if deducting would violate minimum stake
                        current_stake = self._stakes.get(address, Decimal("0"))
                        remaining_stake = current_stake - withdrawal.amount
                        min_stake = self.config.staking.min_validator_stake

                        # Allow complete exit (stake to 0) but not partial below minimum
                        if remaining_stake > 0 and remaining_stake < min_stake:
                            raise InsufficientStakeError(
                                required=min_stake,
                                actual=remaining_stake,
                                message=f"Withdrawal would leave {remaining_stake} QRDX, minimum is {min_stake} QRDX. "
                                f"Either withdraw all stake (exit validator) or keep at least minimum.",
                            )

                        # Deduct from stake
                        self._stakes[address] = remaining_stake

                        # Update withdrawal
                        withdrawal.status = WithdrawalStatus.COMPLETED
                        withdrawal.tx_hash = tx_hash

                        # Persist to database
                        await self._update_withdrawal(withdrawal)
                        await self._update_stake(address, self._stakes[address])

                        logger.info(
                            f"Withdrawal completed: {address} withdrew "
                            f"{withdrawal.amount} QRDX (remaining: {remaining_stake} QRDX, tx: {tx_hash})"
                        )

                        return True

            raise ValidatorError(f"Withdrawal {withdrawal_id} not found")

    async def cancel_withdrawal(self, withdrawal_id: int) -> bool:
        """
        Cancel a pending withdrawal.

        Args:
            withdrawal_id: Withdrawal ID

        Returns:
            True if successful
        """
        async with self._lock:
            for address, withdrawals in self._pending_withdrawals.items():
                for withdrawal in withdrawals:
                    if withdrawal.id == withdrawal_id:
                        if withdrawal.status != WithdrawalStatus.PENDING:
                            raise ValidatorError("Can only cancel pending withdrawals")

                        withdrawal.status = WithdrawalStatus.CANCELLED
                        await self._update_withdrawal(withdrawal)

                        logger.info(
                            f"Withdrawal cancelled: {address} cancelled "
                            f"{withdrawal.amount} QRDX withdrawal"
                        )

                        return True

            raise ValidatorError(f"Withdrawal {withdrawal_id} not found")

    # =========================================================================
    # SLASHING
    # =========================================================================

    async def slash(
        self,
        validator_address: str,
        percentage: Decimal,
        reason: str,
        evidence: Optional[str] = None,
    ) -> Decimal:
        """
        Slash validator stake.

        Args:
            validator_address: Validator's PQ address
            percentage: Percentage of stake to slash (0.0 - 1.0)
            reason: Slashing reason
            evidence: Evidence data (optional)

        Returns:
            Amount slashed
        """
        if percentage < 0 or percentage > 1:
            raise ValueError("Slash percentage must be between 0 and 1")

        current_stake = await self.get_stake(validator_address)
        slash_amount = current_stake * percentage

        async with self._lock:
            # Deduct slash amount
            new_stake = current_stake - slash_amount
            self._stakes[validator_address] = new_stake

            # Also cancel any pending withdrawals if slashing is severe
            if percentage >= Decimal("0.5"):
                await self._cancel_all_withdrawals(validator_address)

            # Persist to database
            await self._save_slashing(validator_address, slash_amount, reason, evidence)
            await self._update_stake(validator_address, new_stake)

            logger.warning(
                f"Validator slashed: {validator_address} lost {slash_amount} QRDX "
                f"({percentage * 100}%) for {reason}"
            )

            return slash_amount

    # =========================================================================
    # REWARDS
    # =========================================================================

    async def add_reward(
        self, validator_address: str, amount: Decimal, source: str = "block_reward"
    ) -> None:
        """
        Add reward to validator stake.

        Args:
            validator_address: Validator's PQ address
            amount: Reward amount
            source: Reward source (block_reward, attestation, etc.)
        """
        if amount <= 0:
            return

        async with self._lock:
            current_stake = self._stakes.get(validator_address, Decimal("0"))

            if self.config.staking.auto_restake_rewards:
                # Add to stake
                self._stakes[validator_address] = current_stake + amount
                await self._update_stake(validator_address, self._stakes[validator_address])
                logger.debug(f"Reward restaked: {validator_address} +{amount} QRDX ({source})")
            else:
                # Track reward separately (future: withdrawable rewards)
                logger.debug(f"Reward earned: {validator_address} +{amount} QRDX ({source})")

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def _store(self):
        """The node's store (qrdx/store.py), where the stake records live; None without one."""
        return getattr(self.database, "store", None) if self.database else None

    async def _commit(self) -> None:
        await self.database.connection.commit()

    async def _query_stake(self, database, validator_address: str):
        """Query stake from database."""
        store = self._store()
        if store is None:
            return None
        try:
            row = store["validator_stakes"].get(validator_address)
            if row:
                return {"stake": Decimal(str(row.stake)) / _UNIT}
            return None
        except Exception:
            return None

    async def _save_deposit(self, deposit: StakeDeposit, new_stake: Decimal):
        """Save deposit to database."""
        store = self._store()
        if store is None:
            logger.warning("No database for saving deposit")
            return

        try:
            # Stored in 10⁻⁸ QRDX
            stake_units = int(new_stake * _UNIT)
            amount_units = int(deposit.amount * _UNIT)
            now = _now()

            # Update or insert validator stake
            stakes = store["validator_stakes"]
            row = stakes.get(deposit.validator_address)
            if row is None:
                stakes.put(
                    validator_address=deposit.validator_address,
                    stake=stake_units,
                    effective_stake=stake_units,
                    status="PENDING",
                    activation_epoch=deposit.epoch,
                    created_at=now,
                    updated_at=now,
                )
            else:
                stakes.update(
                    (deposit.validator_address,),
                    stake=int(row.stake) + amount_units,
                    effective_stake=int(row.effective_stake) + amount_units,
                    updated_at=now,
                )

            # Record deposit
            store["stake_deposits"].put(
                id=store.next_id("stake_deposits"),
                validator_address=deposit.validator_address,
                amount=amount_units,
                tx_hash=deposit.tx_hash,
                block_number=deposit.block_number,
                epoch=deposit.epoch,
                created_at=now,
            )

            await self._commit()
            logger.info(f"Saved deposit for {deposit.validator_address}: {deposit.amount} QRDX")
        except Exception as e:
            logger.error(f"Failed to save deposit: {e}")

    async def _save_withdrawal(self, withdrawal: StakeWithdrawal):
        """Save withdrawal request to database, under the withdrawal's own id."""
        store = self._store()
        if store is None:
            logger.warning("No database for saving withdrawal")
            return

        try:
            store["stake_withdrawals"].put(
                id=withdrawal.id,
                validator_address=withdrawal.validator_address,
                amount=int(withdrawal.amount * _UNIT),
                request_epoch=withdrawal.request_epoch,
                completion_epoch=withdrawal.completion_epoch,
                status=withdrawal.status.value,
                created_at=_now(),
            )
            await self._commit()
            logger.info(
                f"Saved withdrawal request for {withdrawal.validator_address}: {withdrawal.amount} QRDX"
            )
        except Exception as e:
            logger.error(f"Failed to save withdrawal: {e}")

    async def _update_withdrawal(self, withdrawal: StakeWithdrawal):
        """Update withdrawal in database."""
        store = self._store()
        if store is None:
            logger.warning("No database for updating withdrawal")
            return

        try:
            store["stake_withdrawals"].update(
                (withdrawal.id,), status=withdrawal.status.value, completed_at=_now()
            )
            await self._commit()
        except Exception as e:
            logger.error(f"Failed to update withdrawal: {e}")

    async def _update_stake(self, validator_address: str, new_stake: Decimal):
        """Update validator stake in database."""
        store = self._store()
        if store is None:
            logger.warning("No database for updating stake")
            return

        try:
            units = int(new_stake * _UNIT)
            store["validator_stakes"].update(
                (validator_address,), stake=units, effective_stake=units, updated_at=_now()
            )
            await self._commit()
        except Exception as e:
            logger.error(f"Failed to update stake: {e}")

    async def _save_slashing(
        self, validator_address: str, amount: Decimal, reason: str, evidence: Optional[str] = None
    ):
        """Save slashing event to database: a completed withdrawal of the amount slashed
        (numbered from the withdrawals' own counter, so no request reuses its id)."""
        store = self._store()
        if store is None:
            logger.warning("No database for saving slashing")
            return

        try:
            self._withdrawal_counter += 1
            now = _now()
            store["stake_withdrawals"].put(
                id=self._withdrawal_counter,
                validator_address=validator_address,
                amount=int(amount * _UNIT),
                request_epoch=0,
                status="completed",
                created_at=now,
            )

            # Mark validator as slashed
            store["validator_stakes"].update((validator_address,), slashed=1, updated_at=now)

            await self._commit()
            logger.info(f"Saved slashing for {validator_address}: {amount} QRDX ({reason})")
        except Exception as e:
            logger.error(f"Failed to save slashing: {e}")

    async def _cancel_all_withdrawals(self, validator_address: str):
        """Cancel all pending withdrawals for a validator."""
        withdrawals = self._pending_withdrawals.get(validator_address, [])
        for withdrawal in withdrawals:
            if withdrawal.status == WithdrawalStatus.PENDING:
                withdrawal.status = WithdrawalStatus.CANCELLED
                await self._update_withdrawal(withdrawal)
