"""
State Synchronization Manager

Bridges QRDX native state (UTXO) with EVM contract state (accounts).
Ensures all nodes see consistent state by syncing at deterministic points.

This is a CONSENSUS-CRITICAL component. All operations are:
- Deterministic (same input → same output on all nodes)
- Atomic (all or nothing)
- Verifiable (provable by cryptographic means)
"""

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, Optional

from eth_utils import keccak

from ..crypto.account_id import to_account_id
from ..database_sqlite import DatabaseSQLite as Database
from ..logger import get_logger
from .state import ContractStateManager

logger = get_logger(__name__)


def _root_bytes(root: Any) -> bytes:
    """A state root as bytes, whether a component returned it raw or hex-encoded."""
    return bytes(root) if isinstance(root, (bytes, bytearray)) else bytes.fromhex(str(root))


# Conversion constants
WEI_PER_QRDX = 10**18  # 1 QRDX = 10^18 wei (Ethereum standard)


class StateSyncManager:
    """
    Manages synchronization between QRDX native state and EVM state.

    This is a CONSENSUS-CRITICAL component. All operations must be:
    - Deterministic (same input → same output on all nodes)
    - Atomic (all or nothing)
    - Verifiable (provable by cryptographic means)
    """

    def __init__(self, db: Database, evm_state: ContractStateManager):
        """
        Initialize state sync manager.

        Args:
            db: Native chain database (SQLite)
            evm_state: EVM state manager
        """
        self.db = db
        self.evm_state = evm_state

    async def ensure_tables_exist(self) -> None:
        """
        Ensure sync registry tables exist in database.
        Creates tables if they don't exist (idempotent).
        """
        conn = self.db.connection

        # (The sync registry and the balance-change log are the store's: qrdx/store.py.)

        # Create state checkpoints table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS state_checkpoints (
                checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_height INTEGER NOT NULL UNIQUE,
                block_hash TEXT NOT NULL,
                native_state_root TEXT NOT NULL,
                evm_state_root TEXT NOT NULL,
                combined_state_root TEXT NOT NULL,
                total_synced_addresses INTEGER NOT NULL,
                total_native_balance TEXT NOT NULL,
                total_evm_balance TEXT NOT NULL,
                checkpointed_at TEXT NOT NULL
            )
        """)

        # Create indexes for performance
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_checkpoints_block
            ON state_checkpoints(block_height)
        """)

        await conn.commit()
        logger.info("State sync registry tables verified/created")

    async def sync_address_to_evm(
        self,
        address: str,
        block_height: int,
        block_hash: str,
        tx_hash: Optional[str] = None,
        force: bool = False,
    ) -> bool:
        """
        Synchronize an address's balance from native state to EVM state.

        This is called before executing any contract transaction to ensure
        the sender has their balance available in EVM state.

        All nodes must execute this identically (deterministic).

        Args:
            address: Address to sync (will be checksummed)
            block_height: Current block height (for determinism)
            block_hash: Current block hash (for verification)
            tx_hash: Transaction hash that triggered sync (optional)
            force: If True, sync even if already synced recently

        Returns:
            True if sync performed, False if skipped (already synced)
        """
        address = to_account_id(address)

        # Check if already synced at this block height
        if not force:
            already_synced = await self._is_already_synced(address, block_height)
            if already_synced:
                logger.debug(f"Address {address} already synced at block {block_height}")
                return False

        # Get native balance (source of truth)
        # This is deterministic - all nodes will get same result
        native_balance_qrdx = await self.db.get_address_balance(address)

        # Convert to wei (EVM units)
        # 1 QRDX = 10^18 wei (Ethereum standard)
        # Use int() to ensure no floating point errors
        native_balance_wei = int(native_balance_qrdx * Decimal(WEI_PER_QRDX))

        # Get current EVM balance for logging
        current_evm_balance = await self.evm_state.get_balance(address)

        # Initialize or update EVM account
        account = await self.evm_state.get_account(address)
        account.balance = native_balance_wei
        await self.evm_state.set_account(account)

        # Record sync in registry (for verification and audit)
        await self._record_sync(
            address=address,
            block_height=block_height,
            block_hash=block_hash,
            native_balance=native_balance_qrdx,
            evm_balance=native_balance_wei,
            tx_hash=tx_hash,
        )

        logger.info(
            f"Synced address {address}: "
            f"{native_balance_qrdx} QRDX → {native_balance_wei} wei "
            f"at block {block_height} "
            f"(previous EVM balance: {current_evm_balance} wei)"
        )

        return True

    async def _is_already_synced(self, address: str, block_height: int) -> bool:
        """
        Check if address was already synced at or after given block.
        """
        row = self.db.store["evm_balance_sync_registry"].get(address)
        return row is not None and int(row.last_sync_block_height) >= int(block_height)

    async def _record_sync(
        self,
        address: str,
        block_height: int,
        block_hash: str,
        native_balance: Decimal,
        evm_balance: int,
        tx_hash: Optional[str] = None,
    ) -> None:
        """Record sync in registry."""
        now = datetime.now(timezone.utc).isoformat()
        self.db.store["evm_balance_sync_registry"].put(
            address,
            block_height,
            block_hash,
            now,
            str(native_balance),
            str(evm_balance),
            tx_hash,
        )
        await self.db.connection.commit()

    async def record_balance_change(
        self,
        address: str,
        block_height: int,
        block_hash: str,
        tx_hash: str,
        balance_before: int,
        balance_after: int,
        reason: str,
    ) -> None:
        """
        Record a balance change from contract execution.
        Provides an audit trail of all balance changes.
        """
        delta = balance_after - balance_before
        now = datetime.now(timezone.utc).isoformat()
        changes = self.db.store["evm_balance_changes"]
        newest = changes.scan(reverse=True, limit=1)
        change_id = int(newest[0].change_id) + 1 if newest else 1
        changes.put(
            change_id,
            address,
            block_height,
            block_hash,
            tx_hash,
            str(balance_before),
            str(balance_after),
            str(delta),
            reason,
            now,
        )
        await self.db.connection.commit()

        logger.debug(
            f"Recorded balance change for {address}: "
            f"{balance_before} → {balance_after} wei (delta: {delta}) "
            f"reason: {reason}"
        )

    async def create_state_checkpoint(self, block_height: int, block_hash: str) -> str:
        """
        Create a state checkpoint at block boundary.

        Computes combined state root from both native and EVM state.
        All nodes must compute identical root (consensus-critical).

        Args:
            block_height: Block height to checkpoint
            block_hash: Block hash

        Returns:
            Combined state root (hex string)
        """
        # Get native state root (from UTXO set)
        native_root = await self._compute_native_state_root(block_height)

        # Get EVM state root (from account trie)
        evm_root = await self.evm_state.get_state_root()

        # Combine roots deterministically
        # keccak256(native_root + evm_root)
        combined_root = keccak(_root_bytes(native_root) + _root_bytes(evm_root)).hex()

        # Get statistics
        stats = await self._get_sync_statistics()

        conn = self.db.connection
        now = datetime.now(timezone.utc).isoformat()

        await conn.execute(
            """
            INSERT INTO state_checkpoints (
                block_height, block_hash, native_state_root,
                evm_state_root, combined_state_root,
                total_synced_addresses, total_native_balance,
                total_evm_balance, checkpointed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (block_height) DO UPDATE SET
                block_hash = excluded.block_hash,
                native_state_root = excluded.native_state_root,
                evm_state_root = excluded.evm_state_root,
                combined_state_root = excluded.combined_state_root,
                total_synced_addresses = excluded.total_synced_addresses,
                total_native_balance = excluded.total_native_balance,
                total_evm_balance = excluded.total_evm_balance,
                checkpointed_at = excluded.checkpointed_at
            """,
            (
                block_height,
                block_hash,
                native_root,
                evm_root,
                combined_root,
                stats["synced_count"],
                str(stats["native_total"]),
                str(stats["evm_total"]),
                now,
            ),
        )
        await conn.commit()

        logger.info(
            f"State checkpoint at block {block_height}: "
            f"combined_root={combined_root[:16]}... "
            f"(native: {_root_bytes(native_root).hex()[:16]}..., "
            f"evm: {_root_bytes(evm_root).hex()[:16]}...)"
        )

        return combined_root

    async def _compute_native_state_root(self, block_height: int) -> str:
        """
        Compute Merkle root of native UTXO state.

        This is deterministic — all nodes compute same result.
        """
        conn = self.db.connection
        utxos = []
        for uo in self.db.store["unspent_outputs"].scan():  # (by tx_hash, output_index)
            cursor = await conn.execute(
                "SELECT b.block_height FROM transactions t JOIN blocks b "
                "ON t.block_hash = b.block_hash WHERE t.tx_hash = ?",
                (uo.tx_hash,),
            )
            row = await cursor.fetchone()
            if row is not None and int(row[0]) <= block_height:
                utxos.append(uo)

        if not utxos:
            return "0" * 64

        # Build Merkle tree from UTXOs
        leaves = []
        for uo in utxos:
            leaf_data = (
                bytes.fromhex(uo.tx_hash)
                + int(uo.output_index).to_bytes(4, "big")
                + (uo.address or "").encode("utf-8")
            )
            leaves.append(keccak(leaf_data))

        # Build tree bottom-up
        current_level = leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    combined = keccak(current_level[i] + current_level[i + 1])
                else:
                    combined = current_level[i]
                next_level.append(combined)
            current_level = next_level

        return current_level[0].hex()

    async def _get_sync_statistics(self) -> Dict[str, Any]:
        """Get synchronization statistics."""
        rows = self.db.store["evm_balance_sync_registry"].scan()
        native_total = Decimal("0")
        evm_total = 0
        for r in rows:
            try:
                native_total += Decimal(str(r.native_balance_at_sync or 0))
                evm_total += int(r.evm_balance_at_sync or 0)
            except Exception:
                continue
        return {"synced_count": len(rows), "native_total": native_total, "evm_total": evm_total}


class ExecutionContext:
    """
    Execution context for contract transactions.

    Combines native state, EVM state, and sync manager to provide
    unified execution environment with proper state synchronization.

    Ensures atomic execution — either everything succeeds or everything
    is rolled back.
    """

    def __init__(
        self,
        block_height: int,
        block_hash: str,
        block_timestamp: int,
        db: Database,
        evm_state: ContractStateManager,
        sync_manager: StateSyncManager,
    ):
        self.block_height = block_height
        self.block_hash = block_hash
        self.block_timestamp = block_timestamp
        self.db = db
        self.evm_state = evm_state
        self.sync_manager = sync_manager

        self._evm_snapshot_id: Optional[int] = None
        self._sender_balance_before_sync: Optional[int] = None

    async def prepare_execution(self, sender: str) -> None:
        """
        Prepare execution environment for sender.

        Deterministic — all nodes execute identically:
        1. Sync sender's balance from native to EVM
        2. Create state snapshot for potential rollback
        """
        sender = to_account_id(sender)

        self._sender_balance_before_sync = await self.evm_state.get_balance(sender)

        await self.sync_manager.sync_address_to_evm(
            address=sender, block_height=self.block_height, block_hash=self.block_hash
        )

        self._evm_snapshot_id = await self.evm_state.snapshot()

        logger.debug(
            f"Prepared execution for {sender} at block {self.block_height}: "
            f"EVM balance before sync: {self._sender_balance_before_sync} wei, "
            f"after sync: {await self.evm_state.get_balance(sender)} wei"
        )

    async def finalize_execution(
        self,
        sender: str,
        tx_hash: str,
        success: bool,
        gas_used: int,
        gas_price: int,
        value: int,
        defer_commit: bool = False,
    ) -> None:
        """
        Finalize execution and update state.

        If successful: commits EVM state and records changes
        If failed: reverts EVM state to pre-execution snapshot

        ``defer_commit`` (E-D3b prerequisite): when True, a successful tx's state
        changes are kept in the EVM cache and NOT flushed to the DB, so a caller
        can execute a whole block's EVM section and then atomically commit once
        (root matches) or discard (reject-on-mismatch) via a block-start
        snapshot. Default False preserves the per-tx commit behavior of the live
        RPC path exactly.
        """
        sender = to_account_id(sender)

        if success:
            if self._evm_snapshot_id is not None and not defer_commit:
                await self.evm_state.commit(self.block_height)

            balance_after = await self.evm_state.get_balance(sender)
            gas_cost = gas_used * gas_price
            balance_before = balance_after + gas_cost + value

            await self.sync_manager.record_balance_change(
                address=sender,
                block_height=self.block_height,
                block_hash=self.block_hash,
                tx_hash=tx_hash,
                balance_before=balance_before,
                balance_after=balance_after,
                reason="gas_payment_and_execution",
            )

            logger.info(
                f"Finalized successful execution: "
                f"tx={tx_hash[:16]}... gas_used={gas_used} "
                f"sender_balance: {balance_before} → {balance_after} wei"
            )
        else:
            if self._evm_snapshot_id is not None:
                await self.evm_state.revert(self._evm_snapshot_id)

            logger.info(
                f"Reverted failed execution: tx={tx_hash[:16]}... "
                f"sender balance unchanged (rollback successful)"
            )

        self._evm_snapshot_id = None


def convert_qrdx_to_wei(qrdx_amount: Decimal) -> int:
    """
    Convert QRDX to wei (smallest EVM unit).
    1 QRDX = 10^18 wei (Ethereum standard)
    """
    return int(qrdx_amount * Decimal(WEI_PER_QRDX))


def convert_wei_to_qrdx(wei_amount: int) -> Decimal:
    """Convert wei to QRDX."""
    return Decimal(wei_amount) / Decimal(WEI_PER_QRDX)
