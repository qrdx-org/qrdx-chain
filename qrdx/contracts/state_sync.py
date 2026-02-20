"""
State Synchronization Manager

Bridges QRDX native state (UTXO) with EVM contract state (accounts).
Ensures all nodes see consistent state by syncing at deterministic points.

This is a CONSENSUS-CRITICAL component. All operations are:
- Deterministic (same input → same output on all nodes)
- Atomic (all or nothing)
- Verifiable (provable by cryptographic means)
"""

from typing import Optional, Dict, Tuple, Any
from decimal import Decimal
from datetime import datetime, timezone
from eth_utils import to_checksum_address, keccak
import asyncio
import time

from ..logger import get_logger
from ..database_sqlite import DatabaseSQLite as Database
from .state import ContractStateManager, Account

logger = get_logger(__name__)

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
    
    def __init__(
        self,
        db: Database,
        evm_state: ContractStateManager
    ):
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

        # Create sync registry table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS evm_balance_sync_registry (
                address TEXT PRIMARY KEY,
                last_sync_block_height INTEGER NOT NULL,
                last_sync_block_hash TEXT NOT NULL,
                last_sync_timestamp TEXT NOT NULL,
                native_balance_at_sync TEXT NOT NULL,
                evm_balance_at_sync TEXT NOT NULL,
                sync_tx_hash TEXT
            )
        """)

        # Create balance changes table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS evm_balance_changes (
                change_id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT NOT NULL,
                block_height INTEGER NOT NULL,
                block_hash TEXT NOT NULL,
                tx_hash TEXT NOT NULL,
                balance_before TEXT NOT NULL,
                balance_after TEXT NOT NULL,
                delta TEXT NOT NULL,
                change_reason TEXT NOT NULL,
                changed_at TEXT NOT NULL
            )
        """)

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
            CREATE INDEX IF NOT EXISTS idx_sync_block_height
            ON evm_balance_sync_registry(last_sync_block_height)
        """)
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_balance_changes_address
            ON evm_balance_changes(address)
        """)
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_balance_changes_block
            ON evm_balance_changes(block_height)
        """)
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_balance_changes_tx
            ON evm_balance_changes(tx_hash)
        """)
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
        force: bool = False
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
        address = to_checksum_address(address)
        
        # Check if already synced at this block height
        if not force:
            already_synced = await self._is_already_synced(
                address,
                block_height
            )
            if already_synced:
                logger.debug(
                    f"Address {address} already synced at block {block_height}"
                )
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
            tx_hash=tx_hash
        )
        
        logger.info(
            f"Synced address {address}: "
            f"{native_balance_qrdx} QRDX → {native_balance_wei} wei "
            f"at block {block_height} "
            f"(previous EVM balance: {current_evm_balance} wei)"
        )
        
        return True
    
    async def _is_already_synced(
        self,
        address: str,
        block_height: int
    ) -> bool:
        """
        Check if address was already synced at or after given block.
        """
        conn = self.db.connection
        cursor = await conn.execute(
            """
            SELECT last_sync_block_height
            FROM evm_balance_sync_registry
            WHERE address = ? AND last_sync_block_height >= ?
            """,
            (address, block_height)
        )
        row = await cursor.fetchone()
        return row is not None
    
    async def _record_sync(
        self,
        address: str,
        block_height: int,
        block_hash: str,
        native_balance: Decimal,
        evm_balance: int,
        tx_hash: Optional[str] = None
    ) -> None:
        """Record sync in registry."""
        conn = self.db.connection
        now = datetime.now(timezone.utc).isoformat()

        await conn.execute(
            """
            INSERT INTO evm_balance_sync_registry (
                address, last_sync_block_height, last_sync_block_hash,
                last_sync_timestamp, native_balance_at_sync,
                evm_balance_at_sync, sync_tx_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (address) DO UPDATE SET
                last_sync_block_height = excluded.last_sync_block_height,
                last_sync_block_hash = excluded.last_sync_block_hash,
                last_sync_timestamp = excluded.last_sync_timestamp,
                native_balance_at_sync = excluded.native_balance_at_sync,
                evm_balance_at_sync = excluded.evm_balance_at_sync,
                sync_tx_hash = excluded.sync_tx_hash
            """,
            (address, block_height, block_hash, now,
             str(native_balance), str(evm_balance), tx_hash)
        )
        await conn.commit()
    
    async def record_balance_change(
        self,
        address: str,
        block_height: int,
        block_hash: str,
        tx_hash: str,
        balance_before: int,
        balance_after: int,
        reason: str
    ) -> None:
        """
        Record a balance change from contract execution.
        Provides an audit trail of all balance changes.
        """
        delta = balance_after - balance_before
        conn = self.db.connection
        now = datetime.now(timezone.utc).isoformat()

        await conn.execute(
            """
            INSERT INTO evm_balance_changes (
                address, block_height, block_hash, tx_hash,
                balance_before, balance_after, delta,
                change_reason, changed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (address, block_height, block_hash, tx_hash,
             str(balance_before), str(balance_after), str(delta), reason, now)
        )
        await conn.commit()

        logger.debug(
            f"Recorded balance change for {address}: "
            f"{balance_before} → {balance_after} wei (delta: {delta}) "
            f"reason: {reason}"
        )
    
    async def create_state_checkpoint(
        self,
        block_height: int,
        block_hash: str
    ) -> str:
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
        combined_root = keccak(
            bytes.fromhex(native_root) +
            bytes.fromhex(evm_root)
        ).hex()
        
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
            (block_height, block_hash, native_root, evm_root,
             combined_root, stats['synced_count'],
             str(stats['native_total']), str(stats['evm_total']), now)
        )
        await conn.commit()

        logger.info(
            f"State checkpoint at block {block_height}: "
            f"combined_root={combined_root[:16]}... "
            f"(native: {native_root[:16]}..., evm: {evm_root[:16]}...)"
        )
        
        return combined_root
    
    async def _compute_native_state_root(self, block_height: int) -> str:
        """
        Compute Merkle root of native UTXO state.
        
        This is deterministic — all nodes compute same result.
        """
        conn = self.db.connection
        cursor = await conn.execute(
            """
            SELECT uo.tx_hash, uo."index", t.outputs_amounts, uo.address
            FROM unspent_outputs uo
            INNER JOIN transactions t ON uo.tx_hash = t.tx_hash
            INNER JOIN blocks b ON t.block_hash = b.block_hash
            WHERE b.id <= ?
            ORDER BY uo.tx_hash, uo."index"
            """,
            (block_height,)
        )
        utxos = await cursor.fetchall()

        if not utxos:
            return '0' * 64

        # Build Merkle tree from UTXOs
        leaves = []
        for utxo in utxos:
            tx_hash_val = utxo['tx_hash'] if isinstance(utxo['tx_hash'], str) else utxo[0]
            index_val = utxo['index'] if isinstance(utxo, dict) else utxo[1]
            address_val = utxo['address'] if isinstance(utxo, dict) else utxo[3]

            leaf_data = (
                bytes.fromhex(tx_hash_val) +
                int(index_val).to_bytes(4, 'big') +
                address_val.encode('utf-8')
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
        conn = self.db.connection
        cursor = await conn.execute(
            """
            SELECT
                COUNT(*) as synced_count,
                COALESCE(SUM(CAST(native_balance_at_sync AS REAL)), 0) as native_total,
                COALESCE(SUM(CAST(evm_balance_at_sync AS INTEGER)), 0) as evm_total
            FROM evm_balance_sync_registry
            """
        )
        row = await cursor.fetchone()

        return {
            'synced_count': row[0] or 0,
            'native_total': Decimal(str(row[1])) if row[1] else Decimal('0'),
            'evm_total': int(row[2]) if row[2] else 0,
        }


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
        sync_manager: StateSyncManager
    ):
        self.block_height = block_height
        self.block_hash = block_hash
        self.block_timestamp = block_timestamp
        self.db = db
        self.evm_state = evm_state
        self.sync_manager = sync_manager
        
        self._evm_snapshot_id = None
        self._sender_balance_before_sync = None
    
    async def prepare_execution(self, sender: str) -> None:
        """
        Prepare execution environment for sender.
        
        Deterministic — all nodes execute identically:
        1. Sync sender's balance from native to EVM
        2. Create state snapshot for potential rollback
        """
        sender = to_checksum_address(sender)
        
        self._sender_balance_before_sync = await self.evm_state.get_balance(sender)
        
        await self.sync_manager.sync_address_to_evm(
            address=sender,
            block_height=self.block_height,
            block_hash=self.block_hash
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
        value: int
    ) -> None:
        """
        Finalize execution and update state.
        
        If successful: commits EVM state and records changes
        If failed: reverts EVM state to pre-execution snapshot
        """
        sender = to_checksum_address(sender)
        
        if success:
            if self._evm_snapshot_id is not None:
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
                reason='gas_payment_and_execution'
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
