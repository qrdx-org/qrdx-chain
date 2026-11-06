"""
E-D3b prerequisite — atomic block-level commit/revert of EVM/account state.

The EVM execution path commits account_state to the DB per transaction, which
would prevent an importing node from safely REVERTING a block whose
account_state_root doesn't match (a mismatched block could corrupt state).

`ExecutionContext.finalize_execution(..., defer_commit=True)` keeps a successful
tx's changes in the EVM cache instead of flushing to the DB, so a caller can:
  - snapshot at block start,
  - execute all txs with defer_commit=True,
  - commit once (root matches) OR revert the snapshot (reject-on-mismatch).

These tests pin that behavior (and that the default per-tx commit is unchanged).
"""

import os
import tempfile

from eth_utils import to_checksum_address

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.contracts.state import ContractStateManager, Account
from qrdx.contracts.state_sync import StateSyncManager, ExecutionContext

ADDR = to_checksum_address("0x" + "11" * 20)


async def _setup():
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    sm = ContractStateManager(db)
    sync = StateSyncManager(db, sm)
    await sync.ensure_tables_exist()
    return db, sm, sync, path


async def _db_balance(db):
    cur = await db.connection.execute(
        "SELECT balance FROM account_state WHERE address = ?", (ADDR,))
    row = await cur.fetchone()
    return int(row[0]) if row and row[0] is not None else None


async def test_defer_commit_keeps_change_out_of_db_until_committed():
    db, sm, sync, path = await _setup()
    try:
        ctx = ExecutionContext(1, "h", 0, db, sm, sync)
        await ctx.prepare_execution(ADDR)
        # Mutate EVM cache for the account.
        acc = await sm.get_account(ADDR)
        acc.balance = 5000
        await sm.set_account(acc)

        # Deferred finalize: must NOT write the balance to the DB yet.
        await ctx.finalize_execution(ADDR, "0xtx", True, 21000, 0, 0, defer_commit=True)
        assert await _db_balance(db) != 5000, "defer_commit must keep change in cache"

        # Block-boundary commit flushes the cache to the DB.
        await sm.commit(1)
        assert await _db_balance(db) == 5000, "commit must flush the cached change"
    finally:
        await db.close(); os.remove(path)


async def test_default_commits_per_tx():
    db, sm, sync, path = await _setup()
    try:
        ctx = ExecutionContext(1, "h", 0, db, sm, sync)
        await ctx.prepare_execution(ADDR)
        acc = await sm.get_account(ADDR)
        acc.balance = 7000
        await sm.set_account(acc)
        # Default (defer_commit=False) commits immediately — unchanged live behavior.
        await ctx.finalize_execution(ADDR, "0xtx", True, 21000, 0, 0)
        assert await _db_balance(db) == 7000
    finally:
        await db.close(); os.remove(path)


async def test_revert_after_deferred_block_discards_changes():
    """Snapshot at block start, defer-execute, then revert ⇒ DB untouched."""
    db, sm, sync, path = await _setup()
    try:
        block_snap = await sm.snapshot()  # block-start snapshot
        ctx = ExecutionContext(2, "h", 0, db, sm, sync)
        await ctx.prepare_execution(ADDR)
        acc = await sm.get_account(ADDR)
        acc.balance = 9999
        await sm.set_account(acc)
        await ctx.finalize_execution(ADDR, "0xtx", True, 21000, 0, 0, defer_commit=True)

        # Reject-on-mismatch path: revert to the block-start snapshot, no commit.
        await sm.revert(block_snap)
        await sm.commit(2)  # flush (nothing dirty after revert)
        assert await _db_balance(db) != 9999, "reverted block must not persist its changes"
    finally:
        await db.close(); os.remove(path)
