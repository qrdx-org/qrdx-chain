"""
Reorg-safety of account_state genesis funding (Phase E).

Regression for the divergence found by scripts/phase_e_invariants.py: a 0x address
funded at genesis lost its allocation on a follower's reorg-rebuild because the EVM
balance-sync registry (which dedups account_state→EVM syncs by address+block_height)
SURVIVED the rebuild. The replay then SKIPPED re-syncing, the freshly-cleared EVM
balance stayed 0, and the replayed tx overwrote the reseeded genesis funding.

Fix: clear_account_state() also resets evm_balance_sync_registry so the replay
re-syncs exactly as the original run did.
"""

import os
import tempfile
from decimal import Decimal

import pytest

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.contracts.state_sync import StateSyncManager

ADDR = "0x87cFe9d7A171545FaFf6fcCa1B5a7f3cF3269cEf"


@pytest.fixture
async def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database = await DatabaseSQLite.create(path)
    yield database
    await database.connection.close()
    for p in (path, path + "-wal", path + "-shm"):
        try:
            os.remove(p)
        except OSError:
            pass


async def test_clear_account_state_resets_sync_registry(db):
    ssm = StateSyncManager(db, evm_state=None)
    await ssm.ensure_tables_exist()
    # Original run: the address was synced at block 5.
    await ssm._record_sync(address=ADDR, block_height=5, block_hash="bh",
                           native_balance=Decimal("500000"), evm_balance=0, tx_hash=None)
    await db.connection.commit()
    # Pre-clear: a replay of block 5 would be deduped as "already synced" → SKIP (the bug).
    assert await ssm._is_already_synced(ADDR, 5) is True

    # The reorg rebuild clears account_state — must also reset the sync registry.
    await db.clear_account_state()

    # Post-clear: the replay will RE-SYNC (no stale dedup), so genesis funding survives.
    assert await ssm._is_already_synced(ADDR, 5) is False
    cur = await db.connection.execute("SELECT COUNT(*) FROM evm_balance_sync_registry")
    assert (await cur.fetchone())[0] == 0


async def test_clear_account_state_ok_without_evm_tables(db):
    # EVM never initialized → the sync tables don't exist; clear must not raise.
    await db.connection.execute("INSERT INTO account_state (address, balance, created_at, updated_at) "
                                "VALUES (?, '1', 0, 0)", (ADDR,))
    await db.connection.commit()
    await db.clear_account_state()  # should not raise
    cur = await db.connection.execute("SELECT COUNT(*) FROM account_state")
    assert (await cur.fetchone())[0] == 0
