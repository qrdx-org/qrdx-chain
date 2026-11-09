"""
The undo journal's tables (qrdx/undo_journal.py ``ensure``).

Some journaled tables are created after the node starts (the EVM's balance sync, when it is first
used). Each block used to look for every missing one, two round trips each; now they are looked
for again only when the schema has changed. What must hold: a table created later is still
journaled from its first write (and undone), a schema that did not change costs one query, and a
rollback that takes a table with its triggers is noticed.
"""
import os
import tempfile

import pytest

from qrdx import chain_index, undo_journal
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.node.observability import DB_CALLS, count_db_calls

REGISTRY = (
    "CREATE TABLE IF NOT EXISTS evm_balance_sync_registry (address TEXT PRIMARY KEY,"
    " last_sync_block_height INTEGER NOT NULL, last_sync_block_hash TEXT NOT NULL,"
    " last_sync_timestamp TEXT NOT NULL, native_balance_at_sync TEXT NOT NULL,"
    " evm_balance_at_sync TEXT NOT NULL, sync_tx_hash TEXT)"
)


@pytest.fixture
async def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database = await DatabaseSQLite.create(path)
    await chain_index.sync(database)  # (as a node does: the rollback hook)
    await undo_journal.set_floor(database, 0)
    await database.connection.commit()
    yield database
    await database.connection.close()
    for p in (path, path + "-wal", path + "-shm"):
        if os.path.exists(p):
            os.remove(p)


async def _write(db, height, address):
    async with undo_journal.recording(db, height):
        await db.connection.execute(
            "INSERT INTO evm_balance_sync_registry VALUES (?, ?, 'h', 't', '1', '1', NULL)",
            (address, height),
        )


async def _held(db):
    rows = await db.connection.execute_fetchall(
        "SELECT address FROM evm_balance_sync_registry ORDER BY address")
    return [r[0] for r in rows]


async def test_a_table_created_later_is_journaled_from_its_first_write(db):
    conn = db.connection
    count_db_calls(conn)
    async with undo_journal.recording(db, 1):
        pass
    before = DB_CALLS[0]
    for h in (2, 3):
        async with undo_journal.recording(db, h):
            pass
    assert DB_CALLS[0] - before == 2  # (the schema unchanged: one query a block)

    await conn.execute(REGISTRY)
    await _write(db, 4, "a")
    await _write(db, 5, "b")
    await conn.commit()
    assert await _held(db) == ["a", "b"]
    assert await undo_journal.rollback_to(db, 4) == 1
    assert await _held(db) == ["a"]
    assert await undo_journal.rollback_to(db, 3) == 1
    assert await _held(db) == []


async def test_a_rollback_that_takes_a_table_and_its_triggers_is_noticed(db):
    conn = db.connection
    # (a write opens a transaction: DDL with none open would commit on its own)
    await conn.execute("INSERT OR REPLACE INTO chain_metadata (key, value) VALUES ('t', '1')")
    await conn.execute(REGISTRY)                  # (in the transaction…)
    async with undo_journal.recording(db, 1):     # (…its triggers installed in it too)
        pass
    await conn.rollback()                         # (…both gone)
    assert not await conn.execute_fetchall(
        "SELECT 1 FROM sqlite_master WHERE name = 'evm_balance_sync_registry'")
    await conn.execute(REGISTRY)
    await conn.commit()
    await _write(db, 2, "a")
    await conn.commit()
    assert await undo_journal.rollback_to(db, 1) == 1
    assert await _held(db) == []


async def test_a_batched_balance_flush_journals_what_the_triggers_would(tmp_path, monkeypatch):
    """``apply_account_balance_deltas`` journals its updates in one statement ahead of them and
    folds the accumulator once (undo_journal.written_ahead, state_commitment.batched). Against a
    twin whose flush leaves both to the triggers, row by row: the same undo entries, rows and
    accumulator after every block — and a rollback by the journal restores the earlier state."""
    import marshal
    import random
    from decimal import Decimal

    from qrdx import state_commitment as sc
    from qrdx import undo_journal
    from qrdx.database_sqlite import DatabaseSQLite

    batched_db = await DatabaseSQLite.create(db_path=str(tmp_path / "batched.db"))
    rowwise_db = await DatabaseSQLite.create(db_path=str(tmp_path / "rowwise.db"))
    real_journaling, real_batched = undo_journal.journaling, sc.batched

    class _Triggers:  # (the twin: nothing batched, the triggers do it all)
        def __init__(self, conn, kind):
            pass

        def fold(self, old, new):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

    async def snapshot(db):
        rows = await db.connection.execute_fetchall(
            "SELECT address, balance, nonce, code_hash, storage_root FROM account_state "
            "ORDER BY address")
        undo = await db.connection.execute_fetchall(
            "SELECT height, tbl, op, rid, old FROM undo_log ORDER BY seq")
        # (an entry as the rollback reads it: marshal's bytes for equal values may differ, as it
        # marks objects shared in memory)
        undo = [(h, t, o, r, None if old is None else marshal.loads(old))
                for h, t, o, r, old in undo]
        return [tuple(r) for r in rows], undo, \
            await sc.stored_accumulator(db.connection, "account")

    try:
        rng = random.Random(5)
        addrs = ["0xPQ" + f"{i:064x}" for i in range(30)]
        states = {}
        for height in range(1, 16):
            deltas = [(rng.choice(addrs), Decimal(rng.choice(["1", "-0.5", "2.25", "-3", "7"])))
                      for _ in range(rng.randint(1, 20))]
            for db, plain in ((batched_db, False), (rowwise_db, True)):
                if plain:
                    monkeypatch.setattr(undo_journal, "journaling", lambda conn, table: None)
                    monkeypatch.setattr(sc, "batched", _Triggers)
                async with undo_journal.recording(db, height):
                    await db.apply_account_balance_deltas(deltas)
                await db.connection.commit()
                monkeypatch.setattr(undo_journal, "journaling", real_journaling)
                monkeypatch.setattr(sc, "batched", real_batched)
            a, b = await snapshot(batched_db), await snapshot(rowwise_db)
            assert a == b, height
            assert a[2] == await sc.full_accumulator(batched_db.connection, "account")
            states[height] = a[0]
        assert len(a[1]) > 50                                   # (updates journaled)
        assert await undo_journal.rollback_to(batched_db, 7) is not None
        rows = await batched_db.connection.execute_fetchall(
            "SELECT address, balance, nonce, code_hash, storage_root FROM account_state "
            "ORDER BY address")
        assert [tuple(r) for r in rows] == states[7]
        assert await sc.stored_accumulator(batched_db.connection, "account") == \
            await sc.full_accumulator(batched_db.connection, "account")
    finally:
        await batched_db.connection.close()
        await rowwise_db.connection.close()
