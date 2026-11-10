"""
Finality link 2 (DB) — persistent attestation-vote store + epoch finality.

All nodes (validators and full nodes) record the attestation votes carried in
imported block bodies, so per-epoch attesting stake — and thus finality — is
computable from the DB without an in-memory pool. One vote per validator per
target epoch; finality status is persisted to the epochs table (SQLite path).
"""

import os
import tempfile

from qrdx.database_sqlite import DatabaseSQLite


async def _db():
    path = tempfile.mktemp(suffix=".db")
    return await DatabaseSQLite.create(db_path=path), path


async def test_record_and_query_epoch_attesters():
    db, path = await _db()
    try:
        await db.record_attestation_vote("0xPQaa", target_epoch=2, source_epoch=1, slot=20, block_hash="h")
        await db.record_attestation_vote("0xPQbb", target_epoch=2, source_epoch=1, slot=21, block_hash="h")
        await db.record_attestation_vote("0xPQcc", target_epoch=3, source_epoch=2, slot=30, block_hash="h2")
        assert set(await db.get_epoch_attesters(2)) == {"0xPQaa", "0xPQbb"}
        assert set(await db.get_epoch_attesters(3)) == {"0xPQcc"}
        assert await db.get_epoch_attesters(9) == []
    finally:
        await db.close(); os.remove(path)


async def test_one_vote_per_validator_per_target():
    db, path = await _db()
    try:
        await db.record_attestation_vote("0xPQaa", target_epoch=2, source_epoch=1, slot=20, block_hash="h1")
        # Duplicate / later vote for the same target is ignored (idempotent).
        await db.record_attestation_vote("0xPQaa", target_epoch=2, source_epoch=1, slot=22, block_hash="h2")
        assert await db.get_epoch_attesters(2) == ["0xPQaa"]
    finally:
        await db.close(); os.remove(path)


async def test_set_and_read_back_epoch_finality():
    db, path = await _db()
    try:
        await db.set_epoch_finality(2, start_slot=16, end_slot=23, justified=True, finalized=False)
        row = db.store["epochs"].get(2)
        assert (bool(row.justified), bool(row.finalized)) == (True, False)

        # Upgrade to finalized — finalized_at gets set.
        await db.set_epoch_finality(2, 16, 23, justified=True, finalized=True)
        row = db.store["epochs"].get(2)
        assert bool(row.finalized) is True and row.finalized_at is not None
    finally:
        await db.close(); os.remove(path)


async def test_the_chain_head_reports_the_stored_finality(monkeypatch):
    """``get_pos_chain_head`` reads the newest finalized and justified epochs back."""
    from qrdx import manager
    from qrdx.database import Database

    db, path = await _db()
    try:
        await db.add_block(block_hash="aa" * 32, block_height=0, block_content="{}",
                           validator_address="0xPQ" + "00" * 32, timestamp=1)
        await db.set_epoch_finality(2, 16, 23, justified=True, finalized=True)
        await db.set_epoch_finality(3, 24, 31, justified=True, finalized=False)
        monkeypatch.setattr(Database, "instance", db)
        head = await manager.get_pos_chain_head()
        assert (head["finalized_epoch"], head["finalized_slot"]) == (2, 16)
        assert (head["justified_epoch"], head["justified_slot"]) == (3, 24)
    finally:
        await db.close(); os.remove(path)
