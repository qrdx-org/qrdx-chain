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
        cur = await db.connection.execute(
            "SELECT justified, finalized FROM epochs WHERE epoch = 2")
        row = await cur.fetchone()
        assert (bool(row[0]), bool(row[1])) == (True, False)

        # Upgrade to finalized — finalized_at gets set.
        await db.set_epoch_finality(2, 16, 23, justified=True, finalized=True)
        cur = await db.connection.execute(
            "SELECT finalized, finalized_at FROM epochs WHERE epoch = 2")
        row = await cur.fetchone()
        assert bool(row[0]) is True and row[1] is not None
    finally:
        await db.close(); os.remove(path)
