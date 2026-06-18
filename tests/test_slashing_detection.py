"""
Slashing — DOUBLE_SIGN detection (observe-first). Pins the pure detector
(is_double_sign: same proposer + slot, different hash = offence; distinct
proposers / slots = benign equal-height race) and the durable, idempotent
slashing_events recording on the SQLite consensus DB.
"""

import os
import tempfile
from decimal import Decimal

import pytest

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator.block_verification import is_double_sign


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


def _bc(proposer="0xA", slot=5, h="hash1"):
    # Minimal block_content repr (str(dict)) as carried on the wire.
    return str({"proposer_address": proposer, "slot": slot, "epoch": slot // 8, "hash": h})


def test_double_sign_same_proposer_same_slot_diff_hash():
    assert is_double_sign(_bc(h="hA"), _bc(h="hB")) is True


def test_not_double_sign_distinct_proposers():
    # The benign equal-height race: two different eligible-ish proposers, same height.
    assert is_double_sign(_bc(proposer="0xA", h="hA"), _bc(proposer="0xB", h="hB")) is False


def test_not_double_sign_different_slots():
    assert is_double_sign(_bc(slot=5, h="hA"), _bc(slot=6, h="hB")) is False


def test_not_double_sign_identical_block():
    # Same block re-broadcast — identical hash, not an offence.
    assert is_double_sign(_bc(h="hA"), _bc(h="hA")) is False


def test_double_sign_accepts_dict_or_repr():
    a = {"proposer_address": "0xA", "slot": 5, "hash": "hA"}
    b = {"proposer_address": "0xA", "slot": 5, "hash": "hB"}
    assert is_double_sign(a, b) is True
    assert is_double_sign(str(a), b) is True  # mixed repr/dict


async def test_record_slashing_event_idempotent(db):
    new1 = await db.record_slashing_event("0xA", "double_sign", 5, 0, '{"x":1}')
    new2 = await db.record_slashing_event("0xA", "double_sign", 5, 0, '{"x":1}')  # dup
    assert new1 is True and new2 is False
    events = await db.get_slashing_events("0xA")
    assert len(events) == 1
    assert events[0]["condition"] == "double_sign" and events[0]["slot"] == 5
    assert events[0]["processed"] is False


async def test_record_slashing_event_distinct_offences(db):
    await db.record_slashing_event("0xA", "double_sign", 5, 0, "{}")
    await db.record_slashing_event("0xA", "double_sign", 9, 1, "{}")  # different slot
    await db.record_slashing_event("0xB", "double_sign", 5, 0, "{}")  # different validator
    assert len(await db.get_slashing_events()) == 3
    assert len(await db.get_slashing_events("0xA")) == 2


# ── Deterministic penalty application (the finalized-epoch slash) ──────────────

async def _seed_validator(db, addr, stake="100000"):
    await db.connection.execute(
        "INSERT INTO validators (address, public_key, stake, effective_stake, status) "
        "VALUES (?, 'pk', ?, ?, 'active')", (addr, stake, stake))
    await db.connection.commit()


async def test_unprocessed_events_respect_finalized_epoch(db):
    await db.record_slashing_event("0xA", "double_sign", 5, 2, "{}")
    await db.record_slashing_event("0xA", "double_sign", 90, 9, "{}")
    # Only offences in finalized epochs (≤ up_to_epoch) are eligible.
    assert len(await db.get_unprocessed_slashing_events(up_to_epoch=2)) == 1
    assert len(await db.get_unprocessed_slashing_events(up_to_epoch=9)) == 2


async def test_apply_validator_slash_observe_vs_enforce(db):
    await _seed_validator(db, "0xA", "100000")
    # observe: previews the post-slash stake, writes nothing
    res = await db.apply_validator_slash("0xA", "50000", enforce=False)
    assert res["new_stake"] == "50000" and res["applied"] is False
    row = await _status(db, "0xA")
    assert row[0] == "active" and Decimal(row[1]) == Decimal("100000")  # unchanged
    # enforce: effective_stake -= penalty, status='slashed'
    res = await db.apply_validator_slash("0xA", "50000", enforce=True)
    await db.connection.commit()
    assert res["applied"] is True
    row = await _status(db, "0xA")
    assert row[0] == "slashed" and Decimal(row[1]) == Decimal("50000")


async def test_apply_validator_slash_clamps_at_zero(db):
    await _seed_validator(db, "0xA", "1000")
    await db.apply_validator_slash("0xA", "5000", enforce=True)  # penalty > stake
    await db.connection.commit()
    assert Decimal((await _status(db, "0xA"))[1]) == Decimal("0")


async def test_apply_epoch_slashings_double_sign_is_50pct_and_ejects(db):
    from qrdx.validator.epoch_loop import apply_epoch_slashings
    await _seed_validator(db, "0xBAD", "100000")
    await db.record_slashing_event("0xBAD", "double_sign", 40, 5, "{}")
    # observe: logs, writes nothing — validator untouched, evidence still unprocessed
    await apply_epoch_slashings(db, epoch=5, enforce=False)
    await db.connection.commit()
    assert (await _status(db, "0xBAD"))[0] == "active"
    assert len(await db.get_unprocessed_slashing_events(up_to_epoch=5)) == 1
    # enforce: DOUBLE_SIGN = 50% slash + eject + evidence marked processed
    await apply_epoch_slashings(db, epoch=5, enforce=True)
    await db.connection.commit()
    row = await _status(db, "0xBAD")
    assert row[0] == "slashed" and Decimal(row[1]) == Decimal("50000")
    assert await db.get_unprocessed_slashing_events(up_to_epoch=5) == []  # consumed


async def _status(db, addr):
    c = await db.connection.execute(
        "SELECT status, effective_stake FROM validators WHERE address = ?", (addr,))
    return await c.fetchone()
