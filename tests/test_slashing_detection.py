"""
Slashing — DOUBLE_SIGN detection (observe-first). Pins the pure detector
(is_double_sign: same proposer + slot, different hash = offence; distinct
proposers / slots = benign equal-height race) and the durable, idempotent
slashing_events recording on the SQLite consensus DB.
"""

import os
import tempfile

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
