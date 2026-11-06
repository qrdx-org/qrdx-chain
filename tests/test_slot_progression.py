"""
A block's slot must be later than its parent's and not ahead of the clock
(qrdx/validator/block_verification.py verify_slot_progression).

Eligibility binds a proposer to a slot, but nothing compared the slot with the chain: one eligible
proposer could fill any number of heights from that one slot, or sign blocks for slots it will be
eligible in later. Every import path now refuses both; the proposer skips a slot that is not after
its tip's.
"""

import os
import tempfile

import pytest

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator.block_verification import _future_tolerance_slots, verify_slot_progression


@pytest.fixture
async def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database = await DatabaseSQLite.create(path)
    for h, slot in enumerate([0, 3, 7]):
        await database.connection.execute(
            "INSERT INTO blocks (block_hash, block_height, content, timestamp) VALUES (?, ?, ?, 0)",
            (f"{h:064x}", h, repr({"slot": slot})),
        )
    await database.connection.commit()
    yield database
    await database.connection.close()
    os.remove(path)


async def test_a_later_slot_extends_the_chain(db):
    assert await verify_slot_progression(db, {"slot": 8}, 3, current_slot=8) == (True, "")


@pytest.mark.parametrize("slot", [7, 6])
async def test_a_slot_not_after_the_parents_is_refused(db, slot):
    ok, err = await verify_slot_progression(db, {"slot": slot}, 3, current_slot=20)
    assert not ok and "not after its parent's" in err


async def test_a_slot_ahead_of_the_clock_is_refused(db):
    tolerance = _future_tolerance_slots()
    assert (await verify_slot_progression(db, {"slot": 10 + tolerance}, 3, current_slot=10))[0]
    ok, err = await verify_slot_progression(db, {"slot": 11 + tolerance}, 3, current_slot=10)
    assert not ok and "ahead of the clock" in err


async def test_history_is_judged_against_its_own_parent(db):
    """Sync replays old blocks: the clock check never bites them, the parent rule still does."""
    assert (await verify_slot_progression(db, {"slot": 5}, 2, current_slot=10**6))[0]
    assert not (await verify_slot_progression(db, {"slot": 3}, 2, current_slot=10**6))[0]
