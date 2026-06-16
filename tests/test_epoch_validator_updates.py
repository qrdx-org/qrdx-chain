"""
Validator-lifecycle unification — SQLite epoch validators-table writes.

Pins db.apply_epoch_validator_updates (the SQLite port of the PostgreSQL-only
epoch_processing persistence): rewards/penalties move effective_stake with the
right clamps + bookkeeping, activations/exits flip status, observe-mode writes
nothing, and the arithmetic is deterministic. Plus get_validators_table_hash as
the cross-node convergence probe.
"""

import os
import tempfile
from decimal import Decimal

import pytest

from qrdx.database_sqlite import DatabaseSQLite


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


async def _add(db, addr, stake="1000", status="active"):
    await db.connection.execute(
        "INSERT INTO validators (address, public_key, stake, effective_stake, status) "
        "VALUES (?, ?, ?, ?, ?)", (addr, "pk", stake, stake, status))
    await db.connection.commit()


async def _stake(db, addr):
    c = await db.connection.execute(
        "SELECT effective_stake, total_rewards, total_slashed, status, activation_epoch "
        "FROM validators WHERE address = ?", (addr,))
    return await c.fetchone()


async def test_reward_increases_stake_and_total(db):
    await _add(db, "0xA", "1000")
    await db.apply_epoch_validator_updates(
        rewards={"0xA": Decimal("50")}, penalties={}, activated=[], exited=[],
        activation_epoch=5, max_effective_balance=Decimal("100000"), enforce=True)
    row = await _stake(db, "0xA")
    assert Decimal(row[0]) == Decimal("1050") and Decimal(row[1]) == Decimal("50")


async def test_penalty_decreases_stake_clamps_zero(db):
    await _add(db, "0xB", "30")
    await db.apply_epoch_validator_updates(
        rewards={}, penalties={"0xB": Decimal("100")}, activated=[], exited=[],
        activation_epoch=5, max_effective_balance=None, enforce=True)
    row = await _stake(db, "0xB")
    assert Decimal(row[0]) == Decimal("0") and Decimal(row[2]) == Decimal("100")


async def test_reward_clamps_at_max_effective_balance(db):
    await _add(db, "0xC", "99000")
    await db.apply_epoch_validator_updates(
        rewards={"0xC": Decimal("5000")}, penalties={}, activated=[], exited=[],
        activation_epoch=5, max_effective_balance=Decimal("100000"), enforce=True)
    row = await _stake(db, "0xC")
    assert Decimal(row[0]) == Decimal("100000")


async def test_activation_and_exit_flip_status(db):
    await _add(db, "0xD", "1000", status="pending")
    await _add(db, "0xE", "1000", status="active")
    await db.apply_epoch_validator_updates(
        rewards={}, penalties={}, activated=["0xD"], exited=["0xE"],
        activation_epoch=7, max_effective_balance=None, enforce=True)
    d = await _stake(db, "0xD")
    e = await _stake(db, "0xE")
    assert d[3] == "active" and d[4] == 7
    assert e[3] == "exited"


async def test_observe_mode_writes_nothing(db):
    await _add(db, "0xF", "1000")
    res = await db.apply_epoch_validator_updates(
        rewards={"0xF": Decimal("50")}, penalties={}, activated=[], exited=[],
        activation_epoch=5, max_effective_balance=Decimal("100000"), enforce=False)
    row = await _stake(db, "0xF")
    assert Decimal(row[0]) == Decimal("1000")  # unchanged
    assert res["applied"] is False
    assert res["effective_stake_preview"]["0xF"] == "1050"  # would-be value


async def test_validators_table_hash_deterministic_and_sensitive(db):
    assert await db.get_validators_table_hash() == "0" * 64  # empty
    await _add(db, "0xA", "1000")
    h1 = await db.get_validators_table_hash()
    assert h1 != "0" * 64
    assert h1 == await db.get_validators_table_hash()  # deterministic
    await db.apply_epoch_validator_updates(
        rewards={"0xA": Decimal("1")}, penalties={}, activated=[], exited=[],
        activation_epoch=1, max_effective_balance=None, enforce=True)
    assert await db.get_validators_table_hash() != h1  # reflects the update
