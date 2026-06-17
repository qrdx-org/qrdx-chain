"""
Validator-lifecycle Phase 3 — membership (deterministic join/leave on the
consensus validators table). Pins register_pending_validator, the activation/exit
selection (get_validators_to_activate / _to_exit), and the end-to-end
pending→active activation via apply_epoch_validator_updates at the scheduled epoch.
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


async def _status(db, addr):
    c = await db.connection.execute(
        "SELECT status, stake, activation_epoch FROM validators WHERE address = ?", (addr,))
    return await c.fetchone()


async def test_register_pending_validator(db):
    created = await db.register_pending_validator("0xV1", "pk1", Decimal("5000"), activation_epoch=3)
    assert created is True
    row = await _status(db, "0xV1")
    assert row[0] == "pending" and Decimal(row[1]) == Decimal("5000") and row[2] == 3


async def test_repeat_deposit_tops_up_stake(db):
    await db.register_pending_validator("0xV1", "pk1", Decimal("5000"), activation_epoch=3)
    created = await db.register_pending_validator("0xV1", "pk1", Decimal("2000"), activation_epoch=3)
    assert created is False  # not a new validator
    row = await _status(db, "0xV1")
    assert Decimal(row[1]) == Decimal("7000")


async def test_get_validators_to_activate_respects_schedule(db):
    await db.register_pending_validator("0xV1", "pk1", Decimal("5000"), activation_epoch=2)
    await db.register_pending_validator("0xV2", "pk2", Decimal("5000"), activation_epoch=5)
    await db.connection.commit()
    assert await db.get_validators_to_activate(1) == []          # none due yet
    assert await db.get_validators_to_activate(2) == ["0xV1"]    # V1 due at 2
    assert await db.get_validators_to_activate(5) == ["0xV1", "0xV2"]  # both due by 5


async def test_get_validators_to_exit(db):
    await db.connection.execute(
        "INSERT INTO validators (address, public_key, stake, effective_stake, status, exit_epoch) "
        "VALUES ('0xE', 'pk', '1000', '1000', 'exiting', 4)")
    await db.connection.commit()
    assert await db.get_validators_to_exit(3) == []
    assert await db.get_validators_to_exit(4) == ["0xE"]


async def test_pending_activates_at_scheduled_epoch(db):
    # Full flow: register pending @ activation_epoch=2, then run the epoch update.
    await db.register_pending_validator("0xV1", "pk1", Decimal("5000"), activation_epoch=2)
    await db.connection.commit()

    # Epoch 1: not yet due → stays pending.
    activated = await db.get_validators_to_activate(1)
    await db.apply_epoch_validator_updates({}, {}, activated, [], 1, Decimal("1000000"), enforce=True)
    await db.connection.commit()
    assert (await _status(db, "0xV1"))[0] == "pending"

    # Epoch 2: due → activated.
    activated = await db.get_validators_to_activate(2)
    assert activated == ["0xV1"]
    await db.apply_epoch_validator_updates({}, {}, activated, [], 2, Decimal("1000000"), enforce=True)
    await db.connection.commit()
    assert (await _status(db, "0xV1"))[0] == "active"
