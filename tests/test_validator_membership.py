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


def test_epoch_from_block_handles_all_import_shapes():
    """The deterministic activation/exit schedule keys off the block epoch, which the
    import paths carry in different shapes; epoch_from_block must extract it from each."""
    from qrdx.validator.block_verification import epoch_from_block
    from qrdx.constants import SLOTS_PER_EPOCH
    assert epoch_from_block({"epoch": 12}) == 12                                   # parsed block
    assert epoch_from_block({"block_content": str({"slot": 96, "epoch": 12})}) == 12  # wire envelope
    assert epoch_from_block({"block_content": str({"slot": 96})}) == 96 // SLOTS_PER_EPOCH  # slot fallback
    assert epoch_from_block({"foo": 1}) is None
    assert epoch_from_block(None) is None


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


async def test_stake_deposit_op_records_and_flush_registers_pending(db):
    """STAKE_DEPOSIT op records a deterministic deposit; the flush registers a
    pending validator (the consensus join path)."""
    from types import SimpleNamespace
    from qrdx.exchange.state_manager import ExchangeStateManager
    from qrdx.exchange.block_processor import flush_validator_lifecycle_deltas

    mgr = ExchangeStateManager()
    mgr.begin_block(1, 0.0)
    tx = SimpleNamespace(sender="0xPQnewval", nonce=0,
                         params={"validator_public_key": "pkNEW", "stake_amount": "100000"})
    res = mgr._op_stake_deposit(tx)
    assert res.success and res.data["status"] == "pending"
    ops = mgr.validator_lifecycle_ops()
    assert ops == [{"type": "deposit", "address": "0xPQnewval",
                    "public_key": "pkNEW", "stake": "100000"}]

    await flush_validator_lifecycle_deltas(db, mgr)
    await db.connection.commit()
    row = await _status(db, "0xPQnewval")
    assert row[0] == "pending" and Decimal(row[1]) == Decimal("100000") and row[2] is None  # unscheduled


async def test_deposit_flush_schedules_activation_from_block_epoch(db):
    """The deposit flush assigns activation_epoch = block_epoch + ACTIVATION_DELAY_EPOCHS
    deterministically (derived from the carrying block, identical on every node) — not
    left for a non-deterministic epoch-loop tick to schedule."""
    from types import SimpleNamespace
    from qrdx.exchange.state_manager import ExchangeStateManager
    from qrdx.exchange.block_processor import flush_validator_lifecycle_deltas
    from qrdx.constants import ACTIVATION_DELAY_EPOCHS

    mgr = ExchangeStateManager()
    mgr.begin_block(1, 0.0)
    mgr._op_stake_deposit(SimpleNamespace(sender="0xPQjoin", nonce=0,
        params={"validator_public_key": "pk", "stake_amount": "100000"}))
    await flush_validator_lifecycle_deltas(db, mgr, block_epoch=5)
    await db.connection.commit()
    row = await _status(db, "0xPQjoin")
    assert row[0] == "pending" and row[2] == 5 + ACTIVATION_DELAY_EPOCHS


async def test_exit_flush_schedules_exit_from_block_epoch(db):
    """The exit flush sets exit_epoch = block_epoch + UNBONDING_PERIOD_EPOCHS
    deterministically when moving an active validator to 'exiting'."""
    from types import SimpleNamespace
    from qrdx.exchange.state_manager import ExchangeStateManager
    from qrdx.exchange.block_processor import flush_validator_lifecycle_deltas
    from qrdx.constants import UNBONDING_PERIOD_EPOCHS

    await _seed_active(db, "0xPQgo")
    mgr = ExchangeStateManager()
    mgr.begin_block(1, 0.0)
    mgr._op_stake_exit(SimpleNamespace(sender="0xPQgo", nonce=0, params={}))
    await flush_validator_lifecycle_deltas(db, mgr, block_epoch=7)
    await db.connection.commit()
    row = await _status(db, "0xPQgo")
    c = await db.connection.execute("SELECT exit_epoch FROM validators WHERE address='0xPQgo'")
    assert row[0] == "exiting" and (await c.fetchone())[0] == 7 + UNBONDING_PERIOD_EPOCHS


async def test_stake_deposit_rejects_nonpositive(db):
    from types import SimpleNamespace
    from qrdx.exchange.state_manager import ExchangeStateManager
    mgr = ExchangeStateManager()
    mgr.begin_block(1, 0.0)
    res = mgr._op_stake_deposit(SimpleNamespace(
        sender="0xz", nonce=0, params={"validator_public_key": "pk", "stake_amount": "0"}))
    assert not res.success and "positive" in res.error


async def _seed_active(db, addr, stake="200000"):
    await db.connection.execute(
        "INSERT INTO validators (address, public_key, stake, effective_stake, status, activation_epoch) "
        "VALUES (?, 'pk', ?, ?, 'active', 0)", (addr, stake, stake))
    await db.connection.commit()


async def test_stake_exit_op_records_and_flush_marks_exiting(db):
    """STAKE_EXIT records a deterministic exit op; the flush moves an ACTIVE validator
    to 'exiting' (still eligible through unbonding — the eligible set is unchanged at
    import, so no proposer-selection flip)."""
    from types import SimpleNamespace
    from qrdx.exchange.state_manager import ExchangeStateManager
    from qrdx.exchange.block_processor import flush_validator_lifecycle_deltas

    await _seed_active(db, "0xPQleaver")
    mgr = ExchangeStateManager()
    mgr.begin_block(1, 0.0)
    res = mgr._op_stake_exit(SimpleNamespace(sender="0xPQleaver", nonce=0, params={}))
    assert res.success and res.data["status"] == "exiting"
    assert mgr.validator_lifecycle_ops() == [{"type": "exit", "address": "0xPQleaver"}]

    await flush_validator_lifecycle_deltas(db, mgr)
    await db.connection.commit()
    row = await _status(db, "0xPQleaver")
    assert row[0] == "exiting"


async def test_stake_exit_noop_when_not_active(db):
    """Exit only affects an ACTIVE validator (you can only exit a validator you hold);
    a pending/unknown address is a harmless no-op."""
    from types import SimpleNamespace
    from qrdx.exchange.state_manager import ExchangeStateManager
    from qrdx.exchange.block_processor import flush_validator_lifecycle_deltas

    await db.register_pending_validator("0xPend", "pk", Decimal("100000"), activation_epoch=None)
    await db.connection.commit()
    mgr = ExchangeStateManager()
    mgr.begin_block(1, 0.0)
    mgr._op_stake_exit(SimpleNamespace(sender="0xPend", nonce=0, params={}))
    await flush_validator_lifecycle_deltas(db, mgr)
    await db.connection.commit()
    assert (await _status(db, "0xPend"))[0] == "pending"  # unchanged


async def test_exiting_completes_at_finalized_exit_epoch(db):
    """Full exit flow: active → (flush) exiting → (epoch loop schedules exit_epoch) →
    at the finalized exit_epoch the validator is removed (status 'exited'). The
    eligibility-removing transition happens only at the scheduled epoch."""
    await _seed_active(db, "0xLeave")
    assert await db.mark_validator_exiting("0xLeave") is True
    await db.connection.commit()
    assert (await _status(db, "0xLeave"))[0] == "exiting"

    # Epoch loop assigns exit_epoch = E + UNBONDING (here UNBONDING small via the call).
    await db.schedule_pending_exits(exit_epoch=3)
    await db.connection.commit()
    c = await db.connection.execute("SELECT exit_epoch FROM validators WHERE address='0xLeave'")
    assert (await c.fetchone())[0] == 3  # exit_epoch now scheduled

    # Before exit_epoch: not due.
    assert await db.get_validators_to_exit(2) == []
    await db.apply_epoch_validator_updates({}, {}, [], [], 2, Decimal("1000000"), enforce=True)
    await db.connection.commit()
    assert (await _status(db, "0xLeave"))[0] == "exiting"

    # At exit_epoch: due → removed from the active set.
    exited = await db.get_validators_to_exit(3)
    assert exited == ["0xLeave"]
    await db.apply_epoch_validator_updates({}, {}, [], exited, 3, Decimal("1000000"), enforce=True)
    await db.connection.commit()
    assert (await _status(db, "0xLeave"))[0] == "exited"


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
