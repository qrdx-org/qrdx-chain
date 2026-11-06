"""
Validator membership: what a STAKE_DEPOSIT / STAKE_EXIT records, and what block application
logs for the validator set (qrdx/validator/epoch_state.py) to read.

The exchange records an operation only if it executed; ``flush_validator_lifecycle_deltas``
logs those against the carrying block — a deposit in ``validator_deposits``, an exit in
``validator_exits`` with the exit epoch the block's epoch implies. The schedule itself
(activation after ACTIVATION_DELAY_EPOCHS, unbonding, a pending exit leaving at once) is the
epoch transition's: tests/test_epoch_state.py.
"""

import os
import tempfile
from decimal import Decimal
from types import SimpleNamespace

import pytest

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.exchange.block_processor import flush_validator_lifecycle_deltas
from qrdx.exchange.state_manager import ExchangeStateManager


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


async def _deposits(db):
    cur = await db.connection.execute(
        "SELECT block_height, address, public_key, stake FROM validator_deposits ORDER BY id")
    return [tuple(r) for r in await cur.fetchall()]


async def _exits(db):
    cur = await db.connection.execute(
        "SELECT block_height, address, exit_epoch FROM validator_exits ORDER BY id")
    return [tuple(r) for r in await cur.fetchall()]


def _mgr():
    mgr = ExchangeStateManager()
    mgr.begin_block(1, 0.0)
    return mgr


def test_epoch_from_block_handles_all_import_shapes():
    """The schedule keys off the carrying block's epoch, which the import paths carry in
    different shapes; epoch_from_block must extract it from each."""
    from qrdx.validator.block_verification import epoch_from_block
    from qrdx.constants import SLOTS_PER_EPOCH
    assert epoch_from_block({"epoch": 12}) == 12                                   # parsed block
    assert epoch_from_block({"block_content": str({"slot": 96, "epoch": 12})}) == 12  # wire envelope
    assert epoch_from_block({"block_content": str({"slot": 96})}) == 96 // SLOTS_PER_EPOCH  # slot fallback
    assert epoch_from_block({"foo": 1}) is None
    assert epoch_from_block(None) is None


async def test_an_executed_deposit_is_logged_against_its_block(db):
    mgr = _mgr()
    res = mgr._op_stake_deposit(SimpleNamespace(
        sender="0xPQnewval", nonce=0,
        params={"validator_public_key": "pkNEW", "stake_amount": "100000"}))
    assert res.success and res.data["status"] == "pending"
    assert mgr.validator_lifecycle_ops() == [{"type": "deposit", "address": "0xPQnewval",
                                              "public_key": "pkNEW", "stake": "100000"}]
    await flush_validator_lifecycle_deltas(db, mgr, block_epoch=5, block_height=40)
    await db.connection.commit()
    assert await _deposits(db) == [(40, "0xPQnewval", "pkNEW", "100000")]
    assert await db.get_validators() == []             # the table is only a display copy


async def test_a_refused_deposit_logs_nothing(db):
    mgr = _mgr()
    res = mgr._op_stake_deposit(SimpleNamespace(
        sender="0xz", nonce=0, params={"validator_public_key": "pk", "stake_amount": "0"}))
    assert not res.success and "positive" in res.error
    await flush_validator_lifecycle_deltas(db, mgr, block_epoch=5, block_height=40)
    assert await _deposits(db) == []


async def test_an_exit_is_logged_with_the_exit_epoch_its_block_implies(db):
    from qrdx.constants import UNBONDING_PERIOD_EPOCHS

    mgr = _mgr()
    res = mgr._op_stake_exit(SimpleNamespace(sender="0xPQleaver", nonce=0, params={}))
    assert res.success and res.data["status"] == "exiting"
    assert mgr.validator_lifecycle_ops() == [{"type": "exit", "address": "0xPQleaver"}]
    await flush_validator_lifecycle_deltas(db, mgr, block_epoch=7, block_height=60)
    await db.connection.commit()
    assert await _exits(db) == [(60, "0xPQleaver", 7 + UNBONDING_PERIOD_EPOCHS)]


async def test_nothing_is_logged_without_a_carrying_block(db):
    mgr = _mgr()
    mgr._op_stake_deposit(SimpleNamespace(
        sender="0xPQa", nonce=0, params={"validator_public_key": "pk", "stake_amount": "100000"}))
    mgr._op_stake_exit(SimpleNamespace(sender="0xPQb", nonce=0, params={}))
    await flush_validator_lifecycle_deltas(db, mgr)
    assert await _deposits(db) == [] and await _exits(db) == []


async def test_a_logged_deposit_is_a_validator_of_the_chain(db):
    """The log is what the epoch transition reads: the deposit becomes a pending validator in
    the next epoch's set."""
    from test_epoch_state import Chain
    from qrdx.validator import epoch_state as ES

    chain = Chain(db)
    await chain.genesis()
    await chain.epoch(1, deposits=[("0xPQjoin", "100000")])
    await chain.epoch(2)
    state = await ES.state_at(db, 2)
    assert state["0xPQjoin"].status == "pending" and state["0xPQjoin"].stake == Decimal(100_000)
