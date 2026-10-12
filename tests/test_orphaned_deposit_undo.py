"""
A deposit must not outlive the block that carried it.

The validator set is computed from the chain and the log of executed stake operations block
application writes (qrdx/validator/epoch_state.py). When a reorg orphans a block carrying a
STAKE_DEPOSIT, the rebuild correctly does not re-apply its stake debit — so its log row must go
too, or the validator would keep stake weight it no longer paid for. (This used to reverse a
registration in the ``validators`` table; that table is now only a display copy.)
"""
import os
import tempfile
from decimal import Decimal

from qrdx.constants import MIN_VALIDATOR_STAKE
from qrdx.database_sqlite import DatabaseSQLite

from pq_addrs import pq

STAKE = MIN_VALIDATOR_STAKE


async def _db():
    return await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))


async def _close(db):
    path = db.db_path
    await db.close()
    os.remove(path)


async def _logged(db):
    cur = await db.connection.execute(
        "SELECT block_height, address, stake FROM validator_deposits ORDER BY id")
    return [tuple(r) for r in await cur.fetchall()]


def test_the_gate_is_on():
    from qrdx.node import main
    assert main._ENFORCE_DEPOSIT_REORG_UNDO is True


async def test_an_orphaned_deposit_leaves_no_log_and_one_below_the_tip_survives():
    db = await _db()
    try:
        a, b = pq("kept"), pq("orphaned")
        await db.log_validator_deposit(a, "aa", STAKE, 5)
        await db.log_validator_deposit(b, "bb", STAKE, 10)
        await db.connection.commit()
        res = await db.undo_validator_deposits_above(9)
        assert res["reversed"] == 1 and await _logged(db) == [(5, a, str(STAKE))]
        again = await db.undo_validator_deposits_above(9)          # idempotent
        assert again["reversed"] == 0 and await _logged(db) == [(5, a, str(STAKE))]
    finally:
        await _close(db)


async def test_an_orphaned_deposit_never_reaches_the_validator_set():
    """End to end: the deposit's block is rolled back and another takes its height; the
    chain-derived set never shows the depositor."""
    from test_epoch_state import Chain, ACTIVATION_DELAY_EPOCHS
    from qrdx.validator import epoch_state as ES

    db = await _db()
    try:
        c = Chain(db)
        await c.genesis()
        await c.epoch(1)
        joiner = pq("orphaned-joiner")
        await c.epoch(2, deposits=[(joiner, str(STAKE * 3))])
        await c.rollback(1)
        c.tag = "b"
        for e in range(2, 4 + ACTIVATION_DELAY_EPOCHS):
            await c.epoch(e)
        state = await ES.state_at(db, 3 + ACTIVATION_DELAY_EPOCHS)
        assert joiner not in state
    finally:
        await _close(db)


async def test_the_real_rollback_hook_drops_orphaned_deposits():
    """``_rebuild_derived_state_after_rollback`` — what every reorg calls after removing the
    blocks — drops the log of the rolled-back heights, deriving the tip from the chain."""
    from qrdx.node import main as node_main

    db = await _db()
    try:
        for h in range(4):
            await db.add_block(block_hash=f"{h:064x}", block_height=h, block_content="",
                               validator_address=pq("proposer"), timestamp=1_700_000_000 + h)
        survivor, joiner = pq("below-fork-joiner"), pq("deep-reorg-joiner")
        await db.log_validator_deposit(survivor, "aa", STAKE, 1)
        await db.log_validator_deposit(joiner, "bb", STAKE, 3)
        await db.connection.commit()
        await db.remove_blocks(2)
        await db.connection.commit()
        original_db, original_sm = node_main.db, node_main.EVM_STATE_MANAGER
        node_main.db, node_main.EVM_STATE_MANAGER = db, None
        try:
            await node_main._rebuild_derived_state_after_rollback()
        finally:
            node_main.db, node_main.EVM_STATE_MANAGER = original_db, original_sm
        assert [r[1] for r in await _logged(db)] == [survivor]
    finally:
        await _close(db)


async def test_the_staker_gets_the_debit_back_and_no_stake_weight():
    """The property that matters: the rebuild restores the balance (modelled here) and the
    deposit no longer counts."""
    db = await _db()
    try:
        staker = pq("end-to-end-staker")
        await db.apply_account_balance_delta(staker, Decimal("500000") - STAKE)
        await db.log_validator_deposit(staker, "aa", STAKE, 10)
        await db.connection.commit()
        await db.apply_account_balance_delta(staker, STAKE)      # the rebuild, modelled
        await db.undo_validator_deposits_above(9)
        await db.connection.commit()
        assert await db.get_address_balance(staker) == Decimal("500000")
        assert await _logged(db) == []
    finally:
        await _close(db)
