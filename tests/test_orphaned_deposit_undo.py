"""
A validator registration must not outlive the block that paid for it.

The ``validators`` table is not reconstructed from the canonical chain
(``_ENFORCE_VALIDATOR_RECONSTRUCTION`` is off — enabling it diverged on
reconstruction↔epoch-loop composition). So when a reorg orphans a block containing a
``STAKE_DEPOSIT``:

  * the derived-state rebuild correctly does NOT re-apply that deposit's stake debit
    (the deposit is no longer canonical), but
  * the ``validators`` row would persist — leaving a validator holding the
    ``effective_stake`` that weights proposer selection and fork-choice attesting
    weight, with none of the funds locked.

That reopens the stake-enforcement guarantee to anyone who can get a block orphaned. The
fix reverses the *logged* deposits above the new tip exactly, rather than recomputing the
table, which is what lets it be safe while full reconstruction stays gated off.

The properties that make it safe, all pinned below:
  * a deposit that CREATED a validator → the validator is removed;
  * a deposit that TOPPED UP one → exactly that increment is subtracted;
  * **genesis validators are never touched** (they have no deposit-log rows);
  * deposits at or below the new tip survive;
  * it is idempotent and order-correct for create-then-top-up sequences.
"""
import os
import tempfile
from decimal import Decimal

import pytest

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


async def _validators(db):
    return {r["address"]: r for r in await db.get_validators()}


async def _deposit_log(db):
    cur = await db.connection.execute(
        "SELECT block_height, address, stake, created_new FROM validator_deposits "
        "ORDER BY id")
    return list(await cur.fetchall())


def test_the_gate_is_on():
    from qrdx.node import main as node_main
    assert node_main._ENFORCE_DEPOSIT_REORG_UNDO is True, (
        "orphaned-deposit undo must stay ON — otherwise a validator keeps stake weight "
        "after the deposit that paid for it was orphaned")


# ── Reversal of an orphaned deposit ────────────────────────────────────────

async def test_an_orphaned_deposit_removes_the_validator():
    db = await _db()
    try:
        joiner = pq("orphaned-joiner")
        await db.register_pending_validator(
            joiner, "ab" * 100, STAKE, activation_epoch=2, block_height=10)
        await db.connection.commit()
        assert joiner in await _validators(db)

        # Reorg rolls the chain back to height 9 — block 10 is orphaned.
        res = await db.undo_validator_deposits_above(9)
        await db.connection.commit()

        assert res == {"reversed": 1, "removed": 1, "reduced": 0}
        assert joiner not in await _validators(db), (
            "an orphaned deposit left its validator registered")
        assert await _deposit_log(db) == [], "the reversed deposit stayed in the log"
    finally:
        await _close(db)


async def test_a_deposit_at_or_below_the_new_tip_survives():
    db = await _db()
    try:
        keeper = pq("canonical-joiner")
        orphan = pq("orphaned-joiner-2")
        await db.register_pending_validator(keeper, "aa" * 100, STAKE, block_height=5)
        await db.register_pending_validator(orphan, "bb" * 100, STAKE, block_height=11)
        await db.connection.commit()

        res = await db.undo_validator_deposits_above(10)
        await db.connection.commit()

        assert res["removed"] == 1
        vals = await _validators(db)
        assert keeper in vals, "a canonical deposit was wrongly reversed"
        assert orphan not in vals
        # Only the orphaned log row is consumed.
        assert [r[0] for r in await _deposit_log(db)] == [5]
    finally:
        await _close(db)


async def test_an_orphaned_top_up_subtracts_exactly_its_increment():
    """
    ``register_pending_validator`` is ADDITIVE, so a top-up can only be undone if its
    own increment is known — which is why the log records each deposit individually
    rather than one height per validator.
    """
    db = await _db()
    try:
        staker = pq("topping-up")
        await db.register_pending_validator(staker, "aa" * 100, STAKE, block_height=5)
        await db.register_pending_validator(staker, "aa" * 100, Decimal("50000"),
                                            block_height=12)
        await db.connection.commit()
        row = (await _validators(db))[staker]
        assert Decimal(str(row["stake"])) == STAKE + Decimal("50000")

        res = await db.undo_validator_deposits_above(10)
        await db.connection.commit()

        assert res == {"reversed": 1, "removed": 0, "reduced": 1}
        row = (await _validators(db))[staker]
        assert Decimal(str(row["stake"])) == STAKE, "top-up not reversed exactly"
        assert Decimal(str(row["effective_stake"])) == STAKE
    finally:
        await _close(db)


async def test_a_create_then_top_up_both_orphaned_removes_the_validator():
    """Unwinds newest-first, so the create is reversed last and the row goes away."""
    db = await _db()
    try:
        staker = pq("create-then-topup")
        await db.register_pending_validator(staker, "aa" * 100, STAKE, block_height=11)
        await db.register_pending_validator(staker, "aa" * 100, Decimal("50000"),
                                            block_height=12)
        await db.connection.commit()

        res = await db.undo_validator_deposits_above(10)
        await db.connection.commit()

        assert res["reversed"] == 2
        assert staker not in await _validators(db)
        assert await _deposit_log(db) == []
    finally:
        await _close(db)


# ── Genesis validators must be untouchable ─────────────────────────────────

async def test_genesis_validators_are_never_reversed():
    """
    The single most important safety property: the undo can only remove what a deposit
    created. Removing genesis validators would empty the validator set and halt the
    chain. They have no deposit-log rows, so they are structurally out of reach.
    """
    db = await _db()
    try:
        genesis = [pq(f"genesis-validator-{i}") for i in range(3)]
        for addr in genesis:
            await db.connection.execute(
                "INSERT INTO validators (address, public_key, stake, effective_stake, "
                "status, activation_epoch) VALUES (?, ?, ?, ?, 'active', 0)",
                (addr, "cc" * 100, str(STAKE), str(STAKE)))
        joiner = pq("late-joiner")
        await db.register_pending_validator(joiner, "dd" * 100, STAKE, block_height=50)
        await db.connection.commit()
        assert len(await _validators(db)) == 4

        # Roll back to genesis — far below every height.
        res = await db.undo_validator_deposits_above(0)
        await db.connection.commit()

        assert res["removed"] == 1
        vals = await _validators(db)
        assert set(vals) == set(genesis), "a genesis validator was reversed"
        for addr in genesis:
            assert Decimal(str(vals[addr]["stake"])) == STAKE
            assert vals[addr]["status"] == "active"
    finally:
        await _close(db)


async def test_a_validator_with_no_deposit_log_row_is_untouched():
    """Belt and braces: a row inserted outside the deposit path stays put."""
    db = await _db()
    try:
        manual = pq("manually-inserted")
        await db.connection.execute(
            "INSERT INTO validators (address, public_key, stake, effective_stake, status) "
            "VALUES (?, ?, ?, ?, 'active')", (manual, "ee" * 100, "1", "1"))
        await db.connection.commit()
        res = await db.undo_validator_deposits_above(0)
        assert res["reversed"] == 0
        assert manual in await _validators(db)
    finally:
        await _close(db)


# ── Shape of the operation ─────────────────────────────────────────────────

async def test_undo_is_a_no_op_when_nothing_was_orphaned():
    db = await _db()
    try:
        await db.register_pending_validator(pq("safe"), "aa" * 100, STAKE, block_height=3)
        await db.connection.commit()
        before = await _validators(db)
        assert await db.undo_validator_deposits_above(100) == {
            "reversed": 0, "removed": 0, "reduced": 0}
        assert await _validators(db) == before
    finally:
        await _close(db)


async def test_undo_is_idempotent():
    """A second rollback to the same tip must not double-subtract."""
    db = await _db()
    try:
        staker = pq("idempotent-staker")
        await db.register_pending_validator(staker, "aa" * 100, STAKE, block_height=5)
        await db.register_pending_validator(staker, "aa" * 100, Decimal("50000"),
                                            block_height=12)
        await db.connection.commit()

        await db.undo_validator_deposits_above(10)
        await db.connection.commit()
        once = Decimal(str((await _validators(db))[staker]["stake"]))

        assert await db.undo_validator_deposits_above(10) == {
            "reversed": 0, "removed": 0, "reduced": 0}
        await db.connection.commit()
        assert Decimal(str((await _validators(db))[staker]["stake"])) == once == STAKE
    finally:
        await _close(db)


async def test_deposits_are_logged_by_every_registration_that_names_its_block():
    db = await _db()
    try:
        a, b = pq("logged-a"), pq("logged-b")
        assert await db.register_pending_validator(a, "aa" * 100, STAKE, block_height=7) is True
        assert await db.register_pending_validator(b, "bb" * 100, STAKE, block_height=7) is True
        # A repeat deposit reports "not new" but is still logged as its own increment.
        assert await db.register_pending_validator(a, "aa" * 100, STAKE, block_height=8) is False
        await db.connection.commit()

        log = await _deposit_log(db)
        assert [(r[0], r[3]) for r in log] == [(7, 1), (7, 1), (8, 0)]
    finally:
        await _close(db)


async def test_a_registration_without_a_block_height_is_not_logged():
    """
    Legacy/omitted callers stay un-reversible rather than being logged at a wrong
    height, which would reverse the wrong thing. Every consensus path passes the height.
    """
    db = await _db()
    try:
        await db.register_pending_validator(pq("unlogged"), "aa" * 100, STAKE)
        await db.connection.commit()
        assert await _deposit_log(db) == []
    finally:
        await _close(db)


# ── The end-to-end guarantee ───────────────────────────────────────────────

async def test_orphaned_deposit_loses_both_the_debit_and_the_stake_weight():
    """
    The property that actually matters: after a reorg orphans the deposit, the staker's
    balance is restored by the rebuild AND the validator no longer carries stake weight.
    Before the fix the balance came back while the weight stayed — stake-weighted
    influence with nothing locked.
    """
    db = await _db()
    try:
        staker = pq("end-to-end-staker")

        # Deposit: balance debited, validator registered at height 10.
        await db.apply_account_balance_delta(staker, Decimal("500000"))
        await db.apply_account_balance_delta(staker, -STAKE)
        await db.register_pending_validator(
            staker, "aa" * 100, STAKE, activation_epoch=2, block_height=10)
        await db.connection.commit()
        assert await db.get_address_balance(staker) == Decimal("500000") - STAKE
        assert staker in await _validators(db)

        # Reorg to height 9: the rebuild reseeds account_state from genesis (modelled
        # here as restoring the balance, since the deposit is no longer canonical)...
        await db.apply_account_balance_delta(staker, STAKE)
        # ...and the undo reverses the registration.
        await db.undo_validator_deposits_above(9)
        await db.connection.commit()

        assert await db.get_address_balance(staker) == Decimal("500000")
        assert staker not in await _validators(db), (
            "stake weight survived the orphaning of the deposit that paid for it")
    finally:
        await _close(db)


# ── The production wiring, not just the DB primitive ───────────────────────

async def test_the_real_rollback_hook_reverses_orphaned_deposits():
    """
    Exercises `_rebuild_derived_state_after_rollback` — the actual function both the
    longest-chain reorg and the equal-height tie-break call after `db.remove_blocks(...)`
    — rather than only the DB primitive. This is what proves the undo is *wired*, and
    that it derives the right tip from the rolled-back chain.

    Worth having because a fault-injecting soak does not cover it: reorgs there are
    shallow tip reorgs (height spread ~6), so a deposit block hundreds of blocks below
    the tip is never rolled back. The soak shows the undo does not MISFIRE across many
    real reorgs; this shows it FIRES on a deep one.
    """
    from qrdx.node import main as node_main

    db = await _db()
    try:
        # A short chain, with a deposit carried by its last block.
        for h in range(4):
            await db.add_block(block_hash=f"{h:064x}", block_height=h, block_content="",
                               validator_address=pq("proposer"),
                               timestamp=1_700_000_000 + h)
        joiner = pq("deep-reorg-joiner")
        survivor = pq("below-fork-joiner")
        await db.register_pending_validator(survivor, "aa" * 100, STAKE, block_height=1)
        await db.register_pending_validator(joiner, "bb" * 100, STAKE, block_height=3)
        await db.connection.commit()
        assert {survivor, joiner} <= set(await _validators(db))

        # Roll back to height 1 — block 3 (and its deposit) is orphaned.
        await db.remove_blocks(2)
        await db.connection.commit()
        assert (await db.get_next_block_id()) - 1 == 1, "rollback did not reach height 1"

        # Drive the REAL hook against this DB.
        original_db = node_main.db
        original_sm = node_main.EVM_STATE_MANAGER
        node_main.db = db
        node_main.EVM_STATE_MANAGER = None      # take the non-EVM reseed branch
        try:
            await node_main._rebuild_derived_state_after_rollback()
        finally:
            node_main.db = original_db
            node_main.EVM_STATE_MANAGER = original_sm

        vals = await _validators(db)
        assert joiner not in vals, (
            "the production rollback hook did not reverse the orphaned deposit")
        assert survivor in vals, (
            "the hook reversed a deposit from a block BELOW the fork point")
        assert [r[0] for r in await _deposit_log(db)] == [1]
    finally:
        await _close(db)
