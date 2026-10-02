"""
A validator that has lost most of its stake must lose its slot.

There was no *maintenance* stake threshold at all — `MIN_VALIDATOR_STAKE` gates
**activation** only. So under sustained inactivity penalties a validator's
`effective_stake` could decay toward zero while it kept full stake-weighted influence over
proposer selection and fork-choice attesting weight.

The threshold is deliberately **not** the activation floor. Attestation penalties push
`effective_stake` a little below it during normal operation (observed live: 99,840 against
a 100,000 floor), so ejecting there would churn the set on ordinary missed attestations —
on a small validator set that means repeatedly losing proposers, and at worst emptying the
set. `VALIDATOR_EJECTION_STAKE` is half the activation floor, mirroring Ethereum's
16 ETH ejection vs 32 ETH activation.

Pinned here: the hysteresis, the exit-through-unbonding behaviour, determinism, and the
liveness backstop that stops a mass ejection from halting the chain.
"""
import os
import tempfile
from decimal import Decimal

import pytest

from qrdx.constants import (
    MIN_VALIDATOR_STAKE,
    UNBONDING_PERIOD_EPOCHS,
    VALIDATOR_EJECTION_STAKE,
)
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator.epoch_loop import (
    _MIN_ACTIVE_AFTER_EJECTION,
    _ENFORCE_STAKE_FLOOR_EJECTION,
    _eject_validators_below_stake_floor,
)

from pq_addrs import pq


async def _db():
    return await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))


async def _close(db):
    path = db.db_path
    await db.close()
    os.remove(path)


async def _add(db, address, effective, status="active"):
    await db.connection.execute(
        "INSERT INTO validators (address, public_key, stake, effective_stake, status, "
        "activation_epoch) VALUES (?, ?, ?, ?, ?, 0)",
        (address, "ab" * 100, str(MIN_VALIDATOR_STAKE), str(effective), status))


async def _status(db, address):
    cur = await db.connection.execute(
        "SELECT status, exit_epoch FROM validators WHERE address = ?", (address,))
    return await cur.fetchone()


async def _healthy_set(db, n=4, effective=None):
    """n comfortably-staked active validators, so the backstop never binds."""
    eff = effective if effective is not None else MIN_VALIDATOR_STAKE
    addrs = [pq(f"healthy-{i}") for i in range(n)]
    for a in addrs:
        await _add(db, a, eff)
    return addrs


# ── Configuration sanity ───────────────────────────────────────────────────

def test_the_gate_is_on():
    assert _ENFORCE_STAKE_FLOOR_EJECTION is True


def test_the_ejection_floor_is_below_the_activation_floor():
    """
    The hysteresis is the whole design. If these were equal, ordinary attestation
    penalties would churn the validator set.
    """
    assert VALIDATOR_EJECTION_STAKE < MIN_VALIDATOR_STAKE
    assert VALIDATOR_EJECTION_STAKE == MIN_VALIDATOR_STAKE / 2


# ── Hysteresis: normal drift must NOT eject ────────────────────────────────

async def test_a_validator_just_below_the_activation_floor_is_kept():
    """
    The live-observed case: 99,840 against a 100,000 activation floor after missing some
    attestations. That is normal operation, not grounds for ejection.
    """
    db = await _db()
    try:
        await _healthy_set(db)
        drifted = pq("drifted-slightly")
        await _add(db, drifted, Decimal("99840.11994400"))
        await db.connection.commit()

        assert await _eject_validators_below_stake_floor(db, epoch=10) == 0
        assert (await _status(db, drifted))["status"] == "active"
    finally:
        await _close(db)


@pytest.mark.parametrize("effective", ["99999", "75000", "50000", "50000.00000001"])
async def test_stakes_at_or_above_the_ejection_floor_are_kept(effective):
    db = await _db()
    try:
        await _healthy_set(db)
        v = pq(f"at-floor-{effective}")
        await _add(db, v, Decimal(effective))
        await db.connection.commit()
        assert await _eject_validators_below_stake_floor(db, epoch=1) == 0
        assert (await _status(db, v))["status"] == "active"
    finally:
        await _close(db)


# ── Below the floor: ejected, through unbonding ────────────────────────────

@pytest.mark.parametrize("effective", ["49999.99999999", "40000", "1000", "0"])
async def test_a_validator_below_the_ejection_floor_is_ejected(effective):
    db = await _db()
    try:
        await _healthy_set(db)
        decayed = pq(f"decayed-{effective}")
        await _add(db, decayed, Decimal(effective))
        await db.connection.commit()

        assert await _eject_validators_below_stake_floor(db, epoch=20) == 1
        row = await _status(db, decayed)
        assert row["status"] == "exiting", "a decayed validator kept its active slot"
    finally:
        await _close(db)


async def test_ejection_leaves_through_unbonding_not_instantly():
    """
    It exits the way a voluntary STAKE_EXIT does — staying eligible until its
    deterministic finalized exit epoch — because the validator was inactive, not slashed.
    Removing it mid-epoch would change the eligible set without a converged chain point.
    """
    db = await _db()
    try:
        await _healthy_set(db)
        decayed = pq("unbonding-exit")
        await _add(db, decayed, Decimal("10000"))
        await db.connection.commit()

        await _eject_validators_below_stake_floor(db, epoch=20)
        row = await _status(db, decayed)
        assert row["status"] == "exiting"
        assert row["exit_epoch"] == 20 + UNBONDING_PERIOD_EPOCHS
        # Still selected for exit only when that epoch arrives.
        assert await db.get_validators_to_exit(20) == []
        assert await db.get_validators_to_exit(20 + UNBONDING_PERIOD_EPOCHS) == [decayed]
    finally:
        await _close(db)


async def test_only_active_validators_are_swept():
    """Pending, exiting, exited and slashed rows must be left alone."""
    db = await _db()
    try:
        await _healthy_set(db)
        for status in ("pending", "exiting", "exited", "slashed"):
            await _add(db, pq(f"low-{status}"), Decimal("100"), status=status)
        await db.connection.commit()

        assert await _eject_validators_below_stake_floor(db, epoch=5) == 0
        for status in ("pending", "exiting", "exited", "slashed"):
            assert (await _status(db, pq(f"low-{status}")))["status"] == status
    finally:
        await _close(db)


async def test_several_decayed_validators_are_all_ejected_when_there_is_room():
    db = await _db()
    try:
        await _healthy_set(db, n=6)
        decayed = [pq(f"multi-decayed-{i}") for i in range(3)]
        for i, a in enumerate(decayed):
            await _add(db, a, Decimal(1000 * (i + 1)))
        await db.connection.commit()

        assert await _eject_validators_below_stake_floor(db, epoch=7) == 3
        for a in decayed:
            assert (await _status(db, a))["status"] == "exiting"
    finally:
        await _close(db)


# ── The liveness backstop ──────────────────────────────────────────────────

async def test_ejection_is_skipped_rather_than_emptying_the_validator_set():
    """
    The scenario this protects against: every validator has decayed together. Ejecting
    them all would halt the chain, so keeping them is strictly better. Silence here would
    be a halt, so the skip is the correct behaviour, not a missed ejection.
    """
    db = await _db()
    try:
        all_low = [pq(f"all-decayed-{i}") for i in range(3)]
        for a in all_low:
            await _add(db, a, Decimal("100"))
        await db.connection.commit()

        assert await _eject_validators_below_stake_floor(db, epoch=9) == 0
        for a in all_low:
            assert (await _status(db, a))["status"] == "active", (
                "ejecting the whole set would halt the chain")
    finally:
        await _close(db)


async def test_ejection_is_capped_to_keep_the_backstop_intact():
    db = await _db()
    try:
        # 5 active, 4 of them below the floor: only 2 may go (5 - 3).
        healthy = pq("the-one-healthy")
        await _add(db, healthy, MIN_VALIDATOR_STAKE)
        low = [pq(f"capped-{i}") for i in range(4)]
        for i, a in enumerate(low):
            await _add(db, a, Decimal(1000 * (i + 1)))
        await db.connection.commit()

        ejected = await _eject_validators_below_stake_floor(db, epoch=11)
        assert ejected == 5 - _MIN_ACTIVE_AFTER_EJECTION == 2

        cur = await db.connection.execute(
            "SELECT COUNT(*) FROM validators WHERE status = 'active'")
        assert (await cur.fetchone())[0] == _MIN_ACTIVE_AFTER_EJECTION
        # The two LOWEST-staked went, deterministically.
        assert (await _status(db, low[0]))["status"] == "exiting"
        assert (await _status(db, low[1]))["status"] == "exiting"
        assert (await _status(db, low[2]))["status"] == "active"
        assert (await _status(db, healthy))["status"] == "active"
    finally:
        await _close(db)


# ── Determinism ────────────────────────────────────────────────────────────

async def test_two_nodes_eject_the_same_subset_when_the_cap_binds():
    """
    Eligibility is enforced off the validators table, so a capped ejection must pick the
    same subset everywhere — hence the canonical lowest-stake-then-address ordering.
    """
    dbs = [await _db(), await _db()]
    try:
        # Equal stakes force the address tie-break to decide.
        equal = sorted(pq(f"tied-{i}") for i in range(4))
        for db in dbs:
            await _add(db, pq("healthy-anchor"), MIN_VALIDATOR_STAKE)
            for a in equal:
                await _add(db, a, Decimal("1000"))
            await db.connection.commit()

        counts = []
        for db in dbs:
            counts.append(await _eject_validators_below_stake_floor(db, epoch=13))
            await db.connection.commit()

        assert counts[0] == counts[1] == 2
        assert await dbs[0].get_validators_table_hash() == await dbs[1].get_validators_table_hash()
    finally:
        for db in dbs:
            await _close(db)


async def test_the_sweep_is_idempotent():
    db = await _db()
    try:
        await _healthy_set(db)
        decayed = pq("idempotent-decayed")
        await _add(db, decayed, Decimal("500"))
        await db.connection.commit()

        assert await _eject_validators_below_stake_floor(db, epoch=3) == 1
        await db.connection.commit()
        # Already 'exiting' — mark_validator_exiting only touches 'active'.
        assert await _eject_validators_below_stake_floor(db, epoch=4) == 0
        row = await _status(db, decayed)
        assert row["exit_epoch"] == 3 + UNBONDING_PERIOD_EPOCHS, (
            "a second sweep must not reschedule the exit")
    finally:
        await _close(db)


async def test_an_empty_validator_set_is_handled():
    db = await _db()
    try:
        assert await _eject_validators_below_stake_floor(db, epoch=1) == 0
    finally:
        await _close(db)


# ── Reached through the LIVE path ──────────────────────────────────────────
#
# Every test above calls `_eject_validators_below_stake_floor` directly, and they all
# passed while the feature was dead in production: with reconstruction on (the live
# configuration) `epoch_validator_update_loop` rebuilds via `reconstruct_validators_live`
# and never reaches the incremental path where ejection was first placed. A test that
# exercises a function is not a test that the function is reached. These drive the real
# single writer.

async def test_the_reconstruction_walk_ejects_a_decayed_validator():
    from qrdx.validator.validator_reconstruction import reconstruct_validators_state

    db = await _db()
    try:
        healthy = [{"address": pq(f"g-healthy-{i}"), "public_key": "ab" * 100,
                    "stake": str(MIN_VALIDATOR_STAKE)} for i in range(4)]
        decayed = {"address": pq("g-decayed"), "public_key": "cd" * 100, "stake": "10000"}

        await reconstruct_validators_state(
            db, genesis_validators=healthy + [decayed], canonical_ops=[],
            attesters_by_epoch={}, finalized_epoch=2)

        row = await _status(db, decayed["address"])
        assert row["status"] == "exiting", (
            "the reconstruction walk — the live single writer — did not eject a validator "
            "below the floor")
        for v in healthy:
            assert (await _status(db, v["address"]))["status"] == "active"
    finally:
        await _close(db)


async def test_the_walk_respects_the_liveness_backstop():
    from qrdx.validator.validator_reconstruction import reconstruct_validators_state

    db = await _db()
    try:
        all_low = [{"address": pq(f"g-low-{i}"), "public_key": "ab" * 100, "stake": "100"}
                   for i in range(3)]
        await reconstruct_validators_state(
            db, genesis_validators=all_low, canonical_ops=[],
            attesters_by_epoch={}, finalized_epoch=2)
        for v in all_low:
            assert (await _status(db, v["address"]))["status"] == "active"
    finally:
        await _close(db)


async def test_the_walk_is_deterministic_across_rebuilds():
    """The walk replays from genesis every finalized epoch; repeating it must not drift."""
    from qrdx.validator.validator_reconstruction import reconstruct_validators_state

    db = await _db()
    try:
        vals = [{"address": pq(f"g-det-{i}"), "public_key": "ab" * 100,
                 "stake": str(MIN_VALIDATOR_STAKE)} for i in range(4)]
        vals.append({"address": pq("g-det-low"), "public_key": "cd" * 100, "stake": "10000"})
        hashes = []
        for _ in range(3):
            await reconstruct_validators_state(
                db, genesis_validators=vals, canonical_ops=[],
                attesters_by_epoch={}, finalized_epoch=3)
            hashes.append(await db.get_validators_table_hash())
        assert len(set(hashes)) == 1, f"rebuild drifted: {hashes}"
    finally:
        await _close(db)


def test_the_live_loop_takes_the_reconstruction_path():
    """Pins the configuration these tests assume, so a flip is noticed."""
    from qrdx.validator import epoch_loop
    assert epoch_loop._RECONSTRUCT_VALIDATORS is True


def test_the_out_of_block_refund_stays_disabled():
    """
    A refund from the epoch loop credits account_state outside block application, which
    makes the E-D4 root depend on whether each node's async loop has run yet.
    """
    from qrdx.validator import epoch_loop
    assert epoch_loop._ENFORCE_EXIT_REFUND_IN_EPOCH_LOOP is False
