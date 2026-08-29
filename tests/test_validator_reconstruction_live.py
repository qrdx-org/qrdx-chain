"""
Validators reorg-reconstruction — LIVE wiring (item 3): the db-backed enumerators + orchestration
that feed the proven core (reconstruct_validators_state) from real stored blocks.

Covers the integration pieces the pure-core test can't: sourcing the genesis set
(db.get_genesis_validators, by activation_epoch=0), enumerating canonical STAKE ops from stored
blocks, and — the reward half — computing per-epoch attesters from attestations carried in
FINALIZED CANONICAL BLOCKS (enumerate_canonical_epoch_attesters) rather than the non-reorg-clean
attestation_votes table, so rewards (hence effective_stake) converge across nodes too.
"""
import os
import tempfile

import pytest

from qrdx.constants import ACTIVATION_DELAY_EPOCHS, SLOTS_PER_EPOCH
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.exchange.transactions import ExchangeTransaction, ExchangeOpType
from qrdx.validator.validator_reconstruction import (
    enumerate_canonical_validator_ops, enumerate_canonical_epoch_attesters,
    reconstruct_validators_live,
)

G1 = "0xPQg1" + "0" * 58
G2 = "0xPQg2" + "0" * 58
V = "0xPQv1" + "0" * 58
DEP_EPOCH = 3
DEP_SLOT = DEP_EPOCH * SLOTS_PER_EPOCH  # 96 → epoch 3
V_ACT = DEP_EPOCH + ACTIVATION_DELAY_EPOCHS
FINALIZED = 8


async def _db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return await DatabaseSQLite.create(path), path


async def _seed_genesis(db):
    for a in (G1, G2):
        await db.connection.execute(
            "INSERT INTO validators (address, public_key, stake, effective_stake, status, "
            "activation_epoch) VALUES (?, 'pk', '100000', '100000', 'active', 0)", (a,))
    await db.connection.commit()


def _att(validator, target):
    return {"slot": target * SLOTS_PER_EPOCH, "epoch": target, "block_hash": "bh",
            "validator_address": validator, "validator_index": 0, "signature": "",
            "source_epoch": max(0, target - 1), "target_epoch": target,
            "included_in_block": None, "created_at": "2020-01-01T00:00:00"}


def _deposit_tx():
    return ExchangeTransaction(
        op_type=ExchangeOpType.STAKE_DEPOSIT, sender=V, nonce=0,
        params={"validator_public_key": "vv", "stake_amount": "50000"})


async def _store_block(db, height, slot, attestations=None, exchange_txs=None):
    bh = f"blk{height:04d}"
    content = repr({"slot": slot, "height": height, "attestations": attestations or []})
    await db.connection.execute(
        "INSERT INTO blocks (block_hash, block_height, content, timestamp) VALUES (?, ?, ?, 0)",
        (bh, height, content))
    if exchange_txs:
        await db.add_block_exchange_txs(bh, [t.to_dict() for t in exchange_txs])
    await db.connection.commit()
    return bh


async def _build_chain(db):
    """One block per epoch 0..FINALIZED (height=epoch, slot=epoch*SPE); each carries that epoch's
    attestations (G1/G2 always, V once active at V_ACT). The deposit rides the epoch-3 block."""
    await _seed_genesis(db)
    for e in range(FINALIZED + 1):
        atts = [_att(G1, e), _att(G2, e)] + ([_att(V, e)] if e >= V_ACT else [])
        ex = [_deposit_tx()] if e == DEP_EPOCH else None
        await _store_block(db, height=e, slot=e * SLOTS_PER_EPOCH, attestations=atts, exchange_txs=ex)


async def _vsnapshot(db):
    c = await db.connection.execute(
        "SELECT address, status, activation_epoch, exit_epoch, stake, effective_stake, "
        "total_rewards, total_slashed FROM validators ORDER BY address")
    return {r[0]: tuple(r[1:]) for r in await c.fetchall()}


@pytest.mark.asyncio
async def test_get_genesis_validators_excludes_deposited():
    db, path = await _db()
    try:
        await _seed_genesis(db)
        await db.register_pending_validator(V, "vv", "50000", activation_epoch=V_ACT)
        await db.connection.commit()
        g = await db.get_genesis_validators()
        assert {x["address"] for x in g} == {G1, G2}
        assert all(x["stake"] == "100000" for x in g)
    finally:
        await db.connection.close()
        os.remove(path)


@pytest.mark.asyncio
async def test_enumerate_canonical_ops_reads_epoch_and_deposit():
    db, path = await _db()
    try:
        await _store_block(db, 0, slot=0)
        await _store_block(db, DEP_EPOCH, slot=DEP_SLOT, exchange_txs=[_deposit_tx()])
        ops = await enumerate_canonical_validator_ops(db)
        assert len(ops) == 1
        op = ops[0]
        assert op["type"] == "deposit" and op["address"] == V and op["stake"] == "50000"
        assert op["epoch"] == DEP_EPOCH and op["public_key"] == "vv"
    finally:
        await db.connection.close()
        os.remove(path)


@pytest.mark.asyncio
async def test_canonical_attesters_bounded_by_finalized_and_ignore_attestation_votes():
    """THE reward-determinism fix: attesters come from FINALIZED canonical blocks, not the
    (non-reorg-clean) attestation_votes table. Two DBs with the SAME canonical blocks but a
    DIVERGENT attestation_votes row must yield IDENTICAL attester sets — and blocks carried in
    epochs beyond `finalized` are excluded."""
    a, pa = await _db()
    b, pb = await _db()
    try:
        await _build_chain(a)
        await _build_chain(b)
        # Divergent attestation_votes on B (the exact node2-outlier shape) — must be IGNORED.
        await b.record_attestation_vote(G1, target_epoch=0, source_epoch=0, slot=0, block_hash="x")
        await b.record_attestation_vote(V, target_epoch=0, source_epoch=0, slot=0, block_hash="x")
        await b.connection.commit()

        ea = await enumerate_canonical_epoch_attesters(a, FINALIZED)
        eb = await enumerate_canonical_epoch_attesters(b, FINALIZED)
        assert {e: sorted(v) for e, v in ea.items()} == {e: sorted(v) for e, v in eb.items()}
        assert sorted(ea[0]) == sorted([G1, G2])          # V not attesting at epoch 0
        assert sorted(ea[V_ACT]) == sorted([G1, G2, V])   # V attests once active
        # Bound: asking for finalized=2 excludes attestations carried in epoch-3+ blocks.
        e2 = await enumerate_canonical_epoch_attesters(a, 2)
        assert set(e2.keys()) == {0, 1, 2}
    finally:
        for db, p in ((a, pa), (b, pb)):
            await db.connection.close()
            os.remove(p)


@pytest.mark.asyncio
async def test_reconstruct_live_converges_incl_rewards_across_divergent_vote_tables():
    """End-to-end: two nodes with identical canonical blocks but DIVERGENT attestation_votes
    reconstruct to a BYTE-IDENTICAL validators table (schedule AND reward-driven effective_stake) —
    the full-table convergence the attestation_votes path could not give."""
    a, pa = await _db()
    b, pb = await _db()
    try:
        await _build_chain(a)
        await _build_chain(b)
        await b.record_attestation_vote(V, target_epoch=0, source_epoch=0, slot=0, block_hash="x")
        # Also give B a divergent live incremental state to heal.
        await b.register_pending_validator(V, "vv", "50000", activation_epoch=2)
        await b.connection.commit()

        await reconstruct_validators_live(a, FINALIZED)
        await reconstruct_validators_live(b, FINALIZED)

        snap_a, snap_b = await _vsnapshot(a), await _vsnapshot(b)
        assert snap_a == snap_b                              # full-table byte-identical
        assert snap_a[V][0] == "active" and snap_a[V][1] == V_ACT and snap_a[V][3] == "50000"
        assert snap_a[G1] == snap_a[G2]                      # symmetric genesis validators agree
    finally:
        for db, p in ((a, pa), (b, pb)):
            await db.connection.close()
            os.remove(p)


@pytest.mark.asyncio
async def test_reconstruct_progression_matches_single_pass():
    """The epoch loop reconstructs at each finalized epoch as finality advances. Stepping through
    (reconstruct at 5, then 8) must yield the SAME state as a single reconstruction at 8."""
    stepped, ps = await _db()
    single, pg = await _db()
    try:
        await _build_chain(stepped)
        await _build_chain(single)
        await reconstruct_validators_live(stepped, 5)
        await reconstruct_validators_live(stepped, FINALIZED)
        await reconstruct_validators_live(single, FINALIZED)
        assert await _vsnapshot(stepped) == await _vsnapshot(single)
    finally:
        for db, p in ((stepped, ps), (single, pg)):
            await db.connection.close()
            os.remove(p)
