"""
Validators reorg-reconstruction — LIVE wiring (item 3): the db-backed enumerators + orchestration
that feed the proven core (reconstruct_validators_state) from real stored blocks.

Covers the integration pieces the pure-core test can't: sourcing the genesis set
(db.get_genesis_validators, by activation_epoch=0), enumerating canonical STAKE ops from stored
blocks (epoch pulled from the block's `content` repr; tx decoded from the exchange section), and
the end-to-end reconstruct_validators_live producing the canonical validators state.
"""
import os
import tempfile

import pytest

from qrdx.constants import ACTIVATION_DELAY_EPOCHS, SLOTS_PER_EPOCH
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.exchange.transactions import ExchangeTransaction, ExchangeOpType
from qrdx.validator.validator_reconstruction import (
    enumerate_canonical_validator_ops, reconstruct_validators_live,
)


async def _vsnapshot(db):
    c = await db.connection.execute(
        "SELECT address, status, activation_epoch, exit_epoch, stake, effective_stake, "
        "total_rewards, total_slashed FROM validators ORDER BY address")
    return {r[0]: tuple(r[1:]) for r in await c.fetchall()}

G1 = "0xPQg1" + "0" * 58
G2 = "0xPQg2" + "0" * 58
V = "0xPQv1" + "0" * 58
DEP_EPOCH = 3
DEP_SLOT = DEP_EPOCH * SLOTS_PER_EPOCH  # 96 → epoch 3
FINALIZED = 8  # V activates at 3+ACTIVATION_DELAY_EPOCHS = 7, active by 8


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


async def _store_block(db, height, slot, exchange_txs=None):
    bh = f"blk{height:04d}"
    content = repr({"slot": slot, "height": height})
    await db.connection.execute(
        "INSERT INTO blocks (block_hash, block_height, content, timestamp) VALUES (?, ?, ?, 0)",
        (bh, height, content))
    if exchange_txs:
        await db.add_block_exchange_txs(bh, [t.to_dict() for t in exchange_txs])
    await db.connection.commit()
    return bh


def _deposit_tx():
    return ExchangeTransaction(
        op_type=ExchangeOpType.STAKE_DEPOSIT, sender=V, nonce=0,
        params={"validator_public_key": "vv", "stake_amount": "50000"})


async def _seed_attesters(db):
    """G1/G2 attest every epoch; V from its canonical activation (epoch 7)."""
    for e in range(FINALIZED + 1):
        voters = [G1, G2] + ([V] if e >= DEP_EPOCH + ACTIVATION_DELAY_EPOCHS else [])
        for v in voters:
            await db.record_attestation_vote(v, target_epoch=e, source_epoch=max(0, e - 1),
                                             slot=e * SLOTS_PER_EPOCH, block_hash="bh")
    await db.connection.commit()


@pytest.mark.asyncio
async def test_get_genesis_validators_excludes_deposited():
    db, path = await _db()
    try:
        await _seed_genesis(db)
        # A deposited validator (pending, activation_epoch = block_epoch+DELAY > 0) must be excluded.
        await db.register_pending_validator(V, "vv", "50000", activation_epoch=DEP_EPOCH + ACTIVATION_DELAY_EPOCHS)
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
        await _store_block(db, 1, slot=DEP_SLOT, exchange_txs=[_deposit_tx()])
        ops = await enumerate_canonical_validator_ops(db)
        assert len(ops) == 1
        op = ops[0]
        assert op["type"] == "deposit" and op["address"] == V and op["stake"] == "50000"
        assert op["epoch"] == DEP_EPOCH          # pulled from the block's content slot
        assert op["public_key"] == "vv"
    finally:
        await db.connection.close()
        os.remove(path)


@pytest.mark.asyncio
async def test_reconstruct_live_end_to_end_produces_canonical_state():
    db, path = await _db()
    try:
        await _seed_genesis(db)
        await _store_block(db, 0, slot=0)
        await _store_block(db, 1, slot=DEP_SLOT, exchange_txs=[_deposit_tx()])
        await _seed_attesters(db)

        # Corrupt the deposited validator's live state to mimic a divergent import history
        # (frozen early activation + double-counted stake) — reconstruction must heal it.
        await db.register_pending_validator(V, "vv", "50000", activation_epoch=2)  # wrong: too early
        await db.register_pending_validator(V, "vv", "50000", activation_epoch=2)  # top-up double
        await db.connection.commit()

        await reconstruct_validators_live(db, FINALIZED)

        c = await db.connection.execute(
            "SELECT status, activation_epoch, stake FROM validators WHERE address = ?", (V,))
        status, act, stake = await c.fetchone()
        assert status == "active"
        assert act == DEP_EPOCH + ACTIVATION_DELAY_EPOCHS   # 7, canonical (not the frozen 2)
        assert stake == "50000"                              # single, not double-counted
        # genesis still present + active
        c2 = await db.connection.execute("SELECT COUNT(*) FROM validators WHERE status='active'")
        assert (await c2.fetchone())[0] == 3
    finally:
        await db.connection.close()
        os.remove(path)


@pytest.mark.asyncio
async def test_reconstruct_progression_matches_single_pass():
    """The epoch loop reconstructs at each finalized epoch as finality advances. Stepping through
    (reconstruct at 5, then 8) must yield the SAME state as a single reconstruction at 8 — the
    single-writer progression is stable + import-history-independent (the composition-fix property
    that diverged when reconstruction and the incremental loop were BOTH writers)."""
    async def _build():
        db, path = await _db()
        await _seed_genesis(db)
        await _store_block(db, 0, slot=0)
        await _store_block(db, 1, slot=DEP_SLOT, exchange_txs=[_deposit_tx()])
        await _seed_attesters(db)
        return db, path

    stepped, ps = await _build()
    single, pg = await _build()
    try:
        # Stepped node: as the loop would, reconstruct at successive finalized epochs.
        await reconstruct_validators_live(stepped, 5)   # V still pending (activates at 7)
        await reconstruct_validators_live(stepped, 8)   # V now active
        # Single-pass node: reconstruct once at 8.
        await reconstruct_validators_live(single, 8)
        assert await _vsnapshot(stepped) == await _vsnapshot(single)
    finally:
        for db, p in ((stepped, ps), (single, pg)):
            await db.connection.close()
            os.remove(p)
