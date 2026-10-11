"""
Incremental validator reconstruction ≡ the full rebuild (qrdx/validator/validator_reconstruction.py).

The live loop used to rebuild the validators dynamic state from genesis — re-parsing every block
and replaying every epoch — each time finality advanced, so its cost grew with the chain until
it starved block production. It now resumes from per-epoch snapshots. That is only acceptable if
the result is EXACTLY what the full rebuild yields, in every situation the full rebuild handles:

  * votes included late — a newly finalized block adding an attester to an epoch already
    processed (rewards of that epoch, and everything after, change);
  * slashing evidence recorded late for an old epoch;
  * import-path writes to the validators table between runs (the full rebuild discards them);
  * a chain change below a snapshot;
  * a vote reaching back past the snapshot window (→ a full rebuild);
  * a restart (snapshots persist; the in-memory state does not exist).

Two identical databases receive the same randomized history; after every finality step the
incremental one must equal a full rebuild of the other — every validators row and every
slashing ``processed`` flag.
"""
import os
import random
import tempfile

import pytest

from qrdx import chain_index
from qrdx.constants import ACTIVATION_DELAY_EPOCHS, SLOTS_PER_EPOCH
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.exchange.transactions import ExchangeOpType, ExchangeTransaction
from qrdx.validator import validator_reconstruction as vr

GENESIS = [f"0xPQg{i}" + "0" * 59 for i in range(3)]
JOINERS = [f"0xPQj{i}" + "0" * 59 for i in range(3)]


async def _db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return await DatabaseSQLite.create(path), path


async def _seed(db):
    for a in GENESIS:
        await db.connection.execute(
            "INSERT INTO validators (address, public_key, stake, effective_stake, status, "
            "activation_epoch) VALUES (?, 'pk', '100000', '100000', 'active', 0)",
            (a,),
        )
    await db.connection.commit()


def _att(validator, target):
    return {"slot": target * SLOTS_PER_EPOCH, "epoch": target, "block_hash": "bh",
            "validator_address": validator, "validator_index": 0, "signature": "",
            "source_epoch": max(0, target - 1), "target_epoch": target,
            "included_in_block": None, "created_at": "2020-01-01T00:00:00"}


def _tx(kind, sender, nonce):
    if kind == "deposit":
        return ExchangeTransaction(op_type=ExchangeOpType.STAKE_DEPOSIT, sender=sender, nonce=nonce,
                                   params={"validator_public_key": "pk" + sender[-4:],
                                           "stake_amount": "60000"})
    return ExchangeTransaction(op_type=ExchangeOpType.STAKE_EXIT, sender=sender, nonce=nonce,
                               params={})


class History:
    """A randomized chain, applied identically to both databases."""

    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.blocks = []          # [(height, slot, attestations, txs)]
        self.tag = 0

    def make_block(self, epoch, late_votes=(), height=None):
        height = len(self.blocks) if height is None else height
        slot = epoch * SLOTS_PER_EPOCH + self.rng.randrange(SLOTS_PER_EPOCH)
        voters = [v for v in GENESIS + JOINERS if self.rng.random() < 0.8]
        atts = [_att(v, epoch) for v in voters] + [_att(v, e) for v, e in late_votes]
        txs = []
        if self.rng.random() < 0.25:
            who = self.rng.choice(JOINERS + GENESIS)
            txs.append(_tx(self.rng.choice(["deposit", "deposit", "exit"]), who, height))
        return height, slot, atts, txs


async def _store(db, block, tag):
    height, slot, atts, txs = block
    bh = f"blk{tag}-{height:05d}"
    await db.connection.execute(
        "INSERT INTO blocks (block_hash, block_height, content, timestamp) VALUES (?, ?, ?, 0)",
        (bh, height, repr({"slot": slot, "height": height, "attestations": atts})),
    )
    if txs:
        await db.add_block_exchange_txs(bh, [t.to_dict() for t in txs])
    await db.connection.commit()


async def _truncate(db, height):
    await db.connection.execute("DELETE FROM blocks WHERE block_height >= ?", (height,))
    await db.connection.commit()


async def _state(db):
    c = await db.connection.execute(
        "SELECT address, status, activation_epoch, exit_epoch, stake, effective_stake, "
        "total_rewards, total_slashed, slashed FROM validators ORDER BY address")
    validators = [tuple(r) for r in await c.fetchall()]
    c = await db.connection.execute(
        "SELECT validator_address, slot, condition, processed FROM slashing_events "
        "ORDER BY validator_address, slot")
    return validators, [tuple(r) for r in await c.fetchall()]


async def _slash(db, address, epoch):
    await db.connection.execute(
        "INSERT OR IGNORE INTO slashing_events (validator_address, condition, slot, epoch, evidence) "
        "VALUES (?, 'double_sign', ?, ?, '{}')",
        (address, epoch * SLOTS_PER_EPOCH, epoch),
    )
    await db.connection.commit()


async def _junk_import_write(db, address):
    """What the live import path does between runs: register a validator for a not-yet-final
    block. The full rebuild discards it; so must the incremental path."""
    await db.register_pending_validator(address, "junk", "12345", activation_epoch=999,
                                        block_height=10**6, block_hash="junk")
    await db.connection.commit()


@pytest.mark.parametrize("seed", range(6))
async def test_incremental_equals_full_rebuild_at_every_step(seed, monkeypatch):
    monkeypatch.setattr(vr, "SNAPSHOT_EPOCHS", 6)  # small window: exercises the fallback too
    inc, p1 = await _db()
    full, p2 = await _db()
    h = History(seed)
    try:
        await _seed(inc)
        await _seed(full)
        epoch, finalized = 0, -1
        while epoch < 40:
            # 1–3 blocks per epoch; sometimes votes for an older epoch arrive late.
            for _ in range(h.rng.randint(1, 3)):
                late = []
                if epoch > 2 and h.rng.random() < 0.3:
                    back = h.rng.choice([1, 2, 3, 9])  # 9: further back than the snapshot window
                    late = [(h.rng.choice(GENESIS + JOINERS), max(0, epoch - back))]
                block = h.make_block(epoch, late)
                h.blocks.append(block)
                for db in (inc, full):
                    await _store(db, block, h.tag)
            if h.rng.random() < 0.15 and finalized > 2:
                victim, when = h.rng.choice(GENESIS + JOINERS), h.rng.randrange(finalized)
                for db in (inc, full):
                    await _slash(db, victim, when)
            if h.rng.random() < 0.2:
                await _junk_import_write(inc, h.rng.choice(JOINERS))
            if h.rng.random() < 0.1 and len(h.blocks) > 12:
                # a chain change reaching below recent snapshots: replace the last few blocks
                cut = len(h.blocks) - h.rng.randint(2, 6)
                h.tag += 1
                for db in (inc, full):
                    await _truncate(db, cut)
                rebuilt = [h.make_block(old[1] // SLOTS_PER_EPOCH, height=old[0])
                           for old in h.blocks[cut:]]
                h.blocks[cut:] = rebuilt
                for block in rebuilt:
                    for db in (inc, full):
                        await _store(db, block, h.tag)
            if epoch >= 2 and h.rng.random() < 0.7:
                finalized = min(epoch - 1, finalized + h.rng.randint(0, 3))
                await vr.reconstruct_validators_live(inc, finalized)
                await vr.reconstruct_validators_full(full, finalized)
                assert await _state(inc) == await _state(full), f"seed={seed} finalized={finalized}"
            epoch += 1
    finally:
        for db, p in ((inc, p1), (full, p2)):
            await db.connection.close()
            os.remove(p)


async def test_a_restart_resumes_from_the_persisted_snapshots():
    a, pa = await _db()
    b, pb = await _db()
    h = History(99)
    try:
        await _seed(a)
        await _seed(b)
        for epoch in range(20):
            block = h.make_block(epoch)
            h.blocks.append(block)
            for db in (a, b):
                await _store(db, block, 0)
        await vr.reconstruct_validators_live(a, 10)
        await a.connection.close()
        a = await DatabaseSQLite.create(pa)  # a restart: fresh process state, same file
        await vr.reconstruct_validators_live(a, 18)
        await vr.reconstruct_validators_full(b, 18)
        assert await _state(a) == await _state(b)
    finally:
        for db, p in ((a, pa), (b, pb)):
            await db.connection.close()
            os.remove(p)


async def test_the_cost_of_an_advance_does_not_grow_with_the_chain():
    """Advancing finality by one epoch reads only the new epoch's blocks — not the history."""
    db, path = await _db()
    h = History(7)
    try:
        await _seed(db)
        for epoch in range(60):
            block = h.make_block(epoch)
            h.blocks.append(block)
            await _store(db, block, 0)
        await vr.reconstruct_validators_live(db, 57)
        applied = []
        real = vr._apply_epoch

        async def counting(db_, epoch, ops, attesters):
            applied.append(epoch)
            await real(db_, epoch, ops, attesters)

        vr._apply_epoch = counting
        try:
            await vr.reconstruct_validators_live(db, 58)
        finally:
            vr._apply_epoch = real
        assert applied == [58]
    finally:
        await db.connection.close()
        os.remove(path)


async def test_a_genesis_validators_top_up_is_counted_once_however_often_it_is_rebuilt():
    """The full rebuild used to read its genesis base from the live table, into which a genesis
    validator's own top-up deposit had already been applied — so every rebuild added the deposit
    again, and the stake grew each finalized epoch."""
    db, path = await _db()
    try:
        await _seed(db)
        for epoch in range(8):
            txs = [_tx("deposit", GENESIS[0], 0)] if epoch == 1 else []
            await _store(db, (epoch, epoch * SLOTS_PER_EPOCH, [], txs), 0)
        stakes = []
        for _ in range(3):
            await vr.reconstruct_validators_full(db, 6)
            c = await db.connection.execute("SELECT stake FROM validators WHERE address = ?", (GENESIS[0],))
            stakes.append((await c.fetchone())[0])
        assert stakes == ["160000"] * 3
    finally:
        await db.connection.close()
        os.remove(path)
