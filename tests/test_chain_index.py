"""
The chain index (qrdx/chain_index.py) answers exactly what the per-call walks from genesis did.

Every consumer it replaced kept its walk as the reference: the RANDAO mix, the height before a
slot, the canonical STAKE ops, the per-epoch attesters from finalized blocks, and whether a
validator was slashed on chain. On randomized chains — blocks without reveals, late votes,
stake ops, real double-sign proofs — each answer must equal the walk's, and keep doing so
after reorgs (blocks replaced below the indexed tip) and after a rolled-back transaction.
"""
import os
import random
import tempfile

import pytest

from qrdx import chain_index
from qrdx.constants import SLOTS_PER_EPOCH
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.exchange.transactions import ExchangeOpType, ExchangeTransaction
from qrdx.validator import randao, validator_reconstruction as vr, withdrawals as W
from qrdx.validator.slashing_block import make_double_sign_evidence

from test_slashing_evidence import _signed_header

VALIDATORS = [f"0xPQv{i}" + "0" * 59 for i in range(4)]


class _NoSQL:
    """The same chain without SQL access: consumers fall back to their walks."""

    def __init__(self, db):
        self._db = db

    async def get_next_block_id(self):
        return await self._db.get_next_block_id()

    async def get_block_by_id(self, height):
        return await self._db.get_block_by_id(height)

    async def get_block_exchange_txs(self, block_hash):
        return await self._db.get_block_exchange_txs(block_hash)


@pytest.fixture
async def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database = await DatabaseSQLite.create(path)
    yield database
    await database.connection.close()
    os.remove(path)


@pytest.fixture(scope="module")
def offender_key():
    return PQPrivateKey.generate()


def _evidence(key, slot):
    h1, _ = _signed_header(key, slot=slot, state_root="11" * 32)
    h2, _ = _signed_header(key, slot=slot, state_root="22" * 32)
    return make_double_sign_evidence(h1, h2)


def _att(validator, target):
    return {"slot": target * SLOTS_PER_EPOCH, "epoch": target, "block_hash": "bh",
            "validator_address": validator, "validator_index": 0, "signature": "",
            "source_epoch": max(0, target - 1), "target_epoch": target,
            "included_in_block": None, "created_at": "2020-01-01T00:00:00"}


async def _add(db, rng, height, slot, tag, key):
    epoch = slot // SLOTS_PER_EPOCH
    body = {"number": height, "slot": slot, "epoch": epoch,
            "attestations": [_att(v, max(0, epoch - rng.choice([0, 0, 0, 1, 3])))
                             for v in VALIDATORS if rng.random() < 0.7],
            "slashing_evidence": [_evidence(key, slot)] if rng.random() < 0.05 else []}
    if rng.random() < 0.85:
        body["randao_reveal"] = rng.randbytes(96).hex()
    bh = f"{tag}{height:063x}"[:64]
    await db.add_block(block_hash=bh, block_height=height, block_content=str(body),
                       validator_address=VALIDATORS[0], timestamp=1_700_000_000 + slot)
    if rng.random() < 0.2:
        kind = rng.choice([ExchangeOpType.STAKE_DEPOSIT, ExchangeOpType.STAKE_EXIT])
        params = {"validator_public_key": "pk", "stake_amount": "50000"} if kind == ExchangeOpType.STAKE_DEPOSIT else {}
        tx = ExchangeTransaction(op_type=kind, sender=rng.choice(VALIDATORS), nonce=height, params=params)
        await db.add_block_exchange_txs(bh, [tx.to_dict()])


async def _build(db, rng, n, key, tag="a", start=0, slot0=0):
    slot = slot0
    for h in range(start, start + n):
        slot += rng.randint(1, 3)
        await _add(db, rng, h, slot, tag, key)
    await db.connection.commit()
    return slot


async def _assert_matches_the_walk(db, rng, key):
    walk = _NoSQL(db)
    tip = await db.get_next_block_id() - 1
    for h in sorted({-1, 0, tip, tip + 5} | {rng.randint(0, tip) for _ in range(12)}):
        assert await randao.compute_randao_mix(db, h) == await randao.compute_randao_mix(walk, h), h
    max_slot = (tip + 2) * 3
    for s in sorted({0, 1, max_slot} | {rng.randint(0, max_slot) for _ in range(12)}):
        assert await randao._boundary_height_for_slot(db, s) == await randao._boundary_height_for_slot(walk, s), s
    assert await vr.enumerate_canonical_validator_ops(db) == await vr.enumerate_canonical_validator_ops(walk)
    last_epoch = ((tip + 1) * 3) // SLOTS_PER_EPOCH
    for f in sorted({0, last_epoch} | {rng.randint(0, last_epoch) for _ in range(5)}):
        mine = await vr.enumerate_canonical_epoch_attesters(db, f)
        theirs = await vr.enumerate_canonical_epoch_attesters(walk, f)
        assert {e: sorted(v) for e, v in mine.items()} == {e: sorted(v) for e, v in theirs.items()}, f
    offender = key.public_key.to_address()
    for before in sorted({0, tip + 1} | {rng.randint(0, tip + 1) for _ in range(6)}):
        for who in (offender, VALIDATORS[1]):
            assert await W.slashed_on_chain(db, who, before) == await W.slashed_on_chain_by_scan(db, who, before), (who, before)


@pytest.mark.parametrize("seed", range(4))
async def test_every_answer_equals_the_walk_across_reorgs(db, offender_key, seed):
    rng = random.Random(seed)
    slot = await _build(db, rng, 80, offender_key)
    await _assert_matches_the_walk(db, rng, offender_key)

    # A reorg below the indexed tip: replace the last 7–25 blocks with different ones.
    for round_ in range(3):
        tip = await db.get_next_block_id() - 1
        cut = tip - rng.randint(6, 24)
        await db.connection.execute("DELETE FROM blocks WHERE block_height > ?", (cut,))
        await db.connection.commit()
        cur = await db.connection.execute("SELECT content FROM blocks WHERE block_height = ?", (cut,))
        slot = int(eval((await cur.fetchone())[0])["slot"])
        slot = await _build(db, rng, rng.randint(10, 40), offender_key, tag="bcdef"[round_],
                            start=cut + 1, slot0=slot)
        await _assert_matches_the_walk(db, rng, offender_key)


async def test_a_rolled_back_block_takes_its_index_rows_with_it(db, offender_key):
    rng = random.Random(11)
    slot = await _build(db, rng, 30, offender_key)
    await chain_index.sync(db)
    body = {"number": 30, "slot": slot + 2, "epoch": (slot + 2) // SLOTS_PER_EPOCH,
            "randao_reveal": "ab" * 48, "attestations": [_att(VALIDATORS[0], 0)]}
    await db.connection.execute(                                # uncommitted
        "INSERT INTO blocks (block_hash, block_height, content, timestamp) VALUES (?, 30, ?, 0)",
        ("z" * 64, str(body)))
    assert await chain_index.sync(db) == 30                     # indexed in the same transaction
    await db.connection.rollback()
    assert await db.get_next_block_id() == 30
    await _assert_matches_the_walk(db, rng, offender_key)


async def test_a_synced_index_does_no_work(db, offender_key, monkeypatch):
    rng = random.Random(5)
    await _build(db, rng, 40, offender_key)
    await chain_index.sync(db)
    calls = []
    real = chain_index._index_block

    async def counting(*a, **k):
        calls.append(1)
        return await real(*a, **k)

    monkeypatch.setattr(chain_index, "_index_block", counting)
    for _ in range(5):
        await randao.compute_randao_mix(db)
    assert calls == []
