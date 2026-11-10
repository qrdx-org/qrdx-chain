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

from qrdx import block_codec, chain_index
from qrdx.constants import SLOTS_PER_EPOCH
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.exchange.transactions import ExchangeOpType, ExchangeTransaction
from qrdx.validator import randao, withdrawals as W
from qrdx.validator.slashing_block import make_double_sign_evidence

from chain_rows import block_content, delete_blocks, put_block, set_block
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


async def _indexed_votes(db, carried_through_epoch):
    """(target epoch, validator) of every vote the index says blocks of an epoch ≤ the given
    one carry — what the validator set's rewards read (validator/epoch_state.py)."""
    await chain_index.sync(db)
    return sorted({(r.target_epoch, r.validator) for r in db.store["chain_index_votes"].scan()
                   if r.carry_epoch is not None and r.carry_epoch <= carried_through_epoch})


async def _walked_votes(db, carried_through_epoch):
    import ast
    from qrdx.validator.attestation_block import extract_attestations_from_dict
    from qrdx.validator.block_verification import epoch_from_block
    out = set()
    for h in range(await db.get_next_block_id()):
        block = await db.get_block_by_id(h)
        if not block:
            continue
        bc = ast.literal_eval(block["content"])
        carry = epoch_from_block(bc)
        if carry is None or carry > carried_through_epoch:
            continue
        out |= {(int(a.target_epoch), a.validator_address) for a in extract_attestations_from_dict(bc)}
    return sorted(out)


async def _assert_matches_the_walk(db, rng, key):
    walk = _NoSQL(db)
    tip = await db.get_next_block_id() - 1
    for h in sorted({-1, 0, tip, tip + 5} | {rng.randint(0, tip) for _ in range(12)}):
        assert await randao.compute_randao_mix(db, h) == await randao.compute_randao_mix(walk, h), h
    max_slot = (tip + 2) * 3
    for s in sorted({0, 1, max_slot} | {rng.randint(0, max_slot) for _ in range(12)}):
        assert await randao._boundary_height_for_slot(db, s) == await randao._boundary_height_for_slot(walk, s), s
    last_epoch = ((tip + 1) * 3) // SLOTS_PER_EPOCH
    for f in sorted({0, last_epoch} | {rng.randint(0, last_epoch) for _ in range(5)}):
        assert await _indexed_votes(db, f) == await _walked_votes(db, f), f
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
        delete_blocks(db, cut + 1)
        await db.connection.commit()
        slot = int(eval(block_content(db, cut))["slot"])
        slot = await _build(db, rng, rng.randint(10, 40), offender_key, tag="bcdef"[round_],
                            start=cut + 1, slot0=slot)
        await _assert_matches_the_walk(db, rng, offender_key)


async def test_a_rolled_back_block_takes_its_index_rows_with_it(db, offender_key):
    rng = random.Random(11)
    slot = await _build(db, rng, 30, offender_key)
    await chain_index.sync(db)
    body = {"number": 30, "slot": slot + 2, "epoch": (slot + 2) // SLOTS_PER_EPOCH,
            "randao_reveal": "ab" * 48, "attestations": [_att(VALIDATORS[0], 0)]}
    put_block(db, 30, "z" * 64, str(body))                      # uncommitted
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


async def test_an_unchanged_chain_is_checked_without_a_round_trip(db, offender_key):
    """Every chain-index read syncs first, many times a block. After one query has found the
    index in step (the chain's block at the indexed top, the index's row there, the tip), no
    query at all while nothing is written to ``blocks`` and nothing is rolled back — and the
    reads come from memory. A new block, a replaced one and an index row rolled back with its
    transaction are each still seen."""
    from qrdx.node.observability import DB_CALLS, count_db_calls

    rng = random.Random(3)
    slot = await _build(db, rng, 20, offender_key)
    count_db_calls(db.connection)
    assert await chain_index.sync(db) == 19
    assert await chain_index.block_hash_at(db, 0) is not None      # (memory filled: one read)
    before = DB_CALLS[0]
    for _ in range(5):
        assert await chain_index.sync(db) == 19
        assert await chain_index.block_hash_at(db, 7) is not None
        assert await chain_index.highest_height_before_slot(db, slot + 1) == 19
    if os.environ.get("QRDX_VERIFY_CHAIN_INDEX") != "1":
        assert DB_CALLS[0] - before == 0
    slot = await _build(db, rng, 1, offender_key, start=20, slot0=slot)          # (a new block)
    assert await chain_index.sync(db) == 20
    delete_blocks(db, 20, 20)                                                     # (replaced)
    await db.connection.commit()
    await _build(db, rng, 1, offender_key, tag="b", start=20, slot0=slot)
    assert await chain_index.sync(db) == 20
    await _assert_matches_the_walk(db, rng, offender_key)
    await db.connection.commit()
    body = {"number": 21, "slot": slot + 3, "epoch": (slot + 3) // SLOTS_PER_EPOCH,
            "randao_reveal": "cd" * 48, "attestations": []}
    put_block(db, 21, "y" * 64, str(body))
    await db.connection.commit()                                   # (the block stays…)
    assert await chain_index.sync(db) == 21
    await db.connection.rollback()                                 # (…its index row does not)
    assert await chain_index.sync(db) == 21
    assert db.store["chain_index"].get(21).block_hash == "y" * 64


async def test_what_memory_holds_follows_every_change_to_the_chain(db, offender_key, monkeypatch):
    """The heights kept in memory (a window of 8 here, so reads below it go to the table) give
    what the table gives — checked on every read (QRDX_VERIFY_CHAIN_INDEX) — through blocks
    deleted by hand, a rollback that brings them back, a hash changed in place, and a new
    chain from a lower height."""
    monkeypatch.setattr(chain_index, "RECENT", 8)
    monkeypatch.setenv("QRDX_VERIFY_CHAIN_INDEX", "1")
    rng = random.Random(9)
    slot = await _build(db, rng, 30, offender_key)

    async def every_read(top):
        assert await chain_index.sync(db) == top
        for h in range(-1, top + 3):
            await chain_index.block_hash_at(db, h)
            await chain_index.slot_at(db, h)
        for s in range(0, slot + 4):
            await chain_index.highest_height_before_slot(db, s)
            for cap in (0, 3, top - 5, top, top + 2):
                await chain_index.height_before_slot_at_or_below(db, s, cap)

    await every_read(29)
    kept = await chain_index.block_hash_at(db, 27)
    delete_blocks(db, 25)                                             # (by hand)
    await every_read(24)
    assert await chain_index.block_hash_at(db, 27) is None
    await db.connection.rollback()                                    # (…and back again)
    await every_read(29)
    assert await chain_index.block_hash_at(db, 27) == kept
    set_block(db, 29, block_hash="e" * 64)
    await every_read(29)
    assert await chain_index.block_hash_at(db, 29) == "e" * 64
    await db.connection.commit()
    delete_blocks(db, 12)
    await db.connection.commit()
    slot = await _build(db, rng, 10, offender_key, tag="r", start=12, slot0=slot)
    await every_read(21)


async def test_two_databases_on_one_connection_share_its_count(db, offender_key):
    """Writes through either object on a connection are seen by both."""
    from qrdx.database_sqlite import DatabaseSQLite

    rng = random.Random(4)
    slot = await _build(db, rng, 6, offender_key)
    other = DatabaseSQLite.__new__(DatabaseSQLite)
    other.connection, other.store = db.connection, db.store
    assert await chain_index.sync(db) == 5 and await chain_index.sync(other) == 5
    await _build(other, rng, 2, offender_key, start=6, slot0=slot)
    assert await chain_index.sync(db) == 7 and await chain_index.sync(other) == 7
    assert await db.get_block_height() == 7
