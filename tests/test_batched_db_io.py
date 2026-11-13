"""
A block's balances read and written in batches give exactly what one at a time gave
(docs/PERFORMANCE.md). Every node must reach the same state, so the batched forms
(``get_address_balances``, ``get_token_balances_of``, ``apply_account_balance_deltas``,
``apply_token_balance_deltas``) are held to the one-row forms on random deltas. These include
the same account under two address forms, debits that clamp or overdraw, new accounts, and
debits on accounts that do not exist.
"""

import os
import random
import tempfile
from decimal import Decimal as D

import pytest

from qrdx.crypto.account_id import to_account_id
from qrdx.database_sqlite import DatabaseSQLite

PQ = ["0xPQ" + f"{i:064x}" for i in range(1, 9)]
ETH = ["0x" + f"{i:040x}" for i in range(100, 106)]
TOKENS = ["0x" + "aa" * 20, "0x" + "bb" * 20]


async def _db():
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    return db, path


async def _seed(db, rng):
    for a in PQ[:5] + ETH[:3]:
        await db.apply_account_balance_delta(a, D(rng.randint(1, 50)))
        for t in TOKENS:
            await db.apply_token_balance_delta(t, a, D(rng.randint(0, 20)))
    await db.connection.commit()


def _deltas(rng, n):
    addrs = PQ + ETH + [to_account_id(PQ[0]), to_account_id(PQ[1])]  # (two forms of one account)
    return [(rng.choice(addrs), D(rng.randint(-60, 60)) / D(rng.choice([1, 7, 1000])))
            for _ in range(n)]


async def _state(db):
    accounts = sorted((r.address.lower(), r.balance) for r in db.store["account_state"].scan())
    tokens = [(r.token_address, r.holder_address, r.balance)
              for r in db.store["token_balances"].scan()]
    return accounts, tokens


@pytest.mark.parametrize("seed", range(8))
async def test_batched_reads_and_writes_match_one_at_a_time(seed):
    rng = random.Random(seed)
    (a, pa), (b, pb) = await _db(), await _db()
    try:
        await _seed(a, random.Random(seed))
        await _seed(b, random.Random(seed))
        holders = PQ + ETH + [to_account_id(PQ[2])]
        assert await a.get_address_balances(holders) == {
            h: await b.get_address_balance(h) for h in holders}
        pairs = [(t, h) for t in TOKENS for h in holders]
        assert await a.get_token_balances_of(pairs) == {
            (t, h): await b.get_token_balance(t, h) for t, h in pairs}

        deltas = _deltas(rng, 40)
        merged = {}
        for addr, d in deltas:  # (a block's deltas: one entry an address, in order)
            merged[addr] = merged.get(addr, D(0)) + d
        batched = await a.apply_account_balance_deltas(list(merged.items()))
        single = {addr: await b.apply_account_balance_delta(addr, d) for addr, d in merged.items()}
        assert batched == single

        token_deltas = {(rng.choice(holders), rng.choice(TOKENS)): D(rng.randint(-30, 30))
                        for _ in range(30)}
        await a.apply_token_balance_deltas(list(token_deltas.items()))
        for (holder, token), d in token_deltas.items():
            await b.apply_token_balance_delta(token, holder, d)
        assert await _state(a) == await _state(b)
    finally:
        for db, p in ((a, pa), (b, pb)):
            await db.close()
            for f in (p, p + "-wal", p + "-shm"):
                if os.path.exists(f):
                    os.remove(f)
