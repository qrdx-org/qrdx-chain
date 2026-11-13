"""
Incremental state roots for the database domains (qrdx/state_commitment.py, chain-spec feature
``incremental_state_root``).

The account, token and UTXO roots used to hash every row on every block. Each domain now keeps
an LtHash accumulator that the store (qrdx/store.py) updates natively with every row change. What
must hold:

  * the accumulator always equals one computed from the rows by the Python encoders, whatever
    wrote them — inserts, updates, upserts, replacements, deletes, rollbacks, clears — and an
    accumulator that drifted is repaired by a reconcile;
  * the root depends on the state, not on the order it was written in: two nodes reaching the
    same rows by different histories agree;
  * a zero token balance contributes nothing, as in the sequential root;
  * the rule follows the block height: the sequential root before the feature's fork, the
    incremental one from it;
  * the cost does not grow with the state.
"""
import os
import random
import tempfile
import time

import pytest

from qrdx import chain_spec as cs
from qrdx import state_commitment as sc
from qrdx.crypto import lthash
from qrdx.database_sqlite import DatabaseSQLite


@pytest.fixture
async def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database = await DatabaseSQLite.create(path)
    yield database
    await database.close()
    os.remove(path)


async def _new_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return await DatabaseSQLite.create(path), path


async def _assert_consistent(db):
    for domain in sc.DOMAINS:
        stored = await sc.stored_accumulator(db, domain)
        assert stored == await sc.full_accumulator(db, domain), domain  # (Python's encoders)
        assert stored == db.store.native.full_acc(domain), domain  # (the store's, from scratch)


# Token balances the native encoder cannot judge alone (Python's Decimal does): unreadable,
# not a number, padded, an exponent.
_ODD_BALANCES = ["abc", "NaN", "Infinity", " 3", "1E+3", "-0", "0E-18", ""]


def _random_write(db, rng):
    accounts = db.store["account_state"]
    storage = db.store["contract_storage"]
    addr = f"0x{rng.randrange(40):040x}"
    op = rng.randrange(9)
    if op == 0:
        accounts.insert(address=addr, balance=str(rng.randrange(10**6)), nonce=rng.randrange(5))
    elif op == 1:
        accounts.upsert((addr,), {"balance": str(rng.randrange(10**6))}, ("balance",))
    elif op == 2:
        accounts.put(address=addr, balance=str(rng.randrange(100)), nonce=rng.randrange(5),
                     code_hash=rng.choice([None, "ab" * 32]))
    elif op == 3:
        accounts.update((addr,), updated_at=rng.randrange(100))  # an uncommitted column only
    elif op == 4:
        accounts.delete(addr)
    elif op == 5:
        storage.put(addr, f"{rng.randrange(8):064x}", f"{rng.randrange(1, 9):064x}",
                    rng.randrange(9))
    elif op == 6:
        storage.delete_prefix(addr)
    elif op == 7:
        db.store["token_balances"].put(
            "0xt", addr,
            rng.choice(["0", "0.0", "5", "17.25", str(rng.randrange(1000))] + _ODD_BALANCES), 0)
    else:
        db.store["unspent_outputs"].insert(
            tx_hash=f"{rng.randrange(30):064x}", output_index=rng.randrange(3), address=addr,
            amount=10)


@pytest.mark.parametrize("seed", range(4))
async def test_the_accumulators_always_equal_the_rows(db, seed):
    rng = random.Random(seed)
    c = db.connection
    for _ in range(40):
        for _ in range(rng.randint(1, 25)):
            _random_write(db, rng)
        if rng.random() < 0.25:
            await c.rollback()
        else:
            await c.commit()
        await _assert_consistent(db)
    await db.clear_account_state()
    await db.clear_token_balances()
    await _assert_consistent(db)
    assert await sc.stored_accumulator(db, "account") == lthash.ZERO


async def test_the_root_does_not_depend_on_the_write_order():
    a, pa = await _new_db()
    b, pb = await _new_db()
    try:
        rows = [(f"0x{i:040x}", str(i * 7), i % 4) for i in range(60)]
        for addr, bal, nonce in rows:
            a.store["account_state"].put(address=addr, balance=bal, nonce=nonce)
        await a.connection.commit()
        # b: another order, with detours that end in the same rows
        accounts = b.store["account_state"]
        for addr, bal, nonce in reversed(rows):
            accounts.put(address=addr, balance="999", nonce=9, created_at=1, updated_at=1)
            accounts.update((addr,), balance=bal, nonce=nonce)
        accounts.put(address="0xgone", balance="1")
        accounts.delete("0xgone")
        await b.connection.commit()
        assert await a.get_account_state_root() == await b.get_account_state_root()
        accounts.update((rows[3][0],), balance="8")
        assert await a.get_account_state_root() != await b.get_account_state_root()
    finally:
        for d, p in ((a, pa), (b, pb)):
            await d.close()
            os.remove(p)


async def test_a_zero_token_balance_contributes_nothing(db):
    tokens = db.store["token_balances"]
    empty = await db.get_token_balances_root()
    assert empty == "0" * 128
    tokens.put("0xt", "0xa", "0", 0)
    tokens.put("0xt", "0xb", "0.00", 0)
    assert await db.get_token_balances_root() == empty
    tokens.update(("0xt", "0xa"), balance="3")
    three = await db.get_token_balances_root()
    assert three != empty
    tokens.put("0xt", "0xc", "0", 0)
    assert await db.get_token_balances_root() == three


async def test_an_accumulator_that_drifted_is_repaired_by_a_reconcile():
    d, path = await _new_db()
    try:
        d.store["account_state"].put(address="0xa", balance="1")
        await d.connection.commit()
        d.store.set_acc("account", lthash.mix(lthash.ZERO, None, lthash.entry(b"x", b"y")))
        await d.connection.commit()
        assert await sc.stored_accumulator(d, "account") != await sc.full_accumulator(d, "account")
        assert await sc.reconcile(d) == {"account": True}
        await _assert_consistent(d)
    finally:
        await d.close()
        os.remove(path)


def _spec_with_fork(height):
    return cs.build_spec(
        "qrdx-test-commit", 991234, {}, dev=True, features=[],
        forks=[{"name": "inc", "height": height, "features": [sc.FEATURE], "approval": "none"}])


async def test_the_rule_follows_the_block_height(db):
    db.store["account_state"].put(address="0xa", balance="1")
    with cs.use_spec(_spec_with_fork(100)):
        before, at = await db.get_account_state_root(99), await db.get_account_state_root(100)
    assert before != at
    assert at == await sc.root(db, "account")
    with cs.use_spec(_spec_with_fork(100)):
        assert await db.get_account_state_root(10**6) == at


async def test_a_root_costs_the_same_however_large_the_state(db):
    accounts = db.store["account_state"]
    for i in range(20000):
        accounts.put(address=f"0x{i:040x}", balance=str(i))
    await db.connection.commit()
    t = time.perf_counter()
    for i in range(20):
        accounts.update((f"0x{i:040x}",), balance=str(i + 1))
        await db.get_account_state_root()
    per_block = (time.perf_counter() - t) / 20
    assert per_block < 0.01, f"{per_block * 1000:.1f} ms per update + root at 20,000 accounts"


def test_lthash_add_and_remove_are_inverse():
    vs = [lthash.entry(b"t", bytes([i])) for i in range(30)]
    acc = lthash.ZERO
    for v in vs:
        acc = lthash.mix(acc, None, v)
    full = lthash.Accumulator()
    for v in reversed(vs):
        full.add(v)
    assert acc == full.digest()
    for v in vs:
        acc = lthash.mix(acc, v, None)
    assert acc == lthash.ZERO
    assert lthash.root("x", lthash.ZERO) == "0" * 128


async def test_a_batched_balance_flush_folds_what_it_changed(tmp_path):
    """``apply_account_balance_deltas`` writes its rows already packed (``Table.put_raw``): after
    every batch — credits, debits, accounts new and old, one changed twice — the accumulator is
    the rows'."""
    import random
    from decimal import Decimal

    from qrdx import state_commitment as sc
    from qrdx.database_sqlite import DatabaseSQLite

    db = await DatabaseSQLite.create(db_path=str(tmp_path / "flush.db"))
    try:
        rng = random.Random(3)
        addrs = ["0xPQ" + f"{i:064x}" for i in range(40)]
        changed = 0
        for k in range(30):
            deltas = [(rng.choice(addrs), Decimal(rng.choice(["1", "-0.5", "2.25", "1E-6", "-3"])))
                      for _ in range(rng.randint(1, 25))]
            before = await sc.stored_accumulator(db, "account")
            await db.apply_account_balance_deltas(deltas)
            after = await sc.stored_accumulator(db, "account")
            changed += after != before
            assert after == await sc.full_accumulator(db, "account"), k
        assert changed > 20
    finally:
        await db.close()
