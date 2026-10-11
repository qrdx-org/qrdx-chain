"""
Incremental state roots for the database domains (qrdx/state_commitment.py, chain-spec feature
``incremental_state_root``).

The account, token and UTXO roots used to hash every row on every block. Each domain now keeps
an LtHash accumulator that triggers update with every row change. What must hold:

  * the accumulator always equals one computed from the rows, whatever wrote them — inserts,
    updates, upserts, INSERT OR REPLACE, deletes, rollbacks, clears — and an accumulator that
    drifted (rows written without the triggers) is repaired at startup;
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
    await database.connection.close()
    os.remove(path)


async def _new_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return await DatabaseSQLite.create(path), path


async def _assert_consistent(db):
    for domain in sc.DOMAINS:
        assert await sc.stored_accumulator(db.connection, domain) == await sc.full_accumulator(
            db.connection, domain
        ), domain


async def _random_write(c, rng):
    addr = f"0x{rng.randrange(40):040x}"
    op = rng.randrange(9)
    if op == 0:
        await c.execute(
            "INSERT OR IGNORE INTO account_state (address, balance, nonce, created_at, updated_at) "
            "VALUES (?, ?, ?, 0, 0)", (addr, str(rng.randrange(10**6)), rng.randrange(5)))
    elif op == 1:
        await c.execute(
            "INSERT INTO account_state (address, balance, nonce, created_at, updated_at) "
            "VALUES (?, ?, 0, 0, 0) ON CONFLICT (address) DO UPDATE SET balance = excluded.balance",
            (addr, str(rng.randrange(10**6))))
    elif op == 2:
        await c.execute(
            "INSERT OR REPLACE INTO account_state (address, balance, nonce, code_hash, created_at, "
            "updated_at) VALUES (?, ?, ?, ?, 0, 0)",
            (addr, str(rng.randrange(100)), rng.randrange(5), rng.choice([None, "ab" * 32])))
    elif op == 3:
        await c.execute("UPDATE account_state SET updated_at = ? WHERE address = ?",
                        (rng.randrange(100), addr))  # an uncommitted column only
    elif op == 4:
        await c.execute("DELETE FROM account_state WHERE address = ?", (addr,))
    elif op == 5:
        await c.execute(
            "INSERT INTO contract_storage (contract_address, storage_key, storage_value, "
            "block_number) VALUES (?, ?, ?, ?) ON CONFLICT (contract_address, storage_key) DO "
            "UPDATE SET storage_value = excluded.storage_value, block_number = excluded.block_number",
            (addr, f"{rng.randrange(8):064x}", f"{rng.randrange(1, 9):064x}", rng.randrange(9)))
    elif op == 6:
        await c.execute("DELETE FROM contract_storage WHERE contract_address = ?", (addr,))
    elif op == 7:
        await c.execute(
            "INSERT INTO token_balances (token_address, holder_address, balance, updated_at) "
            "VALUES ('0xt', ?, ?, 0) ON CONFLICT (token_address, holder_address) DO UPDATE SET "
            "balance = excluded.balance",
            (addr, rng.choice(["0", "0.0", "5", "17.25", str(rng.randrange(1000))])))
    else:
        await c.execute(
            "INSERT OR IGNORE INTO unspent_outputs (tx_hash, output_index, address, amount) "
            "VALUES (?, ?, ?, ?)", (f"{rng.randrange(30):064x}", rng.randrange(3), addr, 10))


@pytest.mark.parametrize("seed", range(4))
async def test_the_accumulators_always_equal_the_rows(db, seed):
    rng = random.Random(seed)
    c = db.connection
    for _ in range(40):
        for _ in range(rng.randint(1, 25)):
            await _random_write(c, rng)
        if rng.random() < 0.25:
            await c.rollback()
        else:
            await c.commit()
        await _assert_consistent(db)
    await db.clear_account_state()
    await db.clear_token_balances()
    await _assert_consistent(db)
    assert await sc.stored_accumulator(c, "account") == lthash.ZERO


async def test_the_root_does_not_depend_on_the_write_order():
    a, pa = await _new_db()
    b, pb = await _new_db()
    try:
        rows = [(f"0x{i:040x}", str(i * 7), i % 4) for i in range(60)]
        for r in rows:
            await a.connection.execute(
                "INSERT INTO account_state (address, balance, nonce, created_at, updated_at) "
                "VALUES (?, ?, ?, 0, 0)", r)
        await a.connection.commit()
        # b: another order, with detours that end in the same rows
        for r in reversed(rows):
            await b.connection.execute(
                "INSERT INTO account_state (address, balance, nonce, created_at, updated_at) "
                "VALUES (?, '999', 9, 1, 1)", (r[0],))
            await b.connection.execute(
                "UPDATE account_state SET balance = ?, nonce = ? WHERE address = ?",
                (r[1], r[2], r[0]))
        await b.connection.execute(
            "INSERT INTO account_state (address, balance, nonce, created_at, updated_at) "
            "VALUES ('0xgone', '1', 0, 0, 0)")
        await b.connection.execute("DELETE FROM account_state WHERE address = '0xgone'")
        await b.connection.commit()
        assert await a.get_account_state_root() == await b.get_account_state_root()
        await b.connection.execute("UPDATE account_state SET balance = '8' WHERE address = ?",
                                   (rows[3][0],))
        assert await a.get_account_state_root() != await b.get_account_state_root()
    finally:
        for d, p in ((a, pa), (b, pb)):
            await d.connection.close()
            os.remove(p)


async def test_a_zero_token_balance_contributes_nothing(db):
    c = db.connection
    empty = await db.get_token_balances_root()
    assert empty == "0" * 128
    await c.execute("INSERT INTO token_balances (token_address, holder_address, balance, "
                    "updated_at) VALUES ('0xt', '0xa', '0', 0), ('0xt', '0xb', '0.00', 0)")
    assert await db.get_token_balances_root() == empty
    await c.execute("UPDATE token_balances SET balance = '3' WHERE holder_address = '0xa'")
    three = await db.get_token_balances_root()
    assert three != empty
    await c.execute("INSERT INTO token_balances (token_address, holder_address, balance, "
                    "updated_at) VALUES ('0xt', '0xc', '0', 0)")
    assert await db.get_token_balances_root() == three


async def test_rows_written_without_the_triggers_are_repaired_at_startup():
    d, path = await _new_db()
    try:
        await d.connection.execute("INSERT INTO account_state (address, balance, nonce, "
                                   "created_at, updated_at) VALUES ('0xa', '1', 0, 0, 0)")
        await d.connection.commit()
        await d.connection.close()
        import sqlite3  # another connection: no triggers

        raw = sqlite3.connect(path)
        raw.execute("INSERT INTO account_state (address, balance, nonce, created_at, updated_at) "
                    "VALUES ('0xb', '2', 0, 0, 0)")
        raw.commit()
        raw.close()
        d = await DatabaseSQLite.create(path)  # restart
        await _assert_consistent(d)
    finally:
        await d.connection.close()
        os.remove(path)


def _spec_with_fork(height):
    return cs.build_spec(
        "qrdx-test-commit", 991234, {}, dev=True, features=[],
        forks=[{"name": "inc", "height": height, "features": [sc.FEATURE], "approval": "none"}])


async def test_the_rule_follows_the_block_height(db):
    await db.connection.execute("INSERT INTO account_state (address, balance, nonce, created_at, "
                                "updated_at) VALUES ('0xa', '1', 0, 0, 0)")
    with cs.use_spec(_spec_with_fork(100)):
        before, at = await db.get_account_state_root(99), await db.get_account_state_root(100)
    assert before != at
    assert at == await sc.root(db.connection, "account")
    with cs.use_spec(_spec_with_fork(100)):
        assert await db.get_account_state_root(10**6) == at


async def test_a_root_costs_the_same_however_large_the_state(db):
    c = db.connection
    await c.executemany(
        "INSERT INTO account_state (address, balance, nonce, created_at, updated_at) "
        "VALUES (?, ?, 0, 0, 0)", [(f"0x{i:040x}", str(i)) for i in range(20000)])
    await c.commit()
    t = time.perf_counter()
    for i in range(20):
        await c.execute("UPDATE account_state SET balance = ? WHERE address = ?",
                        (str(i), f"0x{i:040x}"))
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
