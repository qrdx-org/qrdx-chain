"""
The node's store (qrdx/store.py, native/qrdx-native/src/store; docs/STORAGE.md).

What must hold:

  * packed keys sort as their tuples do, and every tuple round-trips;
  * reads, scans and counts always show the writes since the last commit over the file's rows,
    a rollback drops them, a commit makes them durable (a reopened file holds them) — against a
    plain dict on random operations;
  * the undo journal takes blocks back out: rows, accumulators and proof-tree marks as they were;
    a write outside any block makes it refuse; a rolled-back block leaves no entry behind;
  * the marks name every changed row of a tracked table, once;
  * a copy is the committed state, whatever is pending.
"""
import random

import pytest

from qrdx import state_commitment as sc
from qrdx import undo_journal
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.store import Spec, Store, pack, unpack

_SPECS = (
    Spec("t", [("a", "TEXT"), ("b", "INTEGER")], [("v", "TEXT", None), ("w", "INTEGER", 0)]),
    Spec("u", [("k", "BLOB")], [("v", "BLOB", b"")]),
)


def _value(rng, kind):
    if kind == "int":
        return rng.choice([0, 1, -1, 255, 256, -256, 2**63 - 1, -(2**63), 2**64, -(2**70),
                           rng.randrange(-(10**30), 10**30)])
    if kind == "str":
        return rng.choice(["", "a", "a\x00", "a\x00b", "ab", "b", "é", "￿", "z" * 40])
    return rng.choice([b"", b"\x00", b"\x00\xff", b"\xff", b"a", bytes(range(5))])


@pytest.mark.parametrize("kind", ["int", "str", "bytes"])
def test_packed_keys_sort_as_their_tuples(kind):
    rng = random.Random(kind)
    tuples = list({(_value(rng, kind), _value(rng, kind)) for _ in range(400)})
    assert sorted(tuples, key=pack) == sorted(tuples)
    # (a tuple's packing is a prefix of every tuple extending it, and the range after it ends
    # before the prefix and 0xFF)
    for t in tuples[:50]:
        p = pack(t[:1])
        assert pack(t).startswith(p) and pack(t) < p + b"\xff"


def test_a_tuple_round_trips():
    rng = random.Random(1)
    for _ in range(500):
        t = tuple(_value(rng, rng.choice(["int", "str", "bytes"])) for _ in range(rng.randrange(6)))
        t += (None, 1.5, -0.25, float("inf"))[: rng.randrange(5)]
        assert unpack(pack(t)) == t
    assert unpack(pack((True, False))) == (1, 0)  # (as SQLite stores a bool)
    with pytest.raises(TypeError):
        pack((object(),))


def _model_scan(rows, lo, hi, reverse, limit):
    keys = sorted(k for k in rows if (lo is None or k >= lo) and (hi is None or k < hi))
    if reverse:
        keys.reverse()
    return [(k, rows[k]) for k in keys][:limit]


@pytest.mark.parametrize("seed", range(6))
def test_the_store_matches_a_dict(tmp_path, seed):
    rng = random.Random(seed)
    path = str(tmp_path / "s.store")
    store = Store(path, _SPECS)
    t = store["t"].id
    committed, pending = {}, {}
    keys = [pack((f"k{i % 7}", i)) for i in range(40)]
    for step in range(600):
        rows = {**committed, **pending}
        rows = {k: v for k, v in rows.items() if v is not None}
        op = rng.random()
        k = rng.choice(keys)
        if op < 0.35:
            v = pack((f"v{rng.randrange(9)}", rng.randrange(5)))
            store.native.put(t, k, v)
            pending[k] = v
        elif op < 0.5:
            assert store.native.delete(t, k) == (k in rows)
            pending[k] = None
        elif op < 0.52:
            store["t"].clear()
            pending = {key: None for key in {**committed, **pending}}
        elif op < 0.6:
            store.commit()
            committed = {key: v for key, v in rows.items()}
            pending = {}
        elif op < 0.65:
            store.rollback()
            pending = {}
        elif op < 0.68:
            store.commit()
            committed, pending = dict(rows), {}
            store.close()
            store = Store(path, _SPECS)  # (reopened: what was committed is there)
            assert store.native.get(t, keys[0]) == committed.get(keys[0])
        else:
            lo = rng.choice([None, *keys])
            hi = rng.choice([None, *keys])
            reverse = rng.random() < 0.5
            limit = rng.choice([None, 1, 3, 100])
            got = [tuple(r) for r in store.native.scan(t, lo, hi, reverse, limit)]
            assert got == _model_scan(rows, lo, hi, reverse, limit), step
            assert store.native.count(t) == len(rows)
            assert list(store.native.get_many(t, keys)) == [rows.get(key) for key in keys]
    store.close()


async def _db(tmp_path, name="n.db"):
    return await DatabaseSQLite.create(str(tmp_path / name))


def _snapshot(db):
    return (
        [tuple(r) for r in db.store["account_state"].scan()],
        [tuple(r) for r in db.store["contract_storage"].scan()],
        [tuple(r) for r in db.store["token_balances"].scan()],
        {d: db.store.acc(d) for d in sc.DOMAINS},
    )


def _block_writes(db, rng):
    accounts, storage = db.store["account_state"], db.store["contract_storage"]
    for _ in range(rng.randint(1, 12)):
        a = f"0x{rng.randrange(12):040x}"
        op = rng.random()
        if op < 0.4:
            accounts.upsert((a,), {"balance": str(rng.randrange(10**4)), "nonce": 0}, ("balance",))
        elif op < 0.5:
            accounts.delete(a)
        elif op < 0.7:
            storage.put(a, f"{rng.randrange(4):064x}", f"{rng.randrange(1, 5):064x}", 0)
        elif op < 0.8:
            storage.delete_prefix(a)
        else:
            db.store["token_balances"].put("0xt", a, str(rng.randrange(5)), 0)


@pytest.mark.parametrize("seed", range(4))
async def test_the_journal_takes_blocks_back_out(tmp_path, seed):
    rng = random.Random(seed)
    db = await _db(tmp_path)
    try:
        await undo_journal.set_floor(db, 0)
        states = {0: _snapshot(db)}
        tip = 0
        for _ in range(30):
            if tip > 2 and rng.random() < 0.25:  # a reorg
                back = rng.randint(max(0, tip - 5), tip - 1)
                assert await undo_journal.rollback_to(db, back) is not None
                await db.connection.commit()
                assert _snapshot(db) == states[back], (tip, back)
                tip = back
                continue
            tip += 1
            async with undo_journal.recording(db, tip):
                _block_writes(db, rng)
            if rng.random() < 0.2:  # (a refused block: its rows and its entries go)
                await db.connection.rollback()
                assert _snapshot(db) == states[tip - 1]
                tip -= 1
                continue
            await db.connection.commit()
            states[tip] = _snapshot(db)
        assert await undo_journal.rollback_to(db, 0) is not None
        assert _snapshot(db) == states[0]
    finally:
        await db.close()


async def test_a_write_outside_any_block_makes_the_journal_refuse(tmp_path):
    db = await _db(tmp_path)
    try:
        await undo_journal.set_floor(db, 0)
        async with undo_journal.recording(db, 1):
            db.store["account_state"].put(address="0xa", balance="1")
        assert await undo_journal.can_roll_back_to(db, 0)
        db.store["account_state"].put(address="0xb", balance="2")  # (no block: unattributed)
        assert not await undo_journal.can_roll_back_to(db, 0)
        assert await undo_journal.rollback_to(db, 0) is None
        await undo_journal.reset(db)
        async with undo_journal.suspended(db):
            db.store["account_state"].put(address="0xc", balance="3")  # (suspended: nothing)
        assert await undo_journal.can_roll_back_to(db, 0)
    finally:
        await db.close()


async def test_a_batched_balance_flush_is_journaled_and_taken_back(tmp_path):
    """``apply_account_balance_deltas`` writes its rows already packed: each block's rows, and the
    accumulator, come back exactly by the journal."""
    from decimal import Decimal

    db = await _db(tmp_path)
    try:
        await undo_journal.set_floor(db, 0)
        rng = random.Random(5)
        addrs = ["0xPQ" + f"{i:064x}" for i in range(30)]
        states = {0: _snapshot(db)}
        for height in range(1, 16):
            deltas = [(rng.choice(addrs), Decimal(rng.choice(["1", "-0.5", "2.25", "-3", "7"])))
                      for _ in range(rng.randint(1, 20))]
            async with undo_journal.recording(db, height):
                await db.apply_account_balance_deltas(deltas)
            await db.connection.commit()
            states[height] = _snapshot(db)
            assert states[height][3]["account"] == await sc.full_accumulator(db, "account")
        assert len(db.store.native.undo_entries()) > 50
        assert await undo_journal.rollback_to(db, 7) is not None
        assert _snapshot(db) == states[7]
    finally:
        await db.close()


async def test_the_marks_name_every_changed_row_once(tmp_path):
    db = await _db(tmp_path)
    try:
        db.store.native.take_marks()
        accounts = db.store["account_state"]
        accounts.put(address="0xa", balance="1")
        accounts.update(("0xa",), balance="2")
        accounts.put(address="0xb", balance="1")
        accounts.put(address="0xb", balance="1")  # (unchanged: not marked again, nor written)
        db.store["contract_code"].put("h", b"code", 0, "", 4)  # (untracked)
        marks = sorted((t, unpack(k)) for t, k in db.store.native.take_marks())
        assert marks == [("account_state", ("0xa",)), ("account_state", ("0xb",))]
        assert db.store.native.take_marks() == []
        await db.connection.rollback()  # (the marks taken in the transaction come back)
        assert db.store.native.take_marks() == []  # (…with the rows: there were none)
    finally:
        await db.close()


async def test_a_copy_is_the_committed_state(tmp_path):
    db = await _db(tmp_path)
    try:
        accounts = db.store["account_state"]
        accounts.put(address="0xa", balance="1")
        await db.connection.commit()
        accounts.put(address="0xb", balance="2")  # (pending)
        db.store.copy_to(str(tmp_path / "copy.store"))
        copy = Store(str(tmp_path / "copy.store"))
        try:
            assert [r.address for r in copy["account_state"].scan()] == ["0xa"]
            assert copy.acc("account") == await sc.full_accumulator(_Rows(copy), "account")
        finally:
            copy.close()
    finally:
        await db.close()


class _Rows:
    """(a database whose store is ``store``, for ``full_accumulator``)"""

    def __init__(self, store):
        self.store = store


_INDEXED = (
    Spec(
        "votes",
        [("height", "INTEGER"), ("seq", "INTEGER")],
        [("target", "INTEGER", 0), ("validator", "TEXT", None)],
        journaled=True,
        indexes={"by_target": ("target", "validator"), "by_validator": ("validator",)},
    ),
    Spec("store_meta", [("key", "TEXT")], [("value", "TEXT", None)]),
)


@pytest.mark.parametrize("seed", range(4))
def test_an_index_follows_every_write(tmp_path, seed):
    """Puts, overwrites that move a row in the index, deletes, rollbacks, a clear and the
    journal's own rollback: the index always lists exactly the rows, in its columns' order."""
    rng = random.Random(seed)
    path = str(tmp_path / "i.store")
    store = Store(path, _INDEXED)
    votes = store["votes"]
    states = {}
    height = 0
    for _ in range(300):
        op = rng.random()
        if op < 0.5:
            with store.recording(height):
                votes.put(rng.randrange(8), rng.randrange(4), rng.randrange(5), f"v{rng.randrange(6)}")
        elif op < 0.6:
            with store.recording(height):
                votes.delete(rng.randrange(8), rng.randrange(4))
        elif op < 0.7:
            store.commit()
            states[height] = sorted(tuple(r) for r in votes.scan())
            height += 1
        elif op < 0.75:
            store.rollback()
        elif op < 0.78 and states:
            back = rng.choice(sorted(states))
            store.native.undo_rollback(back)
            store.commit()
            assert sorted(tuple(r) for r in votes.scan()) == states[back]
            states = {h: s for h, s in states.items() if h <= back}
            height = back + 1
        rows = [tuple(r) for r in votes.scan()]
        want = sorted(rows, key=lambda r: (r[2], r[3], r[0], r[1]))
        assert [tuple(r) for r in votes.scan_index("by_target")] == want
        t = rng.randrange(5)
        assert [tuple(r) for r in votes.scan_index("by_target", t)] == [r for r in want if r[2] == t]
        assert [tuple(r) for r in votes.scan_index("by_target", lo=(1,), hi=(3,))] == [
            r for r in want if 1 <= r[2] < 3]
        v = f"v{rng.randrange(6)}"
        assert [tuple(r) for r in votes.scan_index("by_validator", v, reverse=True)] == sorted(
            (r for r in rows if r[3] == v), key=lambda r: (r[0], r[1]), reverse=True)
    votes.clear()
    assert votes.scan_index("by_target") == [] and votes.scan_index("by_validator") == []
    store.close()
