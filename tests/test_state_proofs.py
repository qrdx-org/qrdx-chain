"""
Provable state (qrdx/state_proofs.py, docs/STATE_PROOFS.md): a sparse Merkle tree over the
accounts, contract storage and token balances, kept from the rows' own triggers and bound into
the unified state root — so one entry, or its absence, is proven against a block's signed root,
off chain (``verify_against``) and on chain (the precompile at 0x…0300).
"""
import os
import tempfile
from decimal import Decimal

import pytest
from test_evm_world import ALICE, BOB, Chain, _hex, chain  # noqa: F401  (fixture)

from qrdx import state_proofs
from qrdx.contracts.evm_world import STATE_PROOF_ADDRESS
from qrdx.contracts.state_proof_evm import encode
from qrdx.crypto.account_id import to_account_id
from qrdx.crypto.hashing import unified_state_root
from qrdx.database_sqlite import DatabaseSQLite

D = Decimal
TOKEN = "0x" + "70" * 20
PARTS = {"utxo": "1" * 64, "account": "2" * 128, "exchange": "3" * 128, "token": "4" * 128}
VALIDATORS = "5" * 128  # the validator root (validator_state_root is a genesis feature)


@pytest.fixture
async def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    d = await DatabaseSQLite.create(path)
    yield d
    await d.close()
    for p in (path, path + "-wal", path + "-shm"):
        if os.path.exists(p):
            os.remove(p)


async def _seal(db, height):
    """What the proposer does at a block: the proof root, the parts, the signed root."""
    root = await state_proofs.proof_root(db, height)
    await state_proofs.record_parts(db, height, {**PARTS, "proof": root, "validators": VALIDATORS})
    await db.connection.commit()
    return unified_state_root(*PARTS.values(), root, VALIDATORS)


async def _rows(db):
    await db.apply_account_balance_delta(_hex(ALICE), D(5))
    await db.apply_account_balance_delta(_hex(BOB), D("0.25"))
    await db.apply_token_balance_delta(TOKEN, _hex(ALICE), D("12.5"))
    db.store["contract_storage"].put(_hex(BOB), "0x" + "00" * 31 + "07", "0x" + "00" * 31 + "2a", 1)


async def test_an_entry_and_an_absence_are_proven_against_the_signed_root(db):
    await _rows(db)
    signed = await _seal(db, 1)
    p = await state_proofs.prove(db, "account", _hex(ALICE))
    assert p["entry"] and state_proofs.verify_against(signed, p)
    assert state_proofs.decode_entry(bytes.fromhex(p["entry"]))["balance_wei"] == str(5 * 10**18)
    t = await state_proofs.prove(db, "token", TOKEN, _hex(ALICE))
    assert state_proofs.decode_entry(bytes.fromhex(t["entry"]))["balance_e18"] == str(125 * 10**17)
    assert state_proofs.verify_against(signed, t)
    s = await state_proofs.prove(db, "storage", _hex(BOB), "0x" + "00" * 31 + "07")
    assert state_proofs.verify_against(signed, s)
    nobody = await state_proofs.prove(db, "account", "0x" + "ee" * 20)
    assert nobody["entry"] is None and state_proofs.verify_against(signed, nobody)


def _tamper(p):
    entry = bytearray.fromhex(p["entry"])
    entry[30] ^= 1                                                   # the balance
    return {**p, "entry": entry.hex()}


async def test_nothing_false_verifies(db):
    await _rows(db)
    signed = await _seal(db, 1)
    p = await state_proofs.prove(db, "account", _hex(ALICE))
    assert not state_proofs.verify_against(signed, _tamper(p))
    assert not state_proofs.verify_against(signed, {**p, "roots": {**p["roots"], "token": "5" * 128}})
    assert not state_proofs.verify_against("0" * 128, p)
    absent = {**p, "entry": None}                                    # "it holds nothing": no
    assert not state_proofs.verify_against(signed, absent)


async def test_an_earlier_height_still_proves_what_it_held(db):
    await _rows(db)
    first = await _seal(db, 1)
    await db.apply_account_balance_delta(_hex(ALICE), D(1))
    second = await _seal(db, 2)
    assert first != second
    old = await state_proofs.prove(db, "account", _hex(ALICE), height=1)
    new = await state_proofs.prove(db, "account", _hex(ALICE), height=2)
    assert state_proofs.verify_against(first, old) and state_proofs.verify_against(second, new)
    assert old["entry"] != new["entry"]


async def test_the_root_is_a_function_of_the_rows(db):
    """Two databases holding the same rows, written in a different order and folded at
    different times, have the same proof root."""
    await _rows(db)
    await state_proofs.proof_root(db, 1)
    await db.apply_account_balance_delta(_hex(ALICE), D(1))
    await db.apply_account_balance_delta(_hex(ALICE), D(-1))
    a = await state_proofs.proof_root(db, 2)
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    other = await DatabaseSQLite.create(path)
    try:
        other.store["contract_storage"].put(
            _hex(BOB), "0x" + "00" * 31 + "07", "0x" + "00" * 31 + "2a", 1)
        await other.apply_token_balance_delta(TOKEN, _hex(ALICE), D("12.5"))
        await other.apply_account_balance_delta(_hex(BOB), D("0.25"))
        await other.apply_account_balance_delta(_hex(ALICE), D(5))
        assert await state_proofs.proof_root(other, 7) == a
    finally:
        await other.close()
        os.remove(path)


async def test_a_zero_balance_is_absent_and_a_rollback_forgets_its_heights(db):
    await _rows(db)
    await _seal(db, 1)
    await db.apply_token_balance_delta(TOKEN, _hex(ALICE), D("-12.5"))
    signed = await _seal(db, 2)
    t = await state_proofs.prove(db, "token", TOKEN, _hex(ALICE))
    assert t["entry"] is None and state_proofs.verify_against(signed, t)
    await state_proofs.undo_above(db, 1)
    with pytest.raises(ValueError):
        await state_proofs.prove(db, "account", _hex(ALICE), height=2)


async def test_the_feature_binds_the_proof_root_into_the_unified_root():
    assert unified_state_root(*PARTS.values()) != unified_state_root(*PARTS.values(), "ab" * 32)
    assert unified_state_root(*PARTS.values(), None) == unified_state_root(*PARTS.values())


# ── on chain: the precompile ────────────────────────────────────────────────

async def _block(db, height, state_root):
    await db.connection.execute(
        "INSERT INTO blocks (block_hash, block_height, content, timestamp) VALUES (?, ?, ?, 0)",
        (f"{height:064x}", height, repr({"number": height, "state_root": state_root})))
    await db.connection.commit()


async def test_a_contract_verifies_a_proof_against_an_ancestor_block(chain):
    signed = await _seal(chain.db, 1)
    await _block(chain.db, 1, signed)
    p = await state_proofs.prove(chain.db, "account", _hex(ALICE), height=1)
    r = await chain.tx(ALICE, STATE_PROOF_ADDRESS, encode(p))      # executes at height 2
    assert r.success and int.from_bytes(r.output, "big") == 1
    bad = await chain.tx(ALICE, STATE_PROOF_ADDRESS, encode(_tamper(p)))
    assert bad.success and int.from_bytes(bad.output, "big") == 0
    nobody = await state_proofs.prove(chain.db, "account", "0x" + "ee" * 20, height=1)
    r = await chain.tx(ALICE, STATE_PROOF_ADDRESS, encode(nobody))
    assert int.from_bytes(r.output, "big") == 1
    junk = await chain.tx(ALICE, STATE_PROOF_ADDRESS, b"\x01\x02")
    assert junk.success and int.from_bytes(junk.output, "big") == 0  # never reverts


async def test_only_an_ancestor_can_be_proven_against(chain):
    signed = await _seal(chain.db, 1)
    await _block(chain.db, 1, signed)
    p = await state_proofs.prove(chain.db, "account", _hex(ALICE), height=1)
    future = dict(p, height=50)                                      # not below this block
    await _block(chain.db, 50, signed)
    r = await chain.tx(ALICE, STATE_PROOF_ADDRESS, encode(future))
    assert int.from_bytes(r.output, "big") == 0


async def test_a_reopened_store_keeps_its_tree(tmp_path):
    """The tree, its marks and its version live in the store's file: a node restarted between
    two blocks folds the second into the tree it kept, to the root a node that never stopped (or
    one built from the final rows alone) has — a deleted row's leaf included."""
    path = str(tmp_path / "n.db")
    db = await DatabaseSQLite.create(path)
    await _rows(db)
    await state_proofs.proof_root(db, 1)
    await db.connection.commit()
    await db.close()
    db = await DatabaseSQLite.create(path)
    try:
        db.store["account_state"].delete(to_account_id(_hex(BOB)))
        await db.apply_token_balance_delta(TOKEN, _hex(ALICE), D("-9.5"))
        got = await state_proofs.proof_root(db, 2)
        fresh_path = str(tmp_path / "fresh.db")
        fresh = await DatabaseSQLite.create(fresh_path)
        try:
            await fresh.apply_account_balance_delta(_hex(ALICE), D(5))
            await fresh.apply_token_balance_delta(TOKEN, _hex(ALICE), D(3))
            fresh.store["contract_storage"].put(
                _hex(BOB), "0x" + "00" * 31 + "07", "0x" + "00" * 31 + "2a", 1)
            assert got == await state_proofs.proof_root(fresh, 2)
        finally:
            await fresh.close()
    finally:
        await db.close()


def _odd(rng):
    """A column value as the store may hold one: plain and odd numerals, ids in either case, a
    PQ address, words with and without 0x, text, ints of any size."""
    return rng.choice([
        None, "", "0", "1", "-1", "1.9", "-1.9", "12.5", ".5", "5.", "+3", " 3", "1e3", "NaN",
        "0E-18", "1_000", "١", "99999999999999999999999999999999999999999999999999999999999999999999999999999999",
        0, 7, -7, 2**255, 2**256, 2**300,
        "0x" + "ab" * 20, "0X" + "AB" * 20, "0x" + "Ab" * 20, " 0x" + "ab" * 20, "0x" + "zz" * 20,
        "0xPQ" + "11" * 32, "QRDX", "0x" + "cd" * 32, "cd" * 32, "0x" + "cd" * 31, "ab " * 21,
    ])


_PLAIN = {
    "id": lambda rng: "0x" + f"{rng.randrange(50):040x}",
    "word": lambda rng: rng.choice([None, "", "0x" + f"{rng.randrange(10**9):064x}",
                                    f"{rng.randrange(10**9):064x}"]),
    "amount": lambda rng: rng.choice(["0", str(rng.randrange(10**30)),
                                      str(rng.randrange(10**6)) + ".25", "7.000000000000000001"]),
    "nonce": lambda rng: rng.randrange(1000),
}
# each kind's key columns and value columns, by what they hold
_SHAPE = {
    "account": (("id",), ("amount", "nonce", "word", "word")),
    "storage": (("id", "word"), ("word",)),
    "token": (("id", "id"), ("amount",)),
}


@pytest.mark.parametrize("seed", range(6))
def test_the_native_entries_are_pythons(seed):
    """``smt_entries`` (the module) against ``identity`` and the entry functions, on rows of
    every kind with odd values: each entry it computes is Python's, and what it hands back
    (None) Python computes."""
    import random

    import qrdx_native as N

    from qrdx.crypto import smt
    from qrdx.store import pack

    rng = random.Random(seed)
    handed, native = 0, 0
    for kind, (table, ident_cols, cols) in state_proofs.TABLES.items():
        nkey = len(ident_cols)
        items, rows = [], []
        key_shape, value_shape = _SHAPE[kind]
        for _ in range(300):
            key = tuple(_odd(rng) if rng.random() < 0.1 else _PLAIN[k](rng) for k in key_shape)
            vals = None if rng.random() < 0.1 else tuple(
                _odd(rng) if rng.random() < 0.1 else _PLAIN[k](rng) for k in value_shape)
            items.append((pack(key), None if vals is None else pack(vals)))
            rows.append((key, vals))
        at = list(range(len(cols)))
        for (key, vals), got in zip(rows, N.smt_entries(kind, items, at)):
            if got is None:
                handed += 1
                continue
            native += 1
            want_key = smt.key_of(state_proofs.identity(kind, *key))
            want = None if vals is None else state_proofs._ENTRY[kind](*key, *vals)
            assert got == (want_key, want), (kind, key, vals)
    assert native > 600 and handed > 100
