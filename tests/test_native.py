"""
The native module (native/qrdx-native; qrdx/native.py; docs/NATIVE.md) gives exactly what the
Python it stands in for gives. It feeds consensus (a block's body root, its signature verdicts),
so a single byte or verdict apart would split nodes that have it from nodes that do not.

Held here against Python itself, on random inputs:

* ``canonical_json`` against ``json.dumps(sort_keys=True, ensure_ascii=True)``, in both separator
  styles and with ``default=str``: unicode, escapes and control characters, surrogate pairs,
  huge and negative integers, floats with their special values, nesting, tuples, subclasses.
  What it does not reproduce (a key that is not a string, an unpaired surrogate) falls back to
  Python through ``qrdx.native``, and an object that is not serializable fails the same way;
* ``mldsa65_verify_batch`` against liboqs through Python, valid and tampered;
* a block's body root and a section's verification verdicts, with the module and without it.
"""

import enum
import json
import random
from decimal import Decimal

import pytest

N = pytest.importorskip("qrdx_native")

from qrdx import native  # noqa: E402

ALPHABET = ['a', 'Z', '0', ' ', '"', '\\', '/', '\n', '\r', '\t', '\b', '\f', '\x00', '\x1f',
            '\x7f', 'é', 'ß', '€', '中', ' ', '😀', '\U0010ffff', '~', '{', '}', ',', ':']


def _text(rng):
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 12)))


class _Op(enum.IntEnum):
    A = 7


class _Str(str):
    pass


def _value(rng, depth=0, floats=True):
    kinds = ["str", "int", "bool", "none"] + (["float"] if floats else [])
    if depth < 4:
        kinds += ["dict", "list", "tuple"]
    k = rng.choice(kinds)
    if k == "str":
        return _Str(_text(rng)) if rng.random() < 0.1 else _text(rng)
    if k == "int":
        return rng.choice([0, 1, -1, 2 ** 63 - 1, -(2 ** 63), 2 ** 64, -(10 ** 30), 10 ** 40,
                           _Op.A, rng.randint(-10 ** 6, 10 ** 6)])
    if k == "float":
        return rng.choice([0.0, -0.0, 1.5, -2.25, 1e16, 1e-7, 123456789.125, 1 / 3, 2.0 ** 70,
                           float("inf"), float("-inf"), float("nan"), rng.uniform(-1e9, 1e9)])
    if k == "bool":
        return rng.random() < 0.5
    if k == "none":
        return None
    if k == "dict":
        return {_text(rng): _value(rng, depth + 1, floats) for _ in range(rng.randint(0, 5))}
    items = [_value(rng, depth + 1, floats) for _ in range(rng.randint(0, 5))]
    return items if k == "list" else tuple(items)


def _python(obj, compact=True, default_str=False):
    kwargs = {"sort_keys": True, "ensure_ascii": True}
    if compact:
        kwargs["separators"] = (",", ":")
    if default_str:
        kwargs["default"] = str
    return json.dumps(obj, **kwargs).encode()


@pytest.mark.parametrize("seed", range(40))
def test_canonical_json_is_pythons_byte_for_byte(seed):
    rng = random.Random(seed)
    for _ in range(50):
        obj = _value(rng)
        for compact in (True, False):
            assert bytes(N.canonical_json(obj, compact, False)) == _python(obj, compact)


def test_default_str_writes_what_python_writes():
    obj = {"amount": Decimal("1.50"), "nested": [Decimal("-0"), {"x": Decimal("1E+3")}]}
    assert bytes(N.canonical_json(obj, False, True)) == _python(obj, False, True)
    assert native.canonical_json(obj, False, True) == _python(obj, False, True)


def test_what_it_does_not_reproduce_falls_back_to_python():
    for obj in ({1: "int key"}, {"x": "\ud800"}, {"\udfff": 1}):
        with pytest.raises(N.Unsupported):
            N.canonical_json(obj)
        assert native.canonical_json(obj) == _python(obj)


def test_an_unserializable_object_fails_as_in_python():
    with pytest.raises(TypeError):
        N.canonical_json({"x": object()})
    with pytest.raises(TypeError):
        native.canonical_json({"x": object()})


@pytest.mark.parametrize("seed", range(10))
def test_body_root_is_the_same_with_and_without_the_module(seed, monkeypatch):
    import hashlib

    rng = random.Random(seed)
    body = {"attestations": [_value(rng) for _ in range(3)], "slashing_evidence": [],
            "graffiti": _text(rng), "exchange_transactions": [_value(rng) for _ in range(20)],
            "evm_transactions": ["0x" + "ab" * 40]}
    expected = hashlib.sha256(b"qrdx-block-body:" + _python(body)).hexdigest()
    assert N.body_root_sha256(b"qrdx-block-body:", body) == expected
    assert native.body_root(b"qrdx-block-body:", body) == expected
    monkeypatch.setattr(native, "_native", None)
    assert native.body_root(b"qrdx-block-body:", body) == expected


def test_signature_verdicts_are_liboqs_through_python():
    from qrdx.crypto.pq.dilithium import PQPrivateKey, PQPublicKey, PQSignature, verify

    rng = random.Random(1)
    keys = [PQPrivateKey.generate() for _ in range(4)]
    items = []
    for i in range(60):
        key = keys[i % 4]
        msg = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 400)))
        sig = key.sign(msg).to_bytes()
        pk = key.public_key.to_bytes()
        kind = i % 6
        if kind == 1:
            msg = msg + b"!"                                    # another message
        elif kind == 2:
            sig = sig[:100] + bytes([sig[100] ^ 1]) + sig[101:]  # a flipped bit
        elif kind == 3:
            pk = keys[(i + 1) % 4].public_key.to_bytes()          # another key
        elif kind == 4:
            sig = sig[:-1]                                      # too short
        items.append((pk, msg, sig))

    def python(pk, msg, sig):
        try:
            return verify(PQPublicKey.from_bytes(pk), msg, PQSignature.from_bytes(sig))
        except Exception:
            return False

    assert N.mldsa65_verify_batch(items) == [python(*it) for it in items]
    assert sum(N.mldsa65_verify_batch(items)) == 20                 # kinds 0 and 5 only


async def test_a_sections_verdicts_are_the_same_with_and_without_the_module(monkeypatch):
    from qrdx.constants import CHAIN_ID
    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.exchange import ExchangeOpType, ExchangeTransaction
    from qrdx.exchange.block_processor import verify_exchange_txs

    keys = [PQPrivateKey.generate() for _ in range(5)]
    wire = []
    for i in range(40):
        k = keys[i % 5]
        t = ExchangeTransaction(op_type=ExchangeOpType.TOKEN_TRANSFER, sender=k.public_key.to_address(),
                                nonce=i, params={"token_address": "QRDX", "to": "0xPQ" + "b" * 64,
                                                 "amount": "1"},
                                gas_limit=40_000, gas_price=10 ** 9, chain_id=CHAIN_ID)
        t.public_key = k.public_key.to_bytes()
        t.signature = k.sign(t.signing_bytes()).to_bytes()
        d = t.to_dict()
        if i % 7 == 3:
            d["params"]["amount"] = "2"                           # tampered after signing
        if i % 11 == 5:
            d["sender"] = keys[(i + 1) % 5].public_key.to_address()  # not the key's address
        wire.append(d)

    def fresh():
        return [ExchangeTransaction.from_dict(json.loads(json.dumps(d))) for d in wire]

    with_module = await verify_exchange_txs(fresh())
    monkeypatch.setattr(native, "_native", None)
    monkeypatch.setattr(native, "AVAILABLE", False)
    without = await verify_exchange_txs(fresh())
    assert with_module == without
    assert 0 < sum(ok for ok, _ in with_module) < len(wire)


def test_the_transport_json_writes_what_json_writes():
    """qrdx/fastjson.py: orjson writes the transport; readers get the same values as from
    Python's json, and what orjson cannot write exactly is written by json."""
    import enum

    from qrdx import fastjson

    class _Op(enum.IntEnum):
        A = 3

    rng = random.Random(7)
    for _ in range(300):
        obj = _value(rng, floats=False)
        assert json.loads(fastjson.dumps(obj)) == json.loads(json.dumps(obj))
    for obj in ({"big": 2 ** 70, "neg": -(10 ** 25)}, {"x": _Op.A, 2: "int key"},
                [{"k": "\ud800"}], {"amount": Decimal("1.5")}):
        try:
            expected = json.loads(json.dumps(obj, default=str))
        except Exception:
            continue
        assert json.loads(fastjson.dumps(obj, default=str)) == expected
    assert fastjson.loads(b'{"x": 123456789012345678901234567890}') == {
        "x": 123456789012345678901234567890}


# ── the database domains' LtHash trigger function (qrdx/state_commitment.py) ──


def _column(rng):
    k = rng.random()
    if k < 0.35:
        return "".join(rng.choice("0123456789abcdefxPQ.-é😀\x00 ") for _ in range(rng.randint(0, 40)))
    if k < 0.55:
        return rng.choice([0, 1, -7, 2 ** 70, 10 ** 30])
    if k < 0.65:
        return None
    if k < 0.75:
        return rng.choice([1.5, -0.0, 1e300])                      # (handed to Python)
    if k < 0.8:
        return b"\x00raw"                                          # (handed to Python)
    return rng.choice(["0", "0.000", "-0", "0E-18", "1", "999.000001", " 0", "0_0", "NaN",
                       "1e", "1e1234567", "sNaN", "Infinity", "+.0", "5.", "١"])


@pytest.mark.parametrize("seed", range(4))
def test_the_trigger_function_answers_as_python(seed):
    from qrdx.crypto import lthash
    from qrdx.state_commitment import _udf_apply

    rng = random.Random(seed)
    accs = [lthash.ZERO, lthash.mix(lthash.ZERO, None, lthash.entry(b"x", b"y"))]
    for _ in range(600):
        acc = rng.choice(accs)
        if rng.random() < 0.03:
            acc = acc[:-4] if rng.random() < 0.5 else b"\xff" * len(acc)   # (malformed)
        kind = rng.choice(["account", "storage", "token", "utxo", "token", "nope"])
        args = (acc, kind, rng.choice([0, 1]), rng.choice([0, 1]),
                *(_column(rng) for _ in range(10)))
        try:
            want = ("ok", _udf_apply(*args))
        except Exception as e:
            want = ("raised", type(e))
        try:
            got = ("ok", N.lt_apply(*args))
        except Exception as e:
            got = ("raised", type(e))
        assert got == want, args
        if want[0] == "ok" and len(want[1]) == lthash.SIZE and want[1] not in accs:
            accs.append(want[1])


async def test_the_accumulators_with_the_native_function_are_the_rows(tmp_path):
    """Through SQLite's triggers: random writes to every domain's tables, then the accumulators
    the native function kept against the ones recomputed from the rows."""
    import aiosqlite

    from qrdx import state_commitment as sc

    assert native.lt_apply_function() is N.lt_apply
    rng = random.Random(5)
    async with aiosqlite.connect(tmp_path / "s.db") as conn:
        await conn.execute("CREATE TABLE account_state (address TEXT PRIMARY KEY, balance TEXT, "
                           "nonce INTEGER, code_hash TEXT, storage_root TEXT)")
        await conn.execute("CREATE TABLE contract_storage (contract_address TEXT, storage_key "
                           "TEXT, storage_value TEXT, PRIMARY KEY (contract_address, storage_key))")
        await conn.execute("CREATE TABLE token_balances (token_address TEXT, holder_address TEXT,"
                           " balance TEXT, PRIMARY KEY (token_address, holder_address))")
        await conn.execute("CREATE TABLE unspent_outputs (tx_hash TEXT, output_index INTEGER, "
                           "address TEXT, amount TEXT, PRIMARY KEY (tx_hash, output_index))")
        await sc.install(conn)
        for _ in range(400):
            a = f"0xPQ{rng.randrange(30):064x}"
            amount = rng.choice(["0", "1.5", str(rng.randrange(10 ** 6)), "0E-18", "12.000"])
            k = rng.random()
            if k < 0.3:
                await conn.execute("INSERT OR REPLACE INTO account_state VALUES (?, ?, ?, ?, ?)",
                                   (a, amount, rng.randrange(9), None, ""))
            elif k < 0.5:
                await conn.execute("INSERT OR REPLACE INTO token_balances VALUES (?, ?, ?)",
                                   ("0xTOKEN", a, amount))
            elif k < 0.6:
                await conn.execute("INSERT OR REPLACE INTO contract_storage VALUES (?, ?, ?)",
                                   (a, str(rng.randrange(5)), amount))
            elif k < 0.7:
                await conn.execute("INSERT OR REPLACE INTO unspent_outputs VALUES (?, ?, ?, ?)",
                                   (a, rng.randrange(3), a, amount))
            elif k < 0.85:
                await conn.execute("UPDATE token_balances SET balance = ? WHERE holder_address = ?",
                                   (amount, a))
            else:
                await conn.execute("DELETE FROM account_state WHERE address = ?", (a,))
        await conn.commit()
        for domain in sc.DOMAINS:
            assert await sc.stored_accumulator(conn, domain) == await sc.full_accumulator(conn, domain)


def test_the_trigger_function_is_faster():
    import timeit

    from qrdx.crypto import lthash
    from qrdx.state_commitment import _udf_apply

    args = (lthash.ZERO, "account", 1, 1, "0xPQ" + "a" * 64, "1000.000001", 3, "", "",
            "0xPQ" + "a" * 64, "999.000001", 4, "", "")
    assert N.lt_apply(*args) == _udf_apply(*args)
    python = min(timeit.repeat(lambda: _udf_apply(*args), number=300, repeat=3))
    rust = min(timeit.repeat(lambda: N.lt_apply(*args), number=300, repeat=3))
    assert rust < python / 2, (rust, python)


# ── the state-proof tree's update (qrdx/crypto/smt.py) ──


@pytest.mark.parametrize("seed", range(6))
async def test_the_tree_update_is_pythons(seed):
    """Random changes over many versions, from an empty cache (every node named missing first,
    loaded, the update run again): the same root, the same writes in the same order, the same
    stale nodes, version after version."""
    from qrdx.crypto import smt

    rng = random.Random(seed)
    store: dict = {}                       # the node table, shared by both
    py_root = nat_root = None
    keys = [smt.key_of(bytes([seed, i])) for i in range(60)]
    if seed % 2:                           # (keys sharing long prefixes: deep paths)
        keys = [bytes([0xAB] * 3) + k[3:] for k in keys]

    async def load(nkey):
        return store.get(nkey)

    for version in range(1, 40):
        changes = {}
        for _ in range(rng.randint(1, 25)):
            changes[rng.choice(keys)] = (None if rng.random() < 0.3
                                         else bytes(rng.randrange(256) for _ in range(rng.randint(0, 40))))
        changes = sorted(changes.items())
        tree = smt.Tree(load, version)
        py_root = await tree.update(py_root, changes)
        cache: dict = {}
        encoded = smt.encode_ref(nat_root)
        for _ in range(300):
            out = N.smt_update(encoded, changes, version, cache)
            if out[0] == "ok":
                break
            assert out[1], "missing names no node"
            for nkey in out[1]:
                cache[nkey] = store[nkey]
        assert out[0] == "ok"
        nat_root = smt.Ref.decode(out[1])[0]
        assert nat_root == py_root
        assert list(out[2]) == list(tree.writes.items())
        assert list(out[3]) == tree.stale
        store.update(tree.writes)
    assert py_root is not None


def test_a_bad_root_or_key_is_refused():
    with pytest.raises(ValueError):
        N.smt_update(b"\x09", [], 1, {})
    with pytest.raises(ValueError):
        N.smt_update(b"\x00", [(b"short", None)], 1, {})


def _py_tree_items(node):
    if node is None:
        return []
    if node.is_leaf:
        return [(node.key, node.payload)]
    return _py_tree_items(node.left) + _py_tree_items(node.right)


@pytest.mark.parametrize("seed", range(8))
def test_the_in_memory_tree_is_pythons(seed):
    """The exchange's proof trees (qrdx/crypto/smt.py ``m_*``): random changes, block after
    block, natively and through Python's reference — the same root every time, the same proof
    of every key (held, deleted, never held), the same entries; a copy of an old root is still
    that root after later updates, and an update that changes nothing changes no hash."""
    import copy
    import pickle

    from qrdx.crypto import smt

    rng = random.Random(seed)
    keys = [smt.key_of(bytes([seed, i])) for i in range(80)]
    if seed % 2:                           # (keys sharing long prefixes: deep paths)
        keys = [bytes([0x5A] * 4) + k[4:] for k in keys]
    py = nat = None
    held = {}
    for _ in range(60):
        changes = {}
        for _ in range(rng.randint(1, 30)):
            changes[rng.choice(keys)] = (None if rng.random() < 0.35
                                         else bytes(rng.randrange(256) for _ in range(rng.randint(0, 30))))
        changes = sorted(changes.items())
        before, before_root = nat, smt.m_root(nat)
        py = smt._py_update(py, changes)
        nat = N.mt_update(nat, changes)
        assert smt.m_root(nat) == smt.m_root(py)
        assert smt.m_root(before) == before_root and copy.deepcopy(before) is before
        for k, v in changes:
            if v is None:
                held.pop(k, None)
            else:
                held[k] = v
        assert _py_tree_items(nat) == sorted(held.items()) == _py_tree_items(py)
        for k in rng.sample(keys, 10) + [smt.key_of(b"never")]:
            assert N.mt_prove(nat, k) == smt._py_prove(py, k)
        same = [(keys[0], held[keys[0]])] if keys[0] in held else [(keys[0], None)]
        assert smt.m_root(N.mt_update(nat, same)) == smt.m_root(nat)
    rebuilt = N.mt_build(sorted(held.items()))
    assert smt.m_root(rebuilt) == smt.m_root(smt._py_build(sorted(held.items())))
    assert smt.m_root(pickle.loads(pickle.dumps(nat))) == smt.m_root(nat)


def test_the_in_memory_tree_refuses_what_python_never_meant():
    from qrdx.crypto import smt

    k = smt.key_of(b"k")
    with pytest.raises(ValueError):
        N.mt_update(None, [(b"short", b"x")])
    with pytest.raises(ValueError):
        N.mt_update(None, [(k, b"x"), (k, None)])
    with pytest.raises(ValueError):
        N.mt_prove(None, b"short")
    with pytest.raises(TypeError):
        N.mt_update(smt._py_build([(k, b"x")]), [])          # (Python's nodes go to Python)
    one = N.mt_build([(k, b"x")])
    assert N.mt_update(one, [(k, b"x")]) is not None
    assert smt.m_root(N.mt_update(one, [(k, None)])) == smt.EMPTY


@pytest.mark.parametrize("seed", range(6))
def test_the_exchange_accumulator_mix_is_pythons(seed):
    from qrdx.crypto import lthash
    from qrdx.exchange import commitment as C

    rng = random.Random(seed)
    acc = lthash.ZERO
    for _ in range(20):
        removed = [rng.randbytes(32) for _ in range(rng.randint(0, 40))]
        added = [rng.randbytes(32) for _ in range(rng.randint(0, 40))]
        r, a = lthash.Accumulator(), lthash.Accumulator()
        for d in removed:
            r.add(C._vector("t", d))
        for d in added:
            a.add(C._vector("t", d))
        want = C._apply(acc, r, a)
        assert N.lt_mix_entries(acc, b"qrdx/exchange/t", removed, added) == want
        assert C._apply_digests(acc, "t", removed, added) == want
        acc = want
    assert N.lt_mix_entries(b"\x01" * lthash.SIZE, b"t", [], []) is None   # (not well formed)
    assert N.lt_mix_entries(b"\x00" * 7, b"t", [], []) is None
