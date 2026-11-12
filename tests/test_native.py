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
    for i in range(60):
        k = keys[i % 5]
        params = {"token_address": "QRDX", "to": "0xPQ" + "b" * 64, "amount": "1"}
        sender, chain, gas = k.public_key.to_address(), CHAIN_ID, 40_000
        # (signed as they are, yet refused by a check besides the signature — or not)
        if i % 13 == 7:
            chain = CHAIN_ID + 1                                  # another network
        if i % 17 == 9:
            gas = 1                                               # below the operation's cost
        if i % 19 == 11:
            del params["to"]                                      # malformed
        if i % 23 == 13:
            sender = sender.lower()                               # the address in another case
        t = ExchangeTransaction(op_type=ExchangeOpType.TOKEN_TRANSFER, sender=sender,
                                nonce=i, params=params,
                                gas_limit=gas, gas_price=10 ** 9, chain_id=chain)
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
    assert with_module == without  # (and the refusals worded alike)
    assert 0 < sum(ok for ok, _ in with_module) < len(wire)
    assert {why.split(":")[0] for ok, why in with_module if not ok} >= {"invalid structure"}


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


# ── the database domains' LtHash accumulators, kept by the store (qrdx/state_commitment.py) ──


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


async def test_the_store_keeps_the_accumulators_python_computes(tmp_path):
    """Through the store (qrdx/store.py), which folds rows natively: random writes to every
    domain's tables, with the column values the trigger function is checked on (odd numerals,
    bytes, Unicode digits), then the accumulators it kept against Python's from the rows."""
    from qrdx import state_commitment as sc
    from qrdx.database_sqlite import DatabaseSQLite

    rng = random.Random(5)
    db = await DatabaseSQLite.create(str(tmp_path / "s.db"))
    try:
        accounts, tokens = db.store["account_state"], db.store["token_balances"]
        for _ in range(400):
            a = f"0xPQ{rng.randrange(30):064x}"
            amount = rng.choice(["0", "1.5", str(rng.randrange(10 ** 6)), "0E-18", "12.000",
                                 _column(rng)])
            k = rng.random()
            if k < 0.3:
                accounts.put(address=a, balance=amount, nonce=rng.randrange(9), storage_root="")
            elif k < 0.5:
                tokens.put("0xTOKEN", a, amount, 0)
            elif k < 0.6:
                db.store["contract_storage"].put(a, str(rng.randrange(5)), amount, 0)
            elif k < 0.7:
                db.store["unspent_outputs"].put(a, rng.randrange(3), a, rng.randrange(99))
            elif k < 0.85:
                tokens.update(("0xTOKEN", a), balance=amount)
            else:
                accounts.delete(a)
            if rng.random() < 0.05:
                await db.connection.commit()
        await db.connection.commit()
        for domain in sc.DOMAINS:
            assert await sc.stored_accumulator(db, domain) == await sc.full_accumulator(db, domain)
    finally:
        await db.close()


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


@pytest.mark.parametrize("seed", range(6))
async def test_the_tree_update_into_native_nodes_is_pythons(seed):
    """``smt_update_into`` over a native node cache (``SmtNodes``, small enough to evict): the
    same root as Python's tree, version after version, and the new and stale nodes packed
    exactly as the store keeps them (``pack((nkey,))`` → ``pack((data,))``, ``pack((version,
    nkey))`` → ``pack(())``)."""
    from qrdx.crypto import smt
    from qrdx.store import pack

    rng = random.Random(seed)
    store: dict = {}
    py_root = nat_root = None
    keys = [smt.key_of(bytes([seed, i])) for i in range(60)]
    if seed % 2:
        keys = [bytes([0xAB] * 3) + k[3:] for k in keys]
    nodes = N.SmtNodes(40)  # (fewer than the tree's nodes: some are evicted and loaded again)

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
        encoded = smt.encode_ref(nat_root)
        for _ in range(300):
            out = N.smt_update_into(encoded, changes, version, nodes)
            if out[0] == "ok":
                break
            assert out[1], "missing names no node"
            nodes.insert_many([(nkey, store[nkey]) for nkey in out[1]])
        assert out[0] == "ok"
        nat_root = smt.Ref.decode(out[1])[0]
        assert nat_root == py_root
        assert sorted(out[2]) == sorted((pack((k,)), pack((d,))) for k, d in tree.writes.items())
        assert sorted(out[3]) == sorted((pack((version, k)), pack(())) for k in tree.stale)
        for k, d in tree.writes.items():
            assert nodes.get(k) in (d, None)  # (held as written, unless evicted)
        store.update(tree.writes)
    assert py_root is not None and len(nodes) <= 40  # (down to capacity after each update)


def test_the_tree_update_writes_into_a_store_what_it_would_return(tmp_path):
    """Given the store and its tables, ``smt_update_into`` writes the new and stale nodes there
    itself: the very rows it returns packed otherwise."""
    from qrdx.crypto import smt
    from qrdx.store import Spec, Store

    specs = [Spec("smt_nodes", [("nkey", "TEXT")], [("data", "BLOB", b"")]),
             Spec("smt_stale", [("version", "INTEGER"), ("nkey", "TEXT")], [])]
    rng = random.Random(7)
    keys = [smt.key_of(bytes([i])) for i in range(80)]
    store = Store(str(tmp_path / "t"), specs)
    try:
        a, b = N.SmtNodes(1000), N.SmtNodes(1000)
        root_a = root_b = None
        tables = (store["smt_nodes"].id, store["smt_stale"].id)
        returned = {"smt_nodes": [], "smt_stale": []}
        for version in range(1, 15):
            changes = sorted({rng.choice(keys): (None if rng.random() < 0.2 else rng.randbytes(20))
                              for _ in range(15)}.items())
            out_a = N.smt_update_into(smt.encode_ref(root_a), changes, version, a)
            out_b = N.smt_update_into(smt.encode_ref(root_b), changes, version, b,
                                      store.native, tables)
            assert out_a[0] == out_b[0] == "ok" and out_a[1] == out_b[1]
            assert (len(out_a[2]), len(out_a[3])) == (out_b[2], out_b[3])
            returned["smt_nodes"] += out_a[2]
            returned["smt_stale"] += out_a[3]
            root_a = root_b = smt.Ref.decode(out_a[1])[0]
        for table, rows in returned.items():
            assert store.native.scan(store[table].id) == sorted(dict(rows).items())
    finally:
        store.close()


def test_the_native_node_cache_keeps_the_most_recently_used():
    from qrdx.crypto import smt

    nodes = N.SmtNodes(10)
    nodes.insert_many([(f"k{i}", bytes([i])) for i in range(25)])
    assert len(nodes) == 25  # (loads before any update settled: none evicted)
    out = N.smt_update_into(smt.encode_ref(None), [], 1, nodes)  # (an update settles…)
    assert out[0] == "ok" and len(nodes) == 9  # (…down to nine tenths of capacity)
    assert "k24" in nodes and "k0" not in nodes  # (the most recently used kept)
    assert nodes.get("k16") == b"\x10"  # (k16 used since: kept until the next update)
    nodes.insert_many([(f"n{i}", b"x") for i in range(30)])  # (past twice capacity: what was
    assert "k17" not in nodes and "k16" in nodes  # last used before the update goes)
    assert all(f"n{i}" in nodes for i in range(30))


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
