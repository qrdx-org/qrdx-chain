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
