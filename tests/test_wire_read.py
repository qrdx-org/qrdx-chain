"""
An exchange transaction read whole by the native module (``wire_read``, src/xfer.rs): the object
``wire.decode`` builds from it, and what it remembers on it (signed bytes, hash, binary form,
text), are the Python reference's in every field and type — for transactions in the common form
and for every form the native read leaves to Python (a signer, a price in text, params that are
not flat plain strings, a varint or base64 written another way, an unset timestamp).
"""

import base64
import json
import re
import random
import struct

import pytest

from qrdx import native
from qrdx.exchange import ExchangeOpType, ExchangeTransaction, wire

pytestmark = pytest.mark.skipif(
    not native.AVAILABLE or not hasattr(native._native, "wire_read"), reason="native module"
)

FIELDS = (
    "op_type",
    "sender",
    "nonce",
    "params",
    "gas_limit",
    "gas_price",
    "timestamp",
    "signature",
    "public_key",
    "chain_id",
    "signer",
    "gas_used",
    "success",
    "result",
    "error",
)


def _tx(rng):
    op = rng.choice(
        [
            ExchangeOpType.TOKEN_TRANSFER,
            ExchangeOpType.PLACE_ORDER,
            ExchangeOpType.CANCEL_ORDER,
            ExchangeOpType.SWAP,
        ]
    )
    params = {}
    for k in rng.sample(
        [
            "to",
            "amount",
            "token_address",
            "memo",
            "pair",
            "side",
            "order_id",
            "z",
            "A",
            "a b",
            "<&>",
        ],
        rng.randint(0, 5),
    ):
        params[k] = rng.choice(
            [
                "0.001",
                "QRDX",
                "0x" + "ab" * 20,
                "",
                "x y",
                "<&>",
                "~!@#$%",
                "é",
                'a"b',
                "back\\slash",
                "tab\tx",
                7,
                1.5,
                None,
                True,
            ]
        )
    t = ExchangeTransaction(
        op_type=op,
        sender=rng.choice(["0xPQ" + "cd" * 32, "0xPQa", "s"]),
        nonce=rng.choice([0, 1, 127, 128, 2**32, 2**64 - 1]),
        params=params,
        gas_limit=rng.choice([1, 200_000, 2**63]),
        gas_price=rng.choice([10**9, 0, 1, 2**64 - 1, 2**70, "1.5"]),
        timestamp=rng.choice([1.5, 1_700_000_000.25, 1e-300]),
        chain_id=rng.choice([0, 1, 2**62]),
        signer=rng.choice(["", "", "0xPQsigner"]),
    )
    t.signature = rng.randbytes(rng.choice([0, 3309, 10]))
    t.public_key = rng.randbytes(rng.choice([0, 1952, 5]))
    return t


def _reference(item):
    """``wire.decode`` as it read before the native read: the module's parse, ``from_dict``."""

    class Without:
        def __getattr__(self, name):
            if name == "wire_read":
                raise AttributeError(name)
            return getattr(native._native, name)

    real = wire._native
    wire._native = lambda: Without()
    try:
        return wire.decode(item)
    finally:
        wire._native = real


def _same(a, b):
    for f in FIELDS:
        va, vb = getattr(a, f), getattr(b, f)
        assert type(va) is type(vb) and va == vb, f
        if f == "params":
            assert list(va) == list(vb) and [type(x) for x in va.values()] == [
                type(x) for x in vb.values()
            ]
    assert a.tx_hash() == b.tx_hash()
    assert a._canonical_bytes() == b._canonical_bytes() == a.signing_bytes()
    assert a.to_wire() == b.to_wire() and a.to_text() == b.to_text()
    assert a.to_dict() == b.to_dict()


@pytest.mark.parametrize("seed", range(8))
def test_a_transaction_read_natively_is_the_one_python_reads(seed):
    rng = random.Random(seed)
    read = 0
    for _ in range(400):
        t = _tx(rng)
        for item in (t.to_wire(), t.to_text()):
            try:
                ref = _reference(item)
            except ValueError:
                with pytest.raises(ValueError):
                    wire.decode(item)
                continue
            got = wire.decode(item)
            read += "_bytes_memo" in got.__dict__
            _same(got, ref)
    assert read > 50  # (the common form is read natively here too)


def _varint_long(n):
    """``n`` as a varint with a needless continuation byte."""
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | 0x80)
        if n == 0:
            out.append(0)
            return bytes(out)


def test_what_python_reads_another_way_is_left_to_it():
    t = ExchangeTransaction(
        op_type=ExchangeOpType.TOKEN_TRANSFER,
        sender="0xPQa",
        nonce=5,
        params={"amount": "1", "to": "0xPQb"},
        gas_limit=9,
        gas_price=7,
        timestamp=2.0,
        chain_id=3,
    )
    t.signature, t.public_key = b"s" * 4, b"k" * 4
    raw = t.to_wire()
    long_nonce = raw[:3] + _varint_long(5) + raw[4:]  # (version, op, chain id, then the nonce)
    spaced = raw.replace(b'{"amount":"1","to":"0xPQb"}', b'{"amount": "1","to":"0xPQb"}')
    spaced = spaced.replace(bytes([27]), bytes([28]), 0)
    unsorted = raw.replace(b'{"amount":"1","to":"0xPQb"}', b'{"to":"0xPQb","amount":"1"}')
    unset = raw.replace(struct.pack(">d", 2.0), struct.pack(">d", 0.0))
    for item in (long_nonce, unsorted, unset):
        assert native._native.wire_read(item) is None
    assert native._native.wire_read(raw) is not None
    text = base64.b64encode(raw).decode()
    loose = (
        text[:-2] + chr(ord(text[-2]) ^ 1) + "="
        if text.endswith("=") and not text.endswith("==")
        else None
    )
    got = native._native.wire_read(text)
    assert got is not None and got[-1] is True  # (its own text)
    if loose and base64.b64decode(loose) == raw:
        got = native._native.wire_read(loose)
        assert got is not None and got[-1] is False  # (read, but its text not remembered)
        tx = wire.decode(loose)
        assert tx.to_text() == text
    assert json.loads(raw[raw.index(b"{") : raw.index(b"}") + 1]) == t.params


def test_what_it_remembers_gives_way_to_a_change():
    t = ExchangeTransaction(
        op_type=ExchangeOpType.TOKEN_TRANSFER,
        sender="0xPQa",
        nonce=5,
        params={"amount": "1", "to": "0xPQb"},
        gas_limit=9,
        gas_price=7,
        timestamp=2.0,
        chain_id=3,
    )
    t.signature, t.public_key = b"s" * 4, b"k" * 4
    got = wire.decode(t.to_text())
    assert "_hash_memo" in got.__dict__
    got.nonce = 6
    got.params["amount"] = "2"
    fresh = ExchangeTransaction.from_dict({**got.to_dict()})
    assert got.tx_hash() == fresh.tx_hash() != t.tx_hash()
    assert got.to_wire() == fresh.to_wire() and got.to_text() == fresh.to_text()


def test_signatures_and_the_sender_binding_in_one_batch():
    from qrdx.crypto.pq.dilithium import PQPrivateKey

    k = PQPrivateKey.generate()
    pk = k.public_key.to_bytes()
    msg = b"message"
    sig = k.sign(msg).to_bytes()
    address = k.public_key.to_address()
    out = native._native.mldsa65_verify_bind_batch(
        [
            (pk, msg, sig, address),
            (pk, msg, sig, address.lower()),
            (pk, b"other", sig, address),
            (pk, msg, sig, "0xPQ" + "00" * 32),
            (pk[:-1], msg, sig, address),
        ]
    )
    assert out == [(True, True), (True, True), (False, True), (True, False), (False, False)]


def test_a_text_is_remembered_only_if_it_is_the_one_python_writes():
    """Python's decoder takes base64 whose last character before the padding carries stray
    bits; such a text decodes to the same bytes, but is not what the node writes for them."""
    rng = random.Random(3)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    seen = set()
    for n in range(60):
        t = ExchangeTransaction(
            op_type=ExchangeOpType.TOKEN_TRANSFER,
            sender="0xPQa",
            nonce=n,
            params={"amount": "1"},
            gas_limit=9,
            gas_price=7,
            timestamp=2.0,
            chain_id=3,
        )
        t.signature, t.public_key = rng.randbytes(n % 7), b"k"
        raw = t.to_wire()
        text = base64.b64encode(raw).decode()
        pad = len(text) - len(text.rstrip("="))
        seen.add(pad)
        assert native._native.wire_read(text)[-1] is True
        if pad:
            at = len(text) - pad - 1
            for c in alphabet:
                other = text[:at] + c + text[at + 1 :]
                if base64.b64decode(other) == raw:
                    assert native._native.wire_read(other)[-1] is (other == text)
    assert seen == {0, 1, 2}


def _head_items(rng):
    """Transactions' texts and binary forms with every head ``peek`` reads: whole prices of any
    size, a price in text, varints written long (up to Python's eleven bytes, and past it),
    texts shorter than the 64 characters read, malformed and non-ASCII texts."""
    t = _tx(rng)
    raw = t.to_wire()
    out = [raw, t.to_text()]
    # (the chain id, nonce and gas limit rewritten as long varints, or past eleven bytes)
    head = bytes([raw[0], raw[1]])
    fields = [rng.randrange(2**rng.choice([7, 64, 76, 77])) for _ in range(3)]
    for long in (False, True):
        b = bytearray(head)
        for n in fields:
            b += _varint_long(n) if long else _varint(n)
        b += bytes([0]) + _varint(rng.randrange(2**rng.choice([8, 64, 80])))
        out += [bytes(b), base64.b64encode(bytes(b)).decode()]
    over = bytes(head) + bytes([0x80] * 11) + bytes([1, 0, 0, 0, 5])
    out += [base64.b64encode(over + bytes(60)).decode()]
    text = t.to_text()
    out += [
        text[:20] + "!" + text[21:],  # (not base64)
        text[:30] + "é" + text[31:],  # (not ASCII)
        text[:8],  # (shorter than a head)
        base64.b64encode(bytes([2]) + raw[1:]).decode(),  # (another version)
    ]
    return out


def _varint(n):
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        if n == 0:
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def _peeked(item):
    try:
        return wire.peek(item)
    except ValueError as e:
        return ("refused", str(e))


@pytest.mark.parametrize("seed", range(6))
def test_heads_read_together_are_what_peek_reads(seed):
    """``wire.heads`` (natively, ``wire_heads``, for texts in the common form) is ``peek`` of each
    item: the same operation, gas limit and price, of the same types; the same refusal, at the
    first item ``peek`` refuses."""
    rng = random.Random(seed)
    items = [x for _ in range(60) for x in _head_items(rng)]
    native_read = 0
    for item in items:
        want = _peeked(item)
        if want[0] == "refused":
            with pytest.raises(ValueError, match=re.escape(want[1])):
                wire.heads([item])
            continue
        (got,) = wire.heads([item])
        assert got == want and [type(x) for x in got] == [type(x) for x in want]
        native_read += native._native.wire_heads([item])[0] is not None
    assert native_read > 50  # (the common form, and heads written long, read natively)
    good = [i for i in items if _peeked(i)[0] != "refused"]
    assert wire.heads(good) == [wire.peek(i) for i in good]
    first_bad = next(i for i in items if _peeked(i)[0] == "refused")
    with pytest.raises(ValueError, match=re.escape(_peeked(first_bad)[1])):
        wire.heads(good[:5] + [first_bad] + good[5:])


def test_a_block_holds_its_transactions_fingerprints_while_it_runs():
    """``fingerprints_held``: each transaction's fingerprint is held while the block runs (what
    is remembered under it is asked without computing one), and released afterwards — on an
    error too; a hold already in place (another holder's) is left to its holder; a transaction
    changed after the block still hashes as changed."""
    from qrdx.exchange.transactions import fingerprints_held

    def tx(n):
        t = ExchangeTransaction(
            op_type=ExchangeOpType.TOKEN_TRANSFER,
            sender="0xPQa",
            nonce=n,
            params={"amount": "1", "to": "0xPQb", "token_address": "QRDX"},
            gas_limit=9,
            gas_price=7,
            timestamp=2.0,
            chain_id=3,
        )
        t.signature, t.public_key = b"s", b"k"
        return t

    a, b, c = tx(1), tx(2), tx(3)
    c.__dict__["_fp_held"] = theirs = c._fingerprint()  # (another holder's)
    before = [t.tx_hash() for t in (a, b, c)]
    with pytest.raises(RuntimeError):
        with fingerprints_held([a, b, c, "not a transaction"]):
            for t in (a, b):  # (the held value itself: none computed)
                assert t._fingerprint() is t.__dict__["_fp_held"]
            assert [t.tx_hash() for t in (a, b)] == before[:2]
            raise RuntimeError("the block failed")
    assert "_fp_held" not in a.__dict__ and "_fp_held" not in b.__dict__
    assert c.__dict__["_fp_held"] is theirs
    del c.__dict__["_fp_held"]
    a.nonce = 9
    assert a.tx_hash() == tx(9).tx_hash() != before[0]
