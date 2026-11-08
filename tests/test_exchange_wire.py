"""
Exchange transactions in binary (qrdx/exchange/wire.py; chain-spec feature
``binary_exchange_txs``): a carrier only.

Random transactions — every operation type, params of every JSON shape (nested, floats, unicode,
booleans, nulls, empty), a signer or none, a multisig keyset, whole and fractional gas prices,
odd timestamps — go through the binary form, its text and back: the same fields as the JSON
form gives, the same signed bytes, the same hash; and the form does not depend on the order of
the params (a block rebuilt from a node's own copies is the proposer's). The native transport's
reader works out the same hash and signed bytes from the binary form as from the JSON form.
Malformed input — truncated, flipped, random, trailing bytes — is a ``ValueError`` in Python and
refused (or left to Python) natively, never anything else. A block section is in the form its
height carries.
"""

import json
import random

import pytest

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import ExchangeOpType, ExchangeTransaction, wire
from qrdx.exchange.block_processor import (
    decode_exchange_txs,
    encode_exchange_txs,
    section_form_error,
)

KEY = PQPrivateKey.generate()
PK = KEY.public_key.to_bytes()


def _value(rng, depth=0):
    k = rng.random()
    if depth > 2 or k < 0.3:
        return rng.choice(["1.5", "QRDX", "0x" + "ab" * 20, "été ✓", "", "-0", "1e-18"])
    if k < 0.4:
        return rng.choice([0, 1, -7, 2**63, 10**30])
    if k < 0.5:
        return rng.choice([0.1, 1e-7, 2.5e300, -0.0, 3.0])
    if k < 0.6:
        return rng.choice([True, False, None])
    if k < 0.8:
        return [_value(rng, depth + 1) for _ in range(rng.randint(0, 3))]
    return {f"k{rng.randint(0, 9)}{c}": _value(rng, depth + 1) for c in "xyz"[: rng.randint(0, 3)]}


def _tx(rng):
    params = {rng.choice(["pair", "amount", "to", "side", "z", "a", "nested"]): _value(rng)
              for _ in range(rng.randint(0, 5))}
    t = ExchangeTransaction(
        op_type=rng.choice(list(ExchangeOpType)), sender=KEY.public_key.to_address(),
        nonce=rng.choice([0, 1, 2**32, 2**64 - 1]), params=params,
        gas_limit=rng.choice([0, 60_000, 2**64 - 1]),
        gas_price=rng.choice([10**9, 0, 1, 2**70]),
        timestamp=rng.choice([0.0, 1_700_000_000.25, 1e-9]),
        chain_id=rng.choice([0, 1, 7777, 2**40]),
        signer=rng.choice(["", "", "0xPQ" + "cd" * 32]),
    )
    t.public_key = rng.choice([PK, b"", b'{"keys": ["aa"], "threshold": 1}'])
    t.signature = rng.choice([b"\x01" * 3309, b"", bytes(rng.randrange(256) for _ in range(40))])
    return t


@pytest.mark.parametrize("seed", range(4))
def test_a_transaction_is_the_same_in_binary(seed):
    rng = random.Random(seed)
    for _ in range(300):
        t = _tx(rng)
        for back in (ExchangeTransaction.from_any(t.to_text()),
                     ExchangeTransaction.from_any(t.to_wire()),
                     ExchangeTransaction.from_wire(t.to_wire())):
            assert back.to_dict() == ExchangeTransaction.from_dict(json.loads(
                json.dumps(t.to_dict()))).to_dict()
            assert back.tx_hash() == t.tx_hash()
            assert back.signing_bytes() == t.signing_bytes()
            assert (back.signature, back.public_key) == (t.signature, t.public_key)
        # (the params' order does not change the form)
        shuffled = dict(reversed(list(t.params.items())))
        twin = ExchangeTransaction.from_dict({**t.to_dict(), "params": shuffled})
        twin.signature, twin.public_key = t.signature, t.public_key
        assert twin.to_wire() == t.to_wire()


def test_a_transfer_is_half_its_json_and_two_thirds_in_a_body():
    t = ExchangeTransaction(op_type=ExchangeOpType.TOKEN_TRANSFER, sender=KEY.public_key.to_address(),
                            nonce=3, params={"token_address": "QRDX", "to": "0xPQ" + "a" * 64,
                                             "amount": "1.5"}, gas_limit=60_000, gas_price=10**9)
    t.public_key, t.signature = PK, b"\x02" * 3309
    as_json = len(json.dumps(t.to_dict(), separators=(",", ":")))
    assert len(t.to_wire()) < 0.51 * as_json
    assert len(t.to_text()) < 0.68 * as_json


@pytest.mark.parametrize("seed", range(3))
def test_the_native_reader_reads_both_forms_alike(seed):
    native = pytest.importorskip("qrdx_native")
    rng = random.Random(seed)
    checked = 0
    for _ in range(200):
        t = _tx(rng)
        a = native.tx_read(json.dumps(t.to_dict()).encode())
        b = native.tx_read(t.to_wire())
        if a[0] == "checked":
            assert b[0] in ("checked", "python")
        if a[0] == b[0] == "checked":
            assert a[1] == b[1] == t.tx_hash() and a[2] == b[2] == t.signing_bytes()
            checked += 1
    assert checked > 50


@pytest.mark.parametrize("seed", range(3))
def test_malformed_binary_is_refused(seed):
    native = pytest.importorskip("qrdx_native")
    rng = random.Random(seed)
    for _ in range(400):
        raw = bytearray(_tx(rng).to_wire())
        k = rng.random()
        if k < 0.3:
            raw = raw[: rng.randrange(len(raw))]
        elif k < 0.6:
            for _ in range(rng.randint(1, 4)):
                raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
        elif k < 0.7:
            raw += bytes(rng.randrange(256) for _ in range(rng.randint(1, 5)))
        else:
            raw = bytearray([1]) + bytes(rng.randrange(256) for _ in range(rng.randint(0, 80)))
        try:
            t = wire.decode(bytes(raw))
            assert t.tx_hash()  # (decoded: it is a whole transaction)
        except ValueError:
            pass
        assert native.tx_read(bytes(raw))[0] in ("checked", "python", "malformed")
    for text in ("", "not base64!", "QUJD", "AQ=="):
        with pytest.raises(ValueError):
            ExchangeTransaction.from_any(text)


def test_a_section_is_in_the_form_its_height_carries(monkeypatch):
    from qrdx import chain_spec

    rng = random.Random(9)
    txs = [_tx(rng) for _ in range(3)]
    monkeypatch.setattr(chain_spec, "is_active", lambda feature, height: height >= 10)
    old, new = encode_exchange_txs(txs, 9), encode_exchange_txs(txs, 10)
    assert all(isinstance(i, dict) for i in old) and all(isinstance(i, str) for i in new)
    assert [t.tx_hash() for t in decode_exchange_txs(old)] == [t.tx_hash() for t in txs]
    assert [t.tx_hash() for t in decode_exchange_txs(new)] == [t.tx_hash() for t in txs]
    assert section_form_error(old, 9) == section_form_error(new, 10) == ""
    assert "binary" in section_form_error(old, 10) and "object" in section_form_error(new, 9)


async def test_a_binary_section_is_stored_relayed_and_imported(monkeypatch):
    """Through what a node does with a block's section: its gas and fees summed (the block's
    limits, its children's base fees), stored and read back (with and without the operations
    decoded beside it), held for peers, and imported — transfers that run."""
    import os
    import tempfile

    from qrdx.block_limits import block_resource_error, exchange_section_gas
    from qrdx.database_sqlite import DatabaseSQLite
    from qrdx.exchange import ExchangeStateManager
    from qrdx.exchange import block_processor as BP
    from qrdx.fee_market import fee_gas
    from qrdx.node import block_import, netd
    from qrdx.node import main as node_main

    sender = KEY.public_key.to_address()
    to = "0xPQ" + "e" * 64
    txs = []
    for n in range(3):
        t = ExchangeTransaction(op_type=ExchangeOpType.TOKEN_TRANSFER, sender=sender, nonce=n,
                                params={"token_address": "QRDX", "to": to, "amount": "2"},
                                gas_limit=60_000, gas_price=10**9)
        t.public_key, t.signature = PK, KEY.sign(t.signing_bytes()).to_bytes()
        txs.append(t)
    section = encode_exchange_txs(txs, 2)
    as_json = [t.to_dict() for t in txs]
    assert all(isinstance(i, str) for i in section)
    assert exchange_section_gas(section) == exchange_section_gas(as_json) == 180_000
    assert block_resource_error({"exchange_transactions": section}, height=2) == ""
    assert fee_gas(section, ()) == fee_gas(as_json, ())
    held = []

    class Service:
        def missing(self, hashes):
            return hashes

        def hold(self, items):
            held.extend(items)

    monkeypatch.setattr(netd, "SERVICE", Service())
    netd.hold_section([t.tx_hash() for t in txs], section)
    assert [ExchangeTransaction.from_wire(raw).tx_hash() for _h, raw in held] == \
        [t.tx_hash() for t in txs]

    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    try:
        monkeypatch.setattr(node_main, "db", db, raising=False)
        await db.add_block(block_hash="00" * 32, block_height=0, block_content="",
                           validator_address="0xPQ" + "00" * 32, timestamp=1_700_000_000)
        await db.add_transaction(tx_hash="alloc", block_hash="00" * 32, tx_hex=json.dumps(
            {"type": "genesis_allocation", "recipient": sender, "amount": "1000"}))
        await db.seed_genesis_account_state()
        for name, objects in (("a1" * 32, None), ("b2" * 32, txs)):
            await db.add_block_exchange_txs(name, section, objects)
            stored = await db.get_block_exchange_txs(name)
            assert [t.tx_hash() for t in decode_exchange_txs(stored)] == [t.tx_hash() for t in txs]
        ExchangeStateManager.reset_instance()
        BP.apply_enforcement(ExchangeStateManager.get_instance())
        ok, err = await block_import._apply_exchange_section_on_import(
            2, 1_700_000_002.0, section, None)
        assert ok, err
        assert ExchangeStateManager.get_instance()._nonces.get(sender) == 3
    finally:
        ExchangeStateManager.reset_instance()
        await db.connection.close()
        os.unlink(path)


@pytest.mark.parametrize("seed", range(3))
def test_the_native_codec_is_pythons(seed):
    """native/qrdx-native/src/wire.rs: the same bytes from the same transaction, the same
    transaction from the same bytes or text, and the same refusals."""
    import base64

    if wire._native() is None:
        pytest.skip("the native module is off (QRDX_NATIVE=0) or not installed")
    rng = random.Random(seed)

    def outcome(fn, arg):
        try:
            t = fn(arg)
        except ValueError:
            return "refused"
        return (t.to_dict(), t.signature, t.public_key)

    for _ in range(300):
        t = _tx(rng)
        raw = wire.encode(t)
        assert raw == wire.py_encode(t)
        assert wire.to_text(raw) == base64.b64encode(raw).decode()
        assert outcome(wire.decode, raw) == outcome(wire.py_decode, raw)
        assert outcome(wire.decode, wire.to_text(raw)) == outcome(wire.py_decode, raw)
        bent = bytearray(raw)
        k = rng.random()
        if k < 0.4:
            bent = bent[: rng.randrange(len(bent))]
        elif k < 0.8:
            bent[rng.randrange(len(bent))] ^= 1 << rng.randrange(8)
        else:
            bent += b"\x00"
        assert outcome(wire.decode, bytes(bent)) == outcome(wire.py_decode, bytes(bent))
    for text in ("", "Zg=", "Zg==Zg==", "Zm9v!", "AQ==", "AQIDBA=="):
        with pytest.raises(ValueError):
            wire.decode(text)
