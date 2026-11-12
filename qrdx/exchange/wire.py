"""
Exchange transactions in binary (chain-spec feature ``binary_exchange_txs``; docs/EXCHANGE_ENGINE.md).

A transaction's JSON form carries its ML-DSA signature (3,309 bytes) and public key (1,952) as
hex: a plain transfer is about 10.5 KB, and every block hashes, stores and relays that. The
binary form carries them as bytes, the rest as compact fields:

    version (1)  op_type (u8)  chain_id, nonce, gas_limit (varints)
    gas_price    a varint (tag 0) or its text (tag 1: a value that is not a whole number)
    timestamp    a big-endian float64
    sender, signer, params, signature, public_key — each a varint length and its bytes
                 (signer empty when there is none; params as sorted, compact JSON)

Inside a JSON block body it travels as base64 (``to_text`` / ``from_text``): 7 KB for that
transfer. Between peers the transport carries the bytes themselves.

The form is a carrier only: a transaction decoded from it is the transaction encoded — the
same signing bytes, the same hash, the same fields as its JSON form gives — and encoding is a
function of the transaction (parameters sorted), so a block rebuilt from a node's own copies of
its transactions (a compact block) is byte for byte the proposer's. Anything malformed is a
``ValueError`` before anything reads it (tests/test_exchange_wire.py fuzzes it).
"""

from __future__ import annotations

import base64
import binascii
import json
import struct
from typing import Any, Tuple

VERSION = 1
_MAX_LEN = 1 << 22  # (no field of a transaction is 4 MB)


def _varint(n: int) -> bytes:
    if n < 0:
        raise ValueError("a varint is not negative")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _field(raw: bytes) -> bytes:
    return _varint(len(raw)) + raw


_RESOLVED: list = []


def _native() -> Any:
    """The native reader and writer (native/qrdx-native/src/wire.rs), if the module has them
    (looked up once: every block's every operation asks)."""
    if not _RESOLVED:
        from .. import native

        module = native._native if native.AVAILABLE else None
        _RESOLVED.append(module if module is not None and hasattr(module, "wire_parse") else None)
    return _RESOLVED[0]


def encode(tx: Any) -> bytes:
    """The binary form of an ``ExchangeTransaction``."""
    module = _native()
    if module is not None:
        gp = tx.gas_price
        whole = isinstance(gp, int) and not isinstance(gp, bool) and gp >= 0
        params = json.dumps(tx.params, sort_keys=True, separators=(",", ":"), default=str)
        return module.wire_build(  # type: ignore[no-any-return]
            int(tx.op_type), int(tx.chain_id), int(tx.nonce), int(tx.gas_limit),
            gp if whole else str(gp), float(tx.timestamp), str(tx.sender), tx.signer or "",
            params, bytes(tx.signature or b""), bytes(tx.public_key or b""),
        )  # fmt: skip
    return py_encode(tx)


def py_encode(tx: Any) -> bytes:
    """``encode`` in Python (the reference; and where the native module is not)."""
    gp = tx.gas_price
    if isinstance(gp, int) and not isinstance(gp, bool) and gp >= 0:
        price = b"\x00" + _varint(gp)
    else:
        price = b"\x01" + _field(str(gp).encode())
    params = json.dumps(tx.params, sort_keys=True, separators=(",", ":"), default=str)
    return b"".join(
        (
            bytes((VERSION, int(tx.op_type))),
            _varint(int(tx.chain_id)),
            _varint(int(tx.nonce)),
            _varint(int(tx.gas_limit)),
            price,
            struct.pack(">d", float(tx.timestamp)),
            _field(str(tx.sender).encode()),
            _field((tx.signer or "").encode()),
            _field(params.encode()),
            _field(bytes(tx.signature or b"")),
            _field(bytes(tx.public_key or b"")),
        )
    )


class _Reader:
    def __init__(self, raw: bytes) -> None:
        self.raw, self.at = raw, 0

    def byte(self) -> int:
        if self.at >= len(self.raw):
            raise ValueError("a binary transaction ends early")
        b = self.raw[self.at]
        self.at += 1
        return b

    def varint(self) -> int:
        n = shift = 0
        while True:
            b = self.byte()
            n |= (b & 0x7F) << shift
            if not b & 0x80:
                return n
            shift += 7
            if shift > 70:
                raise ValueError("a varint is too long")

    def take(self, n: int) -> bytes:
        if n > _MAX_LEN or self.at + n > len(self.raw):
            raise ValueError("a binary transaction ends early")
        out = self.raw[self.at : self.at + n]
        self.at += n
        return out

    def field(self) -> bytes:
        return self.take(self.varint())

    def text(self) -> str:
        try:
            return self.field().decode()
        except UnicodeDecodeError:
            raise ValueError("a binary transaction's text is not UTF-8") from None


def decode(raw: Any) -> Any:
    """An ``ExchangeTransaction`` from its binary form, or that form's text (``ValueError`` if it
    is not one)."""
    module = _native()
    if module is None:
        return py_decode(bytes(raw) if isinstance(raw, (bytes, bytearray)) else from_text(raw))
    if isinstance(raw, (str, bytes)):
        read = getattr(module, "wire_read", None)
        fields = read(raw) if read is not None else None
        if fields is not None:
            tx = _from_read(fields, raw)
            if tx is not None:
                return tx
    if not isinstance(raw, (str, bytes)):
        raw = bytes(raw) if isinstance(raw, bytearray) else raw
    try:
        fields = module.wire_parse(raw)
    except TypeError:
        raise ValueError("a binary transaction is bytes or its text") from None
    op_type, chain_id, nonce, gas_limit, (_text, price), timestamp = fields[:6]
    sender, signer, params, signature, public_key = fields[6:]
    try:
        loaded = json.loads(params)
    except (json.JSONDecodeError, RecursionError):
        raise ValueError("a binary transaction's params are not JSON") from None
    data = {
        "op_type": op_type,
        "sender": sender,
        "nonce": int(nonce),
        "params": loaded,
        "gas_limit": int(gas_limit),
        "gas_price": int(price) if not _text else price,
        "timestamp": timestamp,
        "chain_id": int(chain_id),
    }
    if signer:
        data["signer"] = signer
    tx = ExchangeTransaction.from_dict(data)  # (its own checks, as the JSON form's)
    tx.signature, tx.public_key = signature, public_key
    return tx


def _from_read(fields: Any, given: Any) -> Any:
    """The transaction ``wire_read`` read whole (src/xfer.rs; docs/NATIVE.md): the fields
    ``from_dict`` sets, as it sets them for this form, and what the node would otherwise compute
    again — its signed bytes, its hash, its binary form and text — remembered on it, under the
    same keys as ``tx_hash``, ``to_wire`` and ``to_text`` keep them. None for an operation type
    no transaction has (Python's path refuses it, with the reason)."""
    (op, chain_id, nonce, gas_limit, gas_price, timestamp, sender, pairs, signature,
     public_key, canonical, tx_hash, raw, own_text) = fields  # fmt: skip
    try:
        op_type = ExchangeOpType(op)
    except ValueError:
        return None
    tx = ExchangeTransaction.__new__(ExchangeTransaction)
    d = tx.__dict__
    d.update(
        op_type=op_type,
        sender=sender,
        nonce=nonce,
        params=dict(pairs),
        gas_limit=gas_limit,
        gas_price=gas_price,
        timestamp=timestamp,
        signature=signature,
        public_key=public_key,
        chain_id=chain_id,
        signer="",
        gas_used=0,
        success=False,
        result={},
        error="",
    )
    key = tx._fingerprint()
    d["_bytes_memo"] = (key, canonical)
    d["_hash_memo"] = (key, tx_hash)
    d["_wire_memo"] = ((key, timestamp, signature, public_key), raw)
    if own_text:
        d["_text_memo"] = (raw, given)
    return tx


def py_decode(raw: bytes) -> Any:
    """``decode`` in Python, of the binary form (the reference)."""
    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError("a binary transaction is bytes")
    r = _Reader(bytes(raw))
    if r.byte() != VERSION:
        raise ValueError("unknown binary transaction version")
    op_type = r.byte()
    chain_id, nonce, gas_limit = r.varint(), r.varint(), r.varint()
    tag = r.byte()
    if tag == 0:
        gas_price: Any = r.varint()
    elif tag == 1:
        gas_price = r.text()
    else:
        raise ValueError("unknown gas price form")
    (timestamp,) = struct.unpack(">d", r.take(8))
    sender, signer = r.text(), r.text()
    try:
        params = json.loads(r.text())
    except (json.JSONDecodeError, RecursionError):
        raise ValueError("a binary transaction's params are not JSON") from None
    signature, public_key = r.field(), r.field()
    if r.at != len(r.raw):
        raise ValueError("bytes after a binary transaction")
    data = {
        "op_type": op_type,
        "sender": sender,
        "nonce": nonce,
        "params": params,
        "gas_limit": gas_limit,
        "gas_price": gas_price,
        "timestamp": timestamp,
        "chain_id": chain_id,
    }
    if signer:
        data["signer"] = signer
    tx = ExchangeTransaction.from_dict(data)  # (its own checks, as the JSON form's)
    tx.signature, tx.public_key = signature, public_key
    return tx


def peek(item: Any) -> Tuple[int, int, Any]:
    """(op_type, gas_limit, gas_price) of a transaction in its binary form or its text, read from
    the head alone (a section's gas and fees are summed before anything is decoded); the whole
    decoded only for a gas price written as text."""
    if isinstance(item, str):
        raw = from_text(item[:64])  # (48 bytes: past every field before the price's value)
        if raw[:1] != bytes((VERSION,)):
            raise ValueError("unknown binary transaction version")
    else:
        raw = bytes(item)
    r = _Reader(raw)
    try:
        if r.byte() != VERSION:
            raise ValueError("unknown binary transaction version")
        op_type = r.byte()
        r.varint()  # (chain id)
        r.varint()  # (nonce)
        gas_limit = r.varint()
        if r.byte() == 0:
            return op_type, gas_limit, r.varint()
    except ValueError:
        pass
    tx = decode(bytes(item) if isinstance(item, (bytes, bytearray)) else from_text(item))
    return int(tx.op_type), int(tx.gas_limit), tx.gas_price


def to_text(raw: bytes) -> str:
    module = _native()
    if module is not None:
        return module.wire_text(raw)  # type: ignore[no-any-return]
    return base64.b64encode(raw).decode("ascii")


def from_text(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise ValueError("a binary transaction's text is not base64") from None


def is_text(item: Any) -> bool:
    """A section item in the binary form's text (rather than a JSON object)."""
    return isinstance(item, str)


# (Bound after the module: transactions.py imports this one.)
from .transactions import ExchangeOpType, ExchangeTransaction  # noqa: E402
