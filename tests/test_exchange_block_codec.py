"""
Phase D2 (sub-step 1) — exchange-tx block-body codec.

Before exchange transactions can be included in blocks, they must serialize into
the block body and come back byte-for-byte faithful — including their PQ
signatures, so authentication survives a network round trip — and deterministically,
so all validators encode an identical body for the same ordered set.

Covers (see docs/EXCHANGE_PRODUCTION_READINESS.md §4 Phase D2):
  - round-trip fidelity (fields + tx_hash);
  - signature survives the round trip (decoded tx still verifies);
  - determinism + order sensitivity of the canonical bytes;
  - tamper sensitivity;
  - backward compatibility (blocks without the section decode to empty).
"""

import json
from decimal import Decimal

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import (
    ExchangeTransaction,
    ExchangeOpType,
    encode_exchange_txs,
    decode_exchange_txs,
    exchange_txs_canonical_bytes,
    extract_exchange_transactions_from_dict,
    BLOCK_EXCHANGE_TXS_KEY,
    verify_exchange_tx,
)


def _signed_tx(nonce, side="buy", amount="1"):
    key = PQPrivateKey.generate()
    addr = key.public_key.to_address()
    tx = ExchangeTransaction(
        op_type=ExchangeOpType.PLACE_ORDER,
        sender=addr,
        nonce=nonce,
        params={"pair": "qBTC:qUSD", "side": side, "order_type": "limit",
                "price": "30000", "amount": amount},
        gas_limit=1_000_000,
        gas_price=Decimal("1"),
    )
    tx.public_key = key.public_key.to_bytes()
    tx.signature = key.sign(tx.signing_bytes()).to_bytes()
    return tx


class TestRoundTrip:
    def test_fields_and_hash_preserved(self):
        txs = [_signed_tx(0), _signed_tx(1, side="sell", amount="2.5")]
        decoded = decode_exchange_txs(encode_exchange_txs(txs))
        assert len(decoded) == len(txs)
        for a, b in zip(txs, decoded):
            assert a.tx_hash() == b.tx_hash()
            assert a.sender == b.sender
            assert a.nonce == b.nonce
            assert a.params == b.params
            assert a.op_type == b.op_type

    def test_signature_survives_round_trip(self):
        """The decoded transaction must still authenticate."""
        tx = _signed_tx(0)
        assert verify_exchange_tx(tx)[0]
        decoded = decode_exchange_txs(encode_exchange_txs([tx]))[0]
        ok, err = verify_exchange_tx(decoded)
        assert ok, f"authentication lost across serialization: {err}"

    def test_json_serializable(self):
        """The encoded body must survive a real JSON encode/decode."""
        txs = [_signed_tx(0), _signed_tx(1)]
        wire = json.loads(json.dumps(encode_exchange_txs(txs)))
        decoded = decode_exchange_txs(wire)
        assert [t.tx_hash() for t in decoded] == [t.tx_hash() for t in txs]


class TestCanonicalBytes:
    def test_identical_lists_identical_bytes(self):
        txs = [_signed_tx(0), _signed_tx(1)]
        assert exchange_txs_canonical_bytes(txs) == exchange_txs_canonical_bytes(txs)

    def test_order_sensitive(self):
        a, b = _signed_tx(0), _signed_tx(1)
        assert exchange_txs_canonical_bytes([a, b]) != exchange_txs_canonical_bytes([b, a])

    def test_tamper_sensitive(self):
        txs = [_signed_tx(0), _signed_tx(1)]
        before = exchange_txs_canonical_bytes(txs)
        # Mutate a param after encoding-time (changes tx_hash).
        txs[1].params["amount"] = "999"
        assert exchange_txs_canonical_bytes(txs) != before

    def test_empty_is_stable(self):
        assert exchange_txs_canonical_bytes([]) == exchange_txs_canonical_bytes([])


class TestBlockDictExtraction:
    def test_extract_from_block_dict(self):
        txs = [_signed_tx(0), _signed_tx(1)]
        block = {"number": 5, BLOCK_EXCHANGE_TXS_KEY: encode_exchange_txs(txs)}
        recovered = extract_exchange_transactions_from_dict(block)
        assert [t.tx_hash() for t in recovered] == [t.tx_hash() for t in txs]

    def test_backward_compat_missing_section(self):
        """A legacy block dict with no exchange section decodes to empty."""
        assert extract_exchange_transactions_from_dict({"number": 5}) == []
        assert extract_exchange_transactions_from_dict({"number": 5, BLOCK_EXCHANGE_TXS_KEY: []}) == []
        assert decode_exchange_txs(None) == []

    def test_non_dict_safe(self):
        assert extract_exchange_transactions_from_dict(None) == []
        assert extract_exchange_transactions_from_dict("not-a-dict") == []
