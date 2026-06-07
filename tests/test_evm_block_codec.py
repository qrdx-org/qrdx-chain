"""
E-D2 — EVM block-body codec.

Before EVM transactions can be included in blocks, they must serialize into the
block body and come back faithful (and still authenticate) and deterministically.
The account/EVM analog of tests/test_exchange_block_codec.py.
See docs/EVM_STATE_CONSENSUS_INTEGRATION.md §6 (E-D2).
"""

import json

import pytest
from eth_account import Account

from qrdx.contracts.evm_block import (
    encode_evm_txs, decode_evm_txs, evm_txs_canonical_bytes,
    extract_evm_transactions_from_dict, BLOCK_EVM_TXS_KEY,
)
from qrdx.contracts.evm_mempool import parse_eth_raw_tx


def _raw(i, nonce=0):
    key = "0x" + f"{i:064x}"
    acct = Account.from_key(key)
    tx = {"nonce": nonce, "gasPrice": 10 ** 9, "gas": 21000,
          "to": acct.address, "value": 1, "data": b"", "chainId": 1}
    signed = Account.sign_transaction(tx, key)
    raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
    return "0x" + bytes(raw).hex()


class TestRoundTrip:
    def test_fields_and_authenticity_preserved(self):
        txs = [_raw(1), _raw(2, nonce=3)]
        decoded = decode_evm_txs(encode_evm_txs(txs))
        assert decoded == txs
        # Each decoded tx still recovers its sender (authenticity survives).
        for tx in decoded:
            assert parse_eth_raw_tx(tx)["sender"].startswith("0x")

    def test_json_safe(self):
        txs = [_raw(3), _raw(4)]
        wire = json.loads(json.dumps(encode_evm_txs(txs)))
        assert decode_evm_txs(wire) == txs

    def test_normalizes_missing_0x_prefix(self):
        raw = _raw(5)
        assert encode_evm_txs([raw[2:]]) == [raw]
        assert decode_evm_txs([raw[2:]]) == [raw]

    def test_non_hex_rejected_on_encode(self):
        with pytest.raises(ValueError):
            encode_evm_txs(["not-hex"])


class TestCanonicalBytes:
    def test_deterministic(self):
        txs = [_raw(6), _raw(7)]
        assert evm_txs_canonical_bytes(txs) == evm_txs_canonical_bytes(txs)

    def test_order_sensitive(self):
        a, b = _raw(8), _raw(9)
        assert evm_txs_canonical_bytes([a, b]) != evm_txs_canonical_bytes([b, a])

    def test_tamper_sensitive(self):
        txs = [_raw(10), _raw(11)]
        before = evm_txs_canonical_bytes(txs)
        txs[1] = _raw(11, nonce=99)  # different tx
        assert evm_txs_canonical_bytes(txs) != before


class TestExtraction:
    def test_extract_from_block_dict(self):
        txs = [_raw(12), _raw(13)]
        block = {"number": 5, BLOCK_EVM_TXS_KEY: encode_evm_txs(txs)}
        assert extract_evm_transactions_from_dict(block) == txs

    def test_backward_compat_and_safety(self):
        assert extract_evm_transactions_from_dict({"number": 5}) == []
        assert extract_evm_transactions_from_dict({"number": 5, BLOCK_EVM_TXS_KEY: []}) == []
        assert extract_evm_transactions_from_dict(None) == []
        assert decode_evm_txs(None) == []
