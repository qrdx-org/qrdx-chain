"""
Phase D2.2a — proposer-side block-body assembly with the exchange section.

`assemble_pos_block_data` builds the broadcast/storage payload for a proposed
PoS block. The exchange section must be:
  - present only when exchange txs are included (additive / backward compatible);
  - encoded so importers can recover the txs (and they still authenticate);
  - absent for empty input (legacy blocks unaffected).
"""

from decimal import Decimal

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.validator.node_integration import assemble_pos_block_data
from qrdx.exchange import (
    ExchangeTransaction,
    ExchangeOpType,
    extract_exchange_transactions_from_dict,
    verify_exchange_tx,
    BLOCK_EXCHANGE_TXS_KEY,
)


class _FakeBlock:
    """Minimal stand-in for PoSBlock (only what the assembler reads)."""
    def __init__(self, hash_, proposer, timestamp=123):
        self.hash = hash_
        self.proposer_address = proposer
        self.timestamp = timestamp

    def to_dict(self):
        return {"hash": self.hash, "proposer_address": self.proposer_address,
                "timestamp": self.timestamp}


def _signed_tx(nonce):
    key = PQPrivateKey.generate()
    addr = key.public_key.to_address()
    tx = ExchangeTransaction(
        op_type=ExchangeOpType.PLACE_ORDER, sender=addr, nonce=nonce,
        params={"pair": "qBTC:qUSD", "side": "buy", "order_type": "limit",
                "price": "30000", "amount": "1"},
        gas_limit=1_000_000, gas_price=Decimal("1"),
    )
    tx.public_key = key.public_key.to_bytes()
    tx.signature = key.sign(tx.signing_bytes()).to_bytes()
    return tx


def test_no_exchange_section_when_empty():
    block = _FakeBlock("ab" * 32, "0xPQ" + "11" * 32)
    for arg in (None, []):
        data = assemble_pos_block_data(block, 7, arg)
        assert BLOCK_EXCHANGE_TXS_KEY not in data, "empty input must not add the section"
        assert data["id"] == 7
        assert data["block_hash"] == block.hash
        assert data["validator_address"] == block.proposer_address


def test_exchange_section_present_and_recoverable():
    block = _FakeBlock("cd" * 32, "0xPQ" + "22" * 32)
    txs = [_signed_tx(0), _signed_tx(1)]
    data = assemble_pos_block_data(block, 9, txs)
    assert BLOCK_EXCHANGE_TXS_KEY in data
    recovered = extract_exchange_transactions_from_dict(data)
    assert [t.tx_hash() for t in recovered] == [t.tx_hash() for t in txs]


def test_included_exchange_txs_still_authenticate():
    """Authentication must survive proposer assembly → import recovery."""
    block = _FakeBlock("ef" * 32, "0xPQ" + "33" * 32)
    txs = [_signed_tx(0)]
    data = assemble_pos_block_data(block, 3, txs)
    recovered = extract_exchange_transactions_from_dict(data)
    ok, err = verify_exchange_tx(recovered[0])
    assert ok, f"included exchange tx failed to authenticate after assembly: {err}"


def test_core_fields_match_legacy_shape():
    """The non-exchange fields must match the existing broadcast payload shape."""
    block = _FakeBlock("aa" * 32, "0xPQ" + "44" * 32, timestamp=999)
    data = assemble_pos_block_data(block, 12, None)
    assert set(data) >= {"id", "block_content", "block_hash", "validator_address"}
    assert data["block_content"] == str(block.to_dict())
