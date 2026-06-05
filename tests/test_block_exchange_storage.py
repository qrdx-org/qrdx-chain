"""
Phase D2.2b — per-block exchange-section storage (protocol-level state).

The receiver persists a block's exchange-transaction section on import so it is
durable and replayable (D3). These tests cover the DB round-trip and ordering.
"""

import tempfile
import os

import pytest

from decimal import Decimal
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import ExchangeTransaction, ExchangeOpType, encode_exchange_txs


async def _make_db():
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    return db, path


def _signed_section(n):
    txs = []
    for i in range(n):
        key = PQPrivateKey.generate()
        tx = ExchangeTransaction(
            op_type=ExchangeOpType.PLACE_ORDER, sender=key.public_key.to_address(),
            nonce=0,
            params={"pair": "qBTC:qUSD", "side": "buy", "order_type": "limit",
                    "price": "30000", "amount": str(i + 1)},
            gas_limit=1_000_000, gas_price=Decimal("1"),
        )
        tx.public_key = key.public_key.to_bytes()
        tx.signature = key.sign(tx.signing_bytes()).to_bytes()
        txs.append(tx)
    return txs


async def test_store_and_load_round_trip():
    db, path = await _make_db()
    try:
        txs = _signed_section(3)
        section = encode_exchange_txs(txs)
        await db.add_block_exchange_txs("blockhash_aaa", section)

        loaded = await db.get_block_exchange_txs("blockhash_aaa")
        assert len(loaded) == 3
        # order + tx_hash preserved
        assert [d["tx_hash"] for d in loaded] == [t.tx_hash() for t in txs]
        # decodes back to authentic transactions
        from qrdx.exchange import decode_exchange_txs, verify_exchange_tx
        for tx in decode_exchange_txs(loaded):
            assert verify_exchange_tx(tx)[0]
    finally:
        await db.close()
        os.remove(path)


async def test_empty_section_is_noop():
    db, path = await _make_db()
    try:
        await db.add_block_exchange_txs("blockhash_empty", [])
        assert await db.get_block_exchange_txs("blockhash_empty") == []
    finally:
        await db.close()
        os.remove(path)


async def test_idempotent_insert():
    db, path = await _make_db()
    try:
        section = encode_exchange_txs(_signed_section(2))
        await db.add_block_exchange_txs("blockhash_idem", section)
        await db.add_block_exchange_txs("blockhash_idem", section)  # again
        loaded = await db.get_block_exchange_txs("blockhash_idem")
        assert len(loaded) == 2, "re-storing the same section must not duplicate"
    finally:
        await db.close()
        os.remove(path)


async def test_per_block_isolation():
    db, path = await _make_db()
    try:
        await db.add_block_exchange_txs("block_A", encode_exchange_txs(_signed_section(1)))
        await db.add_block_exchange_txs("block_B", encode_exchange_txs(_signed_section(2)))
        assert len(await db.get_block_exchange_txs("block_A")) == 1
        assert len(await db.get_block_exchange_txs("block_B")) == 2
        assert await db.get_block_exchange_txs("block_missing") == []
    finally:
        await db.close()
        os.remove(path)
