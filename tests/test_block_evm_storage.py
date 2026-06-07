"""
E-D3a — per-block EVM-section storage (foundation for execute-on-mine + replay).

The account/EVM analog of tests/test_block_exchange_storage.py: the raw EVM txs
included in a block are persisted in canonical order for deterministic import
replay and chain rebuild.
"""

import os
import tempfile

from eth_account import Account
from qrdx.database_sqlite import DatabaseSQLite


async def _db():
    path = tempfile.mktemp(suffix=".db")
    return await DatabaseSQLite.create(db_path=path), path


def _raw(i, nonce=0):
    key = "0x" + f"{i:064x}"
    acct = Account.from_key(key)
    tx = {"nonce": nonce, "gasPrice": 10 ** 9, "gas": 21000,
          "to": acct.address, "value": 1, "data": b"", "chainId": 1}
    signed = Account.sign_transaction(tx, key)
    raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
    return "0x" + bytes(raw).hex()


async def test_round_trip_preserves_order():
    db, path = await _db()
    try:
        section = [_raw(1), _raw(2, nonce=1), _raw(3)]
        await db.add_block_evm_txs("blk_a", section)
        assert await db.get_block_evm_txs("blk_a") == section
    finally:
        await db.close(); os.remove(path)


async def test_empty_is_noop():
    db, path = await _db()
    try:
        await db.add_block_evm_txs("blk_empty", [])
        assert await db.get_block_evm_txs("blk_empty") == []
    finally:
        await db.close(); os.remove(path)


async def test_idempotent_and_isolated():
    db, path = await _db()
    try:
        s = [_raw(4), _raw(5)]
        await db.add_block_evm_txs("blk_b", s)
        await db.add_block_evm_txs("blk_b", s)  # again
        assert len(await db.get_block_evm_txs("blk_b")) == 2
        await db.add_block_evm_txs("blk_c", [_raw(6)])
        assert len(await db.get_block_evm_txs("blk_c")) == 1
        assert await db.get_block_evm_txs("blk_missing") == []
    finally:
        await db.close(); os.remove(path)


async def test_remove_blocks_cleans_orphaned_evm_sections():
    db, path = await _db()
    try:
        # Block present in canonical chain.
        await db.add_block(block_hash="h5", block_height=5, block_content="",
                           validator_address="0xPQ" + "00" * 32, timestamp=1)
        await db.add_block_evm_txs("h5", [_raw(7)])
        # Orphaned section (no matching block row).
        await db.add_block_evm_txs("orphan", [_raw(8)])
        await db.remove_blocks(0)  # rolls back everything
        assert await db.get_block_evm_txs("orphan") == []
    finally:
        await db.close(); os.remove(path)
