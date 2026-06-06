"""
Phase D3 (reorg safety + restart durability) — rebuild exchange state from chain.

`rebuild_exchange_state_from_chain` replays every canonical block's stored
exchange section in order, making exchange state a deterministic function of the
canonical chain. This is the mechanism behind:
  - restart durability (rebuild from stored sections on startup), and
  - reorg safety (after a rollback, rebuild to the new canonical tip).

Covers:
  - rebuild applies stored sections and is deterministic;
  - a rolled-back block's effect disappears after rebuild (reorg safety);
  - remove_blocks drops orphaned sections;
  - an empty chain rebuilds to the empty-state root.
"""

import os
import tempfile
from decimal import Decimal

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import (
    ExchangeStateManager,
    ExchangeTransaction,
    ExchangeOpType,
    encode_exchange_txs,
    rebuild_exchange_state_from_chain,
)
from qrdx.exchange.amm import FeeTier, PoolType


async def _db():
    path = tempfile.mktemp(suffix=".db")
    return await DatabaseSQLite.create(db_path=path), path


def _sign(tx, key):
    tx.public_key = key.public_key.to_bytes()
    tx.signature = key.sign(tx.signing_bytes()).to_bytes()
    return tx


def _create_pool_section():
    k = PQPrivateKey.generate()
    tx = _sign(ExchangeTransaction(
        op_type=ExchangeOpType.CREATE_POOL, sender=k.public_key.to_address(), nonce=0,
        params={"token0": "qBTC", "token1": "qUSD", "fee_tier": int(FeeTier.MEDIUM),
                "pool_type": int(PoolType.STANDARD), "initial_sqrt_price": "173.205080756",
                "stake_amount": "10000"},
        gas_limit=1_000_000, gas_price=Decimal("1")), k)
    return encode_exchange_txs([tx])


def _order_section():
    k = PQPrivateKey.generate()
    tx = _sign(ExchangeTransaction(
        op_type=ExchangeOpType.PLACE_ORDER, sender=k.public_key.to_address(), nonce=0,
        params={"pair": "qBTC:qUSD", "side": "sell", "order_type": "limit",
                "price": "30000", "amount": "1"},
        gas_limit=1_000_000, gas_price=Decimal("1")), k)
    return encode_exchange_txs([tx])


async def _add_block(db, height, ex_section=None):
    bh = f"{height:064x}"
    await db.add_block(block_hash=bh, block_height=height, block_content="",
                       validator_address="0xPQ" + "00" * 32, timestamp=1_700_000_000 + height)
    if ex_section:
        await db.add_block_exchange_txs(bh, ex_section)
    return bh


async def test_rebuild_applies_sections_and_is_deterministic():
    db, path = await _db()
    try:
        await _add_block(db, 0)                          # genesis, no exchange
        await _add_block(db, 1, _create_pool_section())  # creates a pair
        await _add_block(db, 2, _order_section())        # places an order

        empty = ExchangeStateManager().compute_state_root()
        root1 = await rebuild_exchange_state_from_chain(db)
        assert root1 != empty, "rebuild must apply the stored sections"
        # Pair present after rebuild.
        assert ExchangeStateManager.get_instance().pool_count >= 1

        # Deterministic: a second rebuild yields the identical root.
        root2 = await rebuild_exchange_state_from_chain(db)
        assert root1 == root2
    finally:
        await db.close()
        os.remove(path)


async def test_reorg_rollback_drops_orphaned_effect():
    db, path = await _db()
    try:
        await _add_block(db, 0)
        await _add_block(db, 1, _create_pool_section())
        await _add_block(db, 2, _order_section())

        root_at_2 = await rebuild_exchange_state_from_chain(db)
        pools_at_2 = ExchangeStateManager.get_instance().pool_count

        # Reorg: roll back block 2 (drops its section via remove_blocks cleanup).
        await db.remove_blocks(2)
        assert await db.get_block_exchange_txs(f"{2:064x}") == [], "orphaned section must be removed"

        root_at_1 = await rebuild_exchange_state_from_chain(db)
        # Block 2's order is gone; block 1's pool remains.
        assert root_at_1 != root_at_2, "rolled-back block effect must disappear"
        assert ExchangeStateManager.get_instance().pool_count == pools_at_2 >= 1
    finally:
        await db.close()
        os.remove(path)


async def test_empty_chain_rebuilds_to_empty_root():
    db, path = await _db()
    try:
        await _add_block(db, 0)  # no exchange activity
        empty = ExchangeStateManager().compute_state_root()
        # Note: empty-state root still commits to block_height=0 inside the
        # manager; rebuild over a section-less chain leaves state empty.
        root = await rebuild_exchange_state_from_chain(db)
        assert root == empty
        assert ExchangeStateManager.get_instance().pool_count == 0
    finally:
        await db.close()
        os.remove(path)
