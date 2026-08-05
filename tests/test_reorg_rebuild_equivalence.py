"""
Reorg-safety: the rebuild path must reproduce the SAME derived state as incremental
forward application, byte-for-byte.

A node that never reorgs builds account_state + token_balances by applying each block's
exchange section INCREMENTALLY as it arrives (preload → process → flush, never cleared).
A node that reorgs instead CLEARS those ledgers, reseeds genesis, and REBUILDS from the
canonical chain (rebuild_exchange_state_from_chain + the account reseed). For the SAME
canonical chain the two paths MUST yield the identical account_state root + token root —
otherwise a reorged node diverges from the network at equal tip (the recurring
"equal-tip derived-state divergence", E-D4=0 because block history matches).

This test drives BOTH paths over one deterministic chain (no network, no reorg timing)
and asserts the roots match. It is the deterministic reproducer for that divergence:
  * FAIL  → a real determinism bug in the rebuild logic (root cause, right here).
  * PASS  → the rebuild logic is equivalent; any field divergence is a concurrency/race
            during rollback→reseed→reflush, not a replay-nondeterminism.
"""

import json
import os
import tempfile
from decimal import Decimal

import pytest

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import (
    ExchangeStateManager, ExchangeTransaction, ExchangeOpType, encode_exchange_txs,
)
from qrdx.exchange.amm import FeeTier, PoolType
from qrdx.exchange import block_processor as BP


# --- helpers ---------------------------------------------------------------

async def _db():
    path = tempfile.mktemp(suffix=".db")
    return await DatabaseSQLite.create(db_path=path), path


def _sign(tx, key):
    tx.public_key = key.public_key.to_bytes()
    tx.signature = key.sign(tx.signing_bytes()).to_bytes()
    return tx


def _tx(op, sender, nonce, params):
    return ExchangeTransaction(op_type=op, sender=sender, nonce=nonce, params=params,
                               gas_limit=2_000_000, gas_price=Decimal("1"))


async def _add_block(db, height, ex_section=None, genesis_alloc=None):
    bh = f"{height:064x}"
    await db.add_block(block_hash=bh, block_height=height, block_content="",
                       validator_address="0xPQ" + "00" * 32, timestamp=1_700_000_000 + height)
    if genesis_alloc:
        for i, (recipient, amount) in enumerate(genesis_alloc):
            await db.add_transaction(
                tx_hash=f"alloc-{i}-{recipient[:8]}",
                tx_hex=json.dumps({"type": "genesis_allocation", "recipient": recipient,
                                   "amount": str(amount)}),
                block_hash=bh)
    if ex_section:
        await db.add_block_exchange_txs(bh, ex_section)
    return bh


async def _build_chain(db, k1, k2):
    """A rich but HONEST activity chain: token deploy/transfer (cross-holder token
    moves), perp market+open (account_state margin debit), pool create+liquidity
    (pool stake debit + token escrow). Every op is affordable (canonical)."""
    t1, t2 = k1.public_key.to_address(), k2.public_key.to_address()
    tokenA = ExchangeStateManager.derive_token_address(t1, 0, "AAA")
    tokenB = ExchangeStateManager.derive_token_address(t1, 4, "BBB")
    pair = ":".join(sorted([tokenA, tokenB]))
    sqrtp = "79228162514264337593543950336"  # 1.0 in Q96

    await _add_block(db, 0, genesis_alloc=[(t1, "1000000"), (t2, "1000000")])
    await _add_block(db, 1, encode_exchange_txs([_sign(_tx(
        ExchangeOpType.TOKEN_DEPLOY, t1, 0,
        {"name": "A", "symbol": "AAA", "total_supply": "1000000", "decimals": 18}), k1)]))
    await _add_block(db, 2, encode_exchange_txs([_sign(_tx(
        ExchangeOpType.TOKEN_TRANSFER, t1, 1,
        {"token_address": tokenA, "to": t2, "amount": "100000"}), k1)]))
    await _add_block(db, 3, encode_exchange_txs([_sign(_tx(
        ExchangeOpType.CREATE_MARKET, t1, 2,
        {"symbol": "BTC", "max_leverage": "10", "initial_margin_rate": "0.1",
         "maintenance_margin_rate": "0.05"}), k1)]))
    await _add_block(db, 4, encode_exchange_txs([_sign(_tx(
        ExchangeOpType.OPEN_POSITION, t1, 3,
        {"market_id": "BTC-QRDX-PERP", "side": "long", "size": "1", "leverage": "10",
         "price": "30000"}), k1)]))
    await _add_block(db, 5, encode_exchange_txs([_sign(_tx(
        ExchangeOpType.TOKEN_DEPLOY, t1, 4,
        {"name": "B", "symbol": "BBB", "total_supply": "1000000", "decimals": 18}), k1)]))
    await _add_block(db, 6, encode_exchange_txs([_sign(_tx(
        ExchangeOpType.CREATE_POOL, t1, 5,
        {"token0": tokenA, "token1": tokenB, "fee_tier": int(FeeTier.MEDIUM),
         "pool_type": int(PoolType.STANDARD), "initial_sqrt_price": sqrtp,
         "stake_amount": "10000"}), k1)]))
    await _add_block(db, 7, encode_exchange_txs([_sign(_tx(
        ExchangeOpType.ADD_LIQUIDITY, t1, 6,
        {"pair": pair, "amount0": "1000", "amount1": "1000",
         "tick_lower": "-887220", "tick_upper": "887220"}), k1)]))
    return 7


def _set_flags(mgr):
    """Match the production FORWARD import path's enforcement set."""
    mgr.enforce_collateral = BP.ENFORCE_EXCHANGE_COLLATERAL
    mgr.enforce_spot_settlement = BP.ENFORCE_SPOT_SETTLEMENT
    mgr.enforce_orderbook_settlement = BP.ENFORCE_ORDERBOOK_SETTLEMENT
    mgr.enforce_pool_stake = BP.ENFORCE_POOL_STAKE


async def _run_forward(db, tip):
    """Incremental forward application (mirrors _apply_exchange_section_on_import's
    trust-replay branch per block): the non-reorg node's path."""
    await db.seed_genesis_account_state()
    await db.connection.commit()
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    _set_flags(mgr)
    for h in range(0, tip + 1):
        bh = f"{h:064x}"
        section = await db.get_block_exchange_txs(bh)
        if not section:
            continue
        txs = BP.decode_exchange_txs(section)
        await BP.preload_sender_balances(db, txs, mgr)
        await BP.preload_token_balances(db, txs, mgr)
        ok, err, _root = BP.process_exchange_transactions(h, float(1_700_000_000 + h), txs, mgr)
        assert ok, f"forward block {h} failed: {err}"
        mgr.commit_block()
        await BP.flush_exchange_balance_deltas(db, mgr, enforce=BP.ENFORCE_EXCHANGE_COLLATERAL)
        await BP.flush_token_balance_deltas(db, mgr)
    await db.connection.commit()
    return await db.get_account_state_root(), await db.get_token_balances_root()


async def _run_rebuild(db):
    """Reorg rebuild (mirrors _rebuild_derived_state_after_rollback, EVM-less branch):
    clear+reseed account_state, clear token ledger, then rebuild exchange on top."""
    await db.clear_account_state()
    await db.seed_genesis_account_state()
    await db.connection.commit()
    await db.clear_token_balances()
    ExchangeStateManager.reset_instance()
    await BP.rebuild_exchange_state_from_chain(db, flush_to_account_state=True)
    await db.connection.commit()
    return await db.get_account_state_root(), await db.get_token_balances_root()


# --- tests -----------------------------------------------------------------

async def _equivalence(monkeypatch, pool_stake: bool):
    if pool_stake:
        monkeypatch.setattr(BP, "ENFORCE_POOL_STAKE", True)
    db, path = await _db()
    try:
        k1, k2 = PQPrivateKey.generate(), PQPrivateKey.generate()
        tip = await _build_chain(db, k1, k2)

        fwd_acct, fwd_tok = await _run_forward(db, tip)
        rb_acct, rb_tok = await _run_rebuild(db)

        assert fwd_tok == rb_tok, (
            f"TOKEN root diverges: forward={fwd_tok[:16]} rebuild={rb_tok[:16]} "
            f"(pool_stake={pool_stake})")
        assert fwd_acct == rb_acct, (
            f"ACCOUNT_STATE root diverges: forward={fwd_acct[:16]} rebuild={rb_acct[:16]} "
            f"(pool_stake={pool_stake})")
    finally:
        await db.close()
        os.remove(path)


async def test_rebuild_equivalence_shipped_flags(monkeypatch):
    """Live/shipped enforcement set (collateral+spot+orderbook on, pool_stake off)."""
    await _equivalence(monkeypatch, pool_stake=False)


async def test_rebuild_equivalence_pool_stake_enforced(monkeypatch):
    """Same, with pool-stake enforce also on (the candidate flip)."""
    await _equivalence(monkeypatch, pool_stake=True)


async def test_rebuild_equivalence_with_rejected_spot_op(monkeypatch):
    """A canonical block may contain a spot op the FORWARD path rejects (enforce_spot
    _settlement on). The rebuild currently does NOT set enforce_spot_settlement — if the
    rebuild then ACCEPTS (moves value for) an op forward rejected, the reorged node
    diverges. Probes exactly that shipped asymmetry: an over-spending TOKEN_TRANSFER
    (T2 sends more AAA than it holds) included in a block."""
    db, path = await _db()
    try:
        k1, k2 = PQPrivateKey.generate(), PQPrivateKey.generate()
        t1, t2 = k1.public_key.to_address(), k2.public_key.to_address()
        tokenA = ExchangeStateManager.derive_token_address(t1, 0, "AAA")

        await _add_block(db, 0, genesis_alloc=[(t1, "1000000"), (t2, "1000000")])
        await _add_block(db, 1, encode_exchange_txs([_sign(_tx(
            ExchangeOpType.TOKEN_DEPLOY, t1, 0,
            {"name": "A", "symbol": "AAA", "total_supply": "1000000", "decimals": 18}), k1)]))
        await _add_block(db, 2, encode_exchange_txs([_sign(_tx(
            ExchangeOpType.TOKEN_TRANSFER, t1, 1,
            {"token_address": tokenA, "to": t2, "amount": "1000"}), k1)]))
        # T2 holds 1000 AAA but tries to send 5000 → forward (spot enforce) REJECTS.
        await _add_block(db, 3, encode_exchange_txs([_sign(_tx(
            ExchangeOpType.TOKEN_TRANSFER, t2, 0,
            {"token_address": tokenA, "to": t1, "amount": "5000"}), k2)]))

        # Forward tolerates a per-block op failure (the block is not rejected), so don't
        # assert ok on every block here — replicate _run_forward but lenient.
        await db.seed_genesis_account_state(); await db.connection.commit()
        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance(); _set_flags(mgr)
        for h in range(0, 4):
            section = await db.get_block_exchange_txs(f"{h:064x}")
            if not section:
                continue
            txs = BP.decode_exchange_txs(section)
            await BP.preload_sender_balances(db, txs, mgr)
            await BP.preload_token_balances(db, txs, mgr)
            BP.process_exchange_transactions(h, float(1_700_000_000 + h), txs, mgr)
            mgr.commit_block()
            await BP.flush_exchange_balance_deltas(db, mgr, enforce=BP.ENFORCE_EXCHANGE_COLLATERAL)
            await BP.flush_token_balance_deltas(db, mgr)
        await db.connection.commit()
        fwd_tok = await db.get_token_balances_root()

        rb_acct, rb_tok = await _run_rebuild(db)
        assert fwd_tok == rb_tok, (
            f"TOKEN root diverges on a block with a forward-rejected spot op: "
            f"forward={fwd_tok[:16]} rebuild={rb_tok[:16]} — the rebuild must make the "
            f"same accept/reject decision the forward path did")
    finally:
        await db.close()
        os.remove(path)
