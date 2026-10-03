"""
Rebuild every derived-state domain from the canonical chain, per block, in forward order.

Why this exists
---------------
Forward block application interleaves the state domains *per block*: block N's exchange
section, then its EVM section, then its stake withdrawals — then block N+1. The rollback
rebuild used to replay them *by domain* instead: every EVM section across the whole chain
first (``rebuild_account_state_from_chain``), then every exchange delta
(``rebuild_exchange_state_from_chain``), then every withdrawal.

Any transaction whose outcome depends on a cross-domain effect from an earlier block then
replays differently. With the validator-stake debit (an exchange delta)::

    forward:  block 10  STAKE_DEPOSIT 100k        balance 500k → 400k
              block 12  EVM send of 450k           → fails: insufficient funds
    rebuild:  EVM pass  block 12's send            balance still 500k → SUCCEEDS
              exchange pass  block 10's debit      → applied afterwards

The rebuilt node disagrees with the network at equal tip. Perp margin and PnL, pool stake,
validator stake and withdrawals all cross domains the same way.

This module replays each canonical block exactly as an importer applies it, so the rebuilt
state equals forward application by construction rather than by coincidence.

Deliberately NOT replayed here
------------------------------
* Validator lifecycle flushes (deposits/exits into the validators table and their logs).
  The validators table is rebuilt from the canonical chain by the epoch loop's
  reconstruction, and the deposit/exit logs are trimmed to the new tip by the rollback's
  ``undo_*_above`` calls — replaying the flush would double-register.
* Withdrawal *computation*. The ledger already records what each canonical block paid, so
  each block's rows are re-credited at that block, in order. Recomputing would find them
  already paid and skip them.
"""

from __future__ import annotations

import logging
from decimal import Decimal

logger = logging.getLogger(__name__)


async def rebuild_derived_state_interleaved(db, evm_state_manager=None, execute_tx=None) -> dict:
    """
    Reset account_state, the token ledger and the in-memory exchange manager, then replay
    every canonical block's exchange section, EVM section and withdrawals in that order.

    Requires the withdrawal ledger to have been trimmed to the canonical tip already
    (``withdrawals.undo_withdrawal_logs_above``), so every ledger row is canonical.

    With ``evm_state_manager=None`` (a node running without EVM) EVM sections are skipped,
    as they are on that node's forward path; exchange and withdrawals still interleave.

    Returns ``{"tip", "blocks", "exchange", "evm", "withdrawals", "account_root"}``.
    """
    from .contracts.evm_block_apply import produce_block_evm_section
    from .exchange.block_processor import (
        run_exchange_tick,
        ENFORCE_EXCHANGE_COLLATERAL,
        ENFORCE_ORDERBOOK_SETTLEMENT,
        ENFORCE_POOL_STAKE,
        ENFORCE_SPOT_SETTLEMENT,
        ENFORCE_VALIDATOR_STAKE, ENFORCE_EXCHANGE_FEES, apply_enforcement,
        decode_exchange_txs,
        flush_exchange_balance_deltas,
        flush_token_balance_deltas,
        preload_sender_balances,
        preload_token_balances,
        process_exchange_transactions,
    )
    from .exchange.state_manager import ExchangeStateManager

    # ── Reset every domain ────────────────────────────────────────────────
    await db.clear_account_state()
    sm = evm_state_manager
    if sm is not None:
        sm._accounts_cache.clear()
        sm._storage_cache.clear()
        sm._code_cache.clear()
        sm._dirty_accounts.clear()
        sm._dirty_storage.clear()
        sm._snapshots.clear()
        sm._destroyed.clear()
    await db.seed_genesis_account_state()
    await db.connection.commit()
    await db.clear_token_balances()

    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    # The forward path's EXACT enforce-flag set. A rebuild running with a different set is
    # this codebase's most-repeated divergence: it accepts an op the network rejected.
    # Guarded by tests/test_reorg_rebuild_equivalence.py::test_rebuild_sets_every_forward_enforce_flag.
    apply_enforcement(mgr)

    # Withdrawals already paid, grouped by the block that paid them.
    cur = await db.connection.execute(
        "SELECT block_height, address, amount FROM validator_withdrawals "
        "ORDER BY block_height, address")
    paid_by_block: dict = {}
    for height, address, amount in await cur.fetchall():
        if Decimal(str(amount)) != 0:     # a forfeited exit is settled with a zero row
            paid_by_block.setdefault(int(height), []).append((address, Decimal(str(amount))))

    tip = (await db.get_next_block_id()) - 1
    counts = {"blocks": 0, "exchange": 0, "evm": 0, "withdrawals": 0}

    # ── Replay per block, in the importer's order ─────────────────────────
    for height in range(0, tip + 1):
        try:
            block = await db.get_block_by_id(height)
        except Exception:
            block = None
        if not block:
            continue
        block_hash = block.get("hash") or block.get("block_hash")
        if not block_hash:
            continue
        counts["blocks"] += 1
        # The timestamp is read only where a section consumes it, with the same conversion
        # the forward path uses for that section. Not every stored block has a numeric
        # timestamp (genesis stores a datetime string), and parsing it unconditionally
        # would abort the rebuild at height 0 — after account_state was already cleared.
        raw_ts = block.get("timestamp", 0) or 0

        # 1. Exchange section.
        try:
            section = await db.get_block_exchange_txs(block_hash)
        except Exception:
            section = None
        if section:
            txs = decode_exchange_txs(section)
            await preload_sender_balances(db, txs, mgr)
            await preload_token_balances(db, txs, mgr)
            ok, err, _root = process_exchange_transactions(height, float(raw_ts), txs, mgr)
            if ok:
                mgr.commit_block()
                await flush_exchange_balance_deltas(db, mgr, enforce=ENFORCE_EXCHANGE_COLLATERAL)
                await flush_token_balance_deltas(db, mgr)
                counts["exchange"] += 1
            else:
                logger.error("interleaved rebuild: exchange section at %d failed: %s", height, err)
        elif height >= 1:
            # No exchange transactions: the exchange still ticks, as on every forward path.
            run_exchange_tick(height, float(raw_ts), mgr)

        # 2. EVM section — sees the exchange effects of this and every earlier block.
        try:
            evm_section = await db.get_block_evm_txs(block_hash) if sm is not None else None
        except Exception:
            evm_section = None
        if evm_section:
            root, _included = await produce_block_evm_section(
                height, block_hash, int(raw_ts), evm_section, db, sm, execute_tx)
            if root is not None:
                counts["evm"] += 1
            else:
                logger.error("interleaved rebuild: EVM section at %d could not execute", height)

        # 3. Withdrawals this block paid.
        for address, amount in paid_by_block.get(height, ()):
            await db.apply_account_balance_delta(address, amount)
            counts["withdrawals"] += 1

    await db.connection.commit()
    counts["tip"] = tip
    counts["account_root"] = await db.get_account_state_root()
    logger.info("[reorg] interleaved rebuild: tip=%d blocks=%d exchange=%d evm=%d "
                "withdrawals=%d account_root=%s", tip, counts["blocks"], counts["exchange"],
                counts["evm"], counts["withdrawals"], counts["account_root"][:16])
    return counts
