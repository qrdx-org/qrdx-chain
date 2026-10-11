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
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


async def rebuild_derived_state_interleaved(db, evm_state_manager=None, execute_tx=None) -> dict:
    """
    Reset account_state, the token ledger and the in-memory exchange manager, then replay
    every canonical block's exchange section, EVM section and withdrawals in that order.

    Requires the withdrawal ledger to have been trimmed to the canonical tip already
    (``withdrawals.undo_withdrawal_logs_above``), so every ledger row is canonical.

    With ``evm_state_manager=None`` (a node running without EVM) EVM sections are skipped,
    as they are on that node's forward path; exchange and withdrawals still interleave.

    The undo journal (qrdx/undo_journal.py) is reset and every replayed block re-recorded, and
    exchange checkpoints are re-taken at epoch boundaries, so the next reorg can take the fast
    path (``rebuild_to_tip``).

    Returns ``{"tip", "blocks", "exchange", "evm", "withdrawals", "account_root"}``.
    """
    from . import undo_journal
    from .exchange.block_processor import apply_enforcement
    from .exchange.state_manager import ExchangeStateManager

    # ── Reset every domain ────────────────────────────────────────────────
    await undo_journal.reset(db)
    CHECKPOINTS.clear()
    _LAST_EPOCH.clear()
    async with undo_journal.suspended(db):
        await db.clear_account_state()
        _clear_evm_caches(evm_state_manager)
        await db.seed_genesis_account_state()
        await db.connection.commit()
        await db.clear_token_balances()

    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    # The forward path's EXACT enforce-flag set. A rebuild running with a different set is
    # this codebase's most-repeated divergence: it accepts an op the network rejected.
    # Guarded by tests/test_reorg_rebuild_equivalence.py::test_rebuild_sets_every_forward_enforce_flag.
    apply_enforcement(mgr)

    tip = (await db.get_next_block_id()) - 1
    counts = await _replay(db, mgr, evm_state_manager, execute_tx, 0, tip)
    await undo_journal.set_floor(db, 0)
    await db.connection.commit()
    counts["tip"] = tip
    counts["account_root"] = await db.get_account_state_root(tip)
    logger.info(
        "[reorg] interleaved rebuild: tip=%d blocks=%d exchange=%d evm=%d "
        "withdrawals=%d account_root=%s",
        tip,
        counts["blocks"],
        counts["exchange"],
        counts["evm"],
        counts["withdrawals"],
        counts["account_root"][:16],
    )
    return counts


async def rebuild_to_tip(db, evm_state_manager=None, execute_tx=None) -> dict:
    """Bring derived state to the current tip after a rollback (or a rejected block): the fast
    path when it applies, else the full rebuild. Same result either way.

    Fast path: undo the journal back to the newest exchange checkpoint at or below the tip,
    restore the exchange from that checkpoint, and replay only the blocks above it — the cost
    of the changes since the checkpoint plus less than an epoch of blocks, not of the chain."""
    from . import undo_journal
    from .exchange.state_manager import ExchangeStateManager

    tip = (await db.get_next_block_id()) - 1
    for height in sorted((h for h in CHECKPOINTS if h > tip), reverse=True):
        del CHECKPOINTS[height]  # the state of blocks no longer on the chain
    base = None
    for height in sorted(CHECKPOINTS, reverse=True):
        if CHECKPOINTS[height][0] == await _block_hash(db, height) and (
            await undo_journal.can_roll_back_to(db, height)
        ):
            base = height
            break
    if base is None:
        return await rebuild_derived_state_interleaved(db, evm_state_manager, execute_tx)

    reversed_entries = await undo_journal.rollback_to(db, base)
    if reversed_entries is None:
        return await rebuild_derived_state_interleaved(db, evm_state_manager, execute_tx)
    mgr = ExchangeStateManager.get_instance()
    mgr._restore_snapshot(CHECKPOINTS[base][1])
    _LAST_EPOCH.clear()
    _clear_evm_caches(evm_state_manager)
    counts = await _replay(db, mgr, evm_state_manager, execute_tx, base + 1, tip)
    await db.connection.commit()
    counts["tip"] = tip
    counts["base"] = base
    counts["account_root"] = await db.get_account_state_root(tip)
    logger.info(
        "[reorg] fast rebuild: tip=%d from checkpoint %d (%d journal entries undone, %d "
        "block(s) replayed) account_root=%s",
        tip,
        base,
        reversed_entries,
        counts["blocks"],
        counts["account_root"][:16],
    )
    return counts


# ── exchange checkpoints ──────────────────────────────────────────────────────────────────

# height → (that block's hash, the exchange state after it): taken when a block starts a new
# epoch, so a reorg restores the newest one at or below its ancestor and replays the rest.
CHECKPOINTS: Dict[int, Any] = {}
_KEEP = 4  # checkpoints kept above the finalized one


async def _block_hash(db, height: int) -> Optional[str]:
    hashes = await db.get_block_hashes(height, height)
    return hashes.get(height)


# The epoch of the last block applied (a block opening a newer one takes a checkpoint);
# unknown after a reset.
_LAST_EPOCH: Dict[str, int] = {}


async def checkpoint_before(db, height: int, epoch: Optional[int]) -> None:
    """Called before block ``height`` is applied: if it opens a new epoch, keep a copy of the
    exchange state after block ``height - 1`` — a state the undo journal can return the
    database to. Once per epoch (the copy costs O(exchange state))."""
    if epoch is None or height < 1:
        return
    last = _LAST_EPOCH.get("epoch")
    _LAST_EPOCH["epoch"] = int(epoch)
    if last is not None and int(epoch) <= last:
        return
    prev = height - 1
    if prev in CHECKPOINTS:
        return
    root = await _block_hash(db, prev)
    if root is None:
        return
    from .exchange.state_manager import ExchangeStateManager

    CHECKPOINTS[prev] = (root, ExchangeStateManager.get_instance().capture())
    for h in sorted(CHECKPOINTS)[:-_KEEP]:
        del CHECKPOINTS[h]


async def prune_reorg_state(db, finalized_height: int) -> None:
    """Finality moved: no reorg can reach below the finalized checkpoint. Keep the newest exchange
    checkpoint at or below it (the base a reorg just above it restores) and every later one, and
    drop the journal below that base."""
    below = sorted(h for h in CHECKPOINTS if h <= finalized_height)
    for h in below[:-1]:
        del CHECKPOINTS[h]
    if below:
        from . import undo_journal

        await undo_journal.prune(db, below[-1])


async def before_block(db, height: int, epoch: Optional[int]):
    """Every block-application path opens its block with this: a checkpoint if the block starts
    a new epoch, then the undo journal recording the block's writes (an async context)."""
    from . import undo_journal

    await checkpoint_before(db, height, epoch)
    return undo_journal.recording(db, height)


# ── the per-block replay ──────────────────────────────────────────────────────────────────


def _clear_evm_caches(sm) -> None:
    if sm is None:
        return
    sm._accounts_cache.clear()
    sm._storage_cache.clear()
    sm._code_cache.clear()
    sm._dirty_accounts.clear()
    sm._dirty_storage.clear()
    sm._snapshots.clear()
    sm._destroyed.clear()


async def _replay(db, mgr, sm, execute_tx, start: int, end: int) -> Dict[str, Any]:
    """Apply blocks ``start``..``end`` to derived state, per block in the importer's order
    (exchange section, EVM section, withdrawals), each recorded in the undo journal."""
    from . import undo_journal
    from .contracts.evm_block_apply import produce_block_evm_section
    from .exchange.block_processor import (
        ENFORCE_EXCHANGE_COLLATERAL,
        decode_exchange_txs,
        flush_exchange_balance_deltas,
        flush_token_balance_deltas,
        preload_sender_balances,
        preload_token_balances,
        process_exchange_transactions,
        run_exchange_tick,
    )

    # Withdrawals already paid, grouped by the block that paid them.
    cur = await db.connection.execute(
        "SELECT block_height, address, amount FROM validator_withdrawals "
        "WHERE block_height BETWEEN ? AND ? ORDER BY block_height, address",
        (start, end),
    )
    paid_by_block: dict = {}
    for height, address, amount in await cur.fetchall():
        if Decimal(str(amount)) != 0:  # a forfeited exit is settled with a zero row
            paid_by_block.setdefault(int(height), []).append((address, Decimal(str(amount))))

    counts: Dict[str, Any] = {"blocks": 0, "exchange": 0, "evm": 0, "withdrawals": 0}
    if end < start:
        return counts

    # What the replay needs of each block is its hash and timestamp, and whether it carries
    # a section. Read them in three queries rather than fetching every block (a ~60 KB body)
    # and probing both section tables per height: that was ~90% of the rebuild's cost, and
    # the rebuild runs on every reorg and every restart.
    cur = await db.connection.execute(
        "SELECT block_height, block_hash, timestamp FROM blocks "
        "WHERE block_height BETWEEN ? AND ? ORDER BY block_height",
        (start, end),
    )
    blocks = await cur.fetchall()
    cur = await db.connection.execute("SELECT DISTINCT block_hash FROM block_exchange_transactions")
    with_exchange = {r[0] for r in await cur.fetchall()}
    with_evm: set = set()
    if sm is not None:
        cur = await db.connection.execute("SELECT DISTINCT block_hash FROM block_evm_transactions")
        with_evm = {r[0] for r in await cur.fetchall()}
    epochs = await _epochs_of(db, start, end)

    for height, block_hash, timestamp in blocks:
        if not block_hash:
            continue
        await checkpoint_before(db, height, epochs.get(height))
        counts["blocks"] += 1
        # The timestamp is read only where a section consumes it, with the same conversion
        # the forward path uses for that section. Not every stored block has a numeric
        # timestamp (genesis stores a datetime string), and parsing it unconditionally
        # would abort the rebuild at height 0 — after account_state was already cleared.
        raw_ts = timestamp or 0

        async with undo_journal.recording(db, height):
            # 1. Exchange section.
            try:
                section = (
                    await db.get_block_exchange_txs(block_hash)
                    if block_hash in with_exchange
                    else None
                )
            except Exception:
                section = None
            if section:
                txs = decode_exchange_txs(section)
                await preload_sender_balances(db, txs, mgr)
                await preload_token_balances(db, txs, mgr)
                ok, err, _root = process_exchange_transactions(height, float(raw_ts), txs, mgr)
                if ok:
                    mgr.commit_block()
                    await flush_exchange_balance_deltas(
                        db, mgr, enforce=ENFORCE_EXCHANGE_COLLATERAL
                    )
                    await flush_token_balance_deltas(db, mgr)
                    counts["exchange"] += 1
                else:
                    logger.error("rebuild: exchange section at %d failed: %s", height, err)
            elif height >= 1:
                # No exchange transactions: the exchange still ticks, as on every forward path.
                run_exchange_tick(height, float(raw_ts), mgr)

            # 2. EVM section — sees the exchange effects of this and every earlier block.
            try:
                evm_section = (
                    await db.get_block_evm_txs(block_hash) if block_hash in with_evm else None
                )
            except Exception:
                evm_section = None
            if evm_section:
                root, _included = await produce_block_evm_section(
                    height, block_hash, int(raw_ts), evm_section, db, sm, execute_tx
                )
                if root is not None:
                    counts["evm"] += 1
                else:
                    logger.error("rebuild: EVM section at %d could not execute", height)

            # 3. Withdrawals this block paid.
            for address, amount in paid_by_block.get(height, ()):
                await db.apply_account_balance_delta(address, amount)
                counts["withdrawals"] += 1
    return counts


async def _epochs_of(db, start: int, end: int) -> Dict[int, Optional[int]]:
    """{height: epoch} for the blocks start..end, from the chain index (no block bodies)."""
    from . import chain_index

    try:
        await chain_index.sync(db, end)
        cur = await db.connection.execute(
            "SELECT height, epoch FROM chain_index WHERE height BETWEEN ? AND ?", (start, end)
        )
        return {int(h): (None if e is None else int(e)) for h, e in await cur.fetchall()}
    except Exception:
        return {}
