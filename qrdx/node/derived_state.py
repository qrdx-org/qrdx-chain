"""
Derived state (exchange, EVM, withdrawals) rebuilt from the blocks: after a rollback,
at startup, and after a block is rejected part way through.

The node's state (the database, the HTTP client, the EVM and exchange runtimes, this node's
identity) lives in qrdx.node.main and is read from it at call time, as ``_node.<name>``:
startup rebinds it, and tests replace it.
"""

import os

from qrdx.logger import get_logger
from qrdx.node import evm_runtime as _evm, main as _node

logger = get_logger(__name__)

# Drop the deposit log of rolled-back blocks: the validator set is computed from the chain and
# this log (validator/epoch_state.py), so a deposit in an orphaned block must leave no input
# behind. (tests/test_orphaned_deposit_undo.py)
_ENFORCE_DEPOSIT_REORG_UNDO = True


# Rollback rebuild order (docs/KNOWN_ISSUES.md — "rollback rebuild replays out of forward
# order"). Forward import applies each block as exchange → EVM → withdrawals, then the next
# block; the rebuild must replay in that same order or any transaction that depends on an
# earlier block's effect in another domain (a stake debit, a withdrawal credit, perp margin)
# replays with a different outcome and the reorged node diverges at equal tip.
# Env-overridable (QRDX_INTERLEAVED_REBUILD=0) only to A/B against the old by-domain rebuild.
_INTERLEAVED_DERIVED_REBUILD = os.getenv("QRDX_INTERLEAVED_REBUILD", "1").lower() not in (
    "0",
    "false",
    "no",
)


async def _rebuild_derived_state_by_domain():
    """The pre-fix rebuild — every EVM section, then every exchange section, then every
    withdrawal. Kept only for A/B (QRDX_INTERLEAVED_REBUILD=0); see
    qrdx/derived_state_rebuild.py for why the order is wrong."""
    if _node.EVM_STATE_MANAGER is not None:
        try:
            from ..contracts.evm_block_apply import rebuild_account_state_from_chain

            await rebuild_account_state_from_chain(
                _node.db, _node.EVM_STATE_MANAGER, _evm._evm_defer_execute()
            )
        except Exception as e:
            logger.error(f"[REORG] EVM/account state rebuild failed: {e}")
    else:
        try:
            await _node.db.clear_account_state()
            await _node.db.seed_genesis_account_state()
            await _node.db.connection.commit()
        except Exception as e:
            logger.error(f"[REORG] account_state genesis reseed failed: {e}")

    try:
        await _node.db.clear_token_balances()
    except Exception as e:
        logger.error(f"[REORG] token ledger clear failed: {e}")

    try:
        from ..exchange.block_processor import rebuild_exchange_state_from_chain

        await rebuild_exchange_state_from_chain(_node.db, flush_to_account_state=True)
    except Exception as e:
        logger.error(f"[REORG] Exchange state rebuild failed: {e}")

    try:
        from ..validator.withdrawals import reapply_withdrawal_ledger

        _recredited = await reapply_withdrawal_ledger(_node.db)
        await _node.db.connection.commit()
        if _recredited:
            logger.info("[REORG] re-credited %d canonical stake withdrawal(s)", _recredited)
    except Exception as e:
        logger.error(f"[REORG] stake-withdrawal ledger restore failed: {e}")


async def _rebuild_derived_state_after_rollback():
    """Rebuild all derived state (account/EVM, token ledger, exchange, stake withdrawals)
    from the canonical blocks up to the CURRENT tip — i.e. after a ``db.remove_blocks(...)``
    rollback. Shared by ``handle_reorganization`` (longest-chain reorg), the equal-height
    tie-break, and ``_restore_after_rejected_block``. Each step is best-effort + logged (a
    rebuild failure must not crash the caller)."""
    # Stake withdrawals: discard exit/withdrawal records carried by orphaned blocks FIRST.
    # A withdrawal is neither an EVM nor an exchange effect, so replaying sections alone
    # would drop it; the rebuild therefore re-credits every row still in the ledger, at the
    # block that paid it. An orphaned row left in place would be paid as if canonical.
    try:
        from ..validator.withdrawals import undo_withdrawal_logs_above

        _wd_tip = (await _node.db.get_next_block_id()) - 1
        await undo_withdrawal_logs_above(_node.db, _wd_tip)
        await _node.db.connection.commit()
    except Exception as e:
        logger.error(f"[REORG] orphaned stake-withdrawal log trim failed: {e}")

    if _INTERLEAVED_DERIVED_REBUILD:
        try:
            # The fast path (undo journal back to an epoch checkpoint, then replay the blocks
            # above it) when it applies, else the full replay from genesis — same result.
            from ..derived_state_rebuild import rebuild_to_tip

            await rebuild_to_tip(
                _node.db,
                _node.EVM_STATE_MANAGER,
                _evm._evm_defer_execute() if _node.EVM_STATE_MANAGER is not None else None,
            )
        except Exception as e:
            logger.error(f"[REORG] derived-state rebuild failed: {e}")
    else:
        await _rebuild_derived_state_by_domain()

    # Mempool nonce expectations must follow the rebuilt account nonces, or transactions
    # from orphaned/rejected blocks can never be re-admitted (see _reset_evm_pending_nonces).
    try:
        await _evm._reset_evm_pending_nonces()
    except Exception as e:
        logger.error(f"[REORG] mempool nonce reset failed: {e}")

    # Drop the stake-operation log of the orphaned blocks: the validator set is computed from
    # the chain and that log (validator/epoch_state.py), keyed by each epoch's checkpoint, so
    # the new branch's states are computed from its own blocks.
    if _ENFORCE_DEPOSIT_REORG_UNDO:
        try:
            tip = (await _node.db.get_next_block_id()) - 1
            res = await _node.db.undo_validator_deposits_above(tip)
            if res.get("reversed"):
                await _node.db.connection.commit()
                logger.warning(
                    "[REORG] dropped %d orphaned validator deposit(s) above h=%d",
                    res["reversed"],
                    tip,
                )
        except Exception as e:
            logger.error(f"[REORG] orphaned validator-deposit undo failed: {e}")


# Startup rebuild (docs/KNOWN_ISSUES.md — "a restart replayed exchange state without
# enforcement"). Env-overridable (QRDX_STARTUP_REBUILD=0) only to A/B against the old
# exchange-only replay.
_STARTUP_DERIVED_REBUILD = os.getenv("QRDX_STARTUP_REBUILD", "1").lower() not in (
    "0",
    "false",
    "no",
)


async def _rebuild_derived_state_on_startup():
    """
    Reconstruct the in-memory exchange state on startup — and, to get it right, every other
    derived domain with it.

    Exchange state lives only in memory, so a restart must replay it from the chain. The
    exchange sections alone cannot reproduce forward decisions: an op is accepted or
    rejected against the sender's balance *at that block*, and the durable account_state
    holds only tip balances. The old exchange-only replay therefore ran with every
    enforcement gate off and accepted ops the network had rejected (an under-collateralised
    position, an unaffordable pool), so a restarted node's exchange root differed from the
    network's and it rejected every later block carrying an exchange section.

    The interleaved rebuild recomputes each block's balances as it replays, so it makes the
    network's decisions. It rewrites account_state and the token ledger to what forward
    application produces; comparing against the durable roots first turns every restart
    into an equivalence check between the rebuild and forward application.

    Must run after the contract system is initialised (EVM sections replay through it) and
    before block production or sync start.
    """
    if not _STARTUP_DERIVED_REBUILD:
        try:
            from ..exchange.block_processor import rebuild_exchange_state_from_chain

            root = await rebuild_exchange_state_from_chain(_node.db)
            logger.info(f"Exchange state initialized from chain (root={root[:16]}...)")
        except Exception as e:
            logger.warning(f"Exchange state rebuild on startup skipped: {e}")
        return

    from ..history_pruning import HistoryPruned

    try:
        from ..derived_state_rebuild import (
            load_persisted_checkpoint,
            rebuild_derived_state_interleaved,
            rebuild_to_tip,
        )
        from ..exchange.state_manager import ExchangeStateManager
        from ..validator.withdrawals import undo_withdrawal_logs_above

        tip = (await _node.db.get_next_block_id()) - 1
        durable_account = await _node.db.get_account_state_root(tip)
        durable_token = await _node.db.get_token_balances_root(tip)
        await undo_withdrawal_logs_above(_node.db, tip)
        await _node.db.connection.commit()

        execute = _evm._evm_defer_execute() if _node.EVM_STATE_MANAGER is not None else None
        # From the persisted exchange checkpoint when there is a usable one: the blocks since
        # it, not the chain. QRDX_STARTUP_FULL_REBUILD=1 replays from genesis instead, the
        # reference the checkpoint path is checked against (the comparison below runs either
        # way).
        base = None
        if os.getenv("QRDX_STARTUP_FULL_REBUILD", "").lower() not in ("1", "true", "yes"):
            base = await load_persisted_checkpoint(_node.db)
        if base is not None:
            res = await rebuild_to_tip(_node.db, _node.EVM_STATE_MANAGER, execute)
        else:
            res = await rebuild_derived_state_interleaved(
                _node.db, _node.EVM_STATE_MANAGER, execute
            )
        rebuilt_token = await _node.db.get_token_balances_root(tip)
        exchange_root = ExchangeStateManager.get_instance().compute_state_root()
        if res["account_root"] != durable_account or rebuilt_token != durable_token:
            logger.error(
                "[RESTART-REBUILD] rebuilt state differs from the durable state at tip %d: "
                "account %s -> %s, token %s -> %s. Either an earlier rebuild or write was "
                "interrupted (a crash or stop mid-rebuild leaves partial state), or rebuild "
                "and forward application disagree on this chain. The chain-derived state is "
                "kept, as every reorg would produce it.",
                tip,
                durable_account[:16],
                res["account_root"][:16],
                durable_token[:16],
                rebuilt_token[:16],
            )
        else:
            logger.info(
                "[startup] derived state rebuilt %s (tip=%d, matches durable state; "
                "exchange root=%s...)",
                f"from the checkpoint at {res['base']}" if "base" in res else "from genesis",
                tip,
                exchange_root[:16],
            )
    except HistoryPruned as e:
        # A pruned node without a usable checkpoint cannot rebuild its state: refuse to run on
        # a half-built one.
        raise SystemExit(f"[startup] {e}") from e
    except Exception as e:
        logger.error(f"[startup] derived-state rebuild failed: {e}")


async def _restore_after_rejected_block(block_height, reason: str) -> None:
    """
    Undo a REJECTED block's effects on derived state.

    Every import path applies a block's sections BEFORE its final checks, and those
    sections do not all roll back on their own: ``apply_block_evm_section`` commits on
    success (committing the exchange deltas flushed before it), the in-memory
    ``ExchangeStateManager`` has already been mutated, and withdrawal credits sit in the
    open transaction for the next commit to persist. So when a LATER step rejects the block
    — the EVM section's own root check, or E-D4 — the node used to keep the effects of a
    block its chain does not contain, and would then build on corrupted state.

    The rejected block was never stored, so the canonical chain is intact: rebuilding
    derived state from it restores exactly the pre-block state, in every domain and in
    memory, using the same rebuild the reorg path relies on.

    It also undoes a failed or mismatched exchange section: there is no per-block revert
    point any more (process_exchange_transactions).

    Cost: the reorg fast path (rebuild_to_tip) — the changes since the newest exchange
    checkpoint and the blocks above it, at most about an epoch. It fires only when a block
    that already passed signature, eligibility and parent-continuity checks then fails a
    state check — which only an eligible proposer can cause, once per slot it owns. Must be
    called with the block-processing lock held (every import path holds it), since it does not
    acquire it.
    """
    logger.warning(
        f"[REJECT] restoring derived state after rejecting block {block_height}: {reason}"
    )
    try:
        await _node.db.connection.rollback()
    except Exception as e:
        logger.debug(f"[REJECT] rollback before restore: {e}")
    try:
        await _rebuild_derived_state_after_rollback()
    except Exception as e:
        logger.error(f"[REJECT] derived-state restore failed after block {block_height}: {e}")
