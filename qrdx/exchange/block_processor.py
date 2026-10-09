"""
QRDX Exchange Block Processor  (Whitepaper §7 — Consensus Integration)

Processes exchange transactions during block production and validation.
This module is called by the consensus layer (validate_pos_block) and
the block builder (create_block) to execute exchange operations as
part of the block state transition function.

Architecture:
  - Runs AFTER standard UTXO transaction validation
  - Runs AFTER EVM contract execution
  - Produces an exchange_state_root committed to the block
  - Deterministic: identical inputs → identical state on every node
  - Supports block revert for chain reorganizations

Validator Duties:
  - Process oracle price updates (submitted by validators)
  - Execute funding rate settlements at epoch boundaries
  - Check and execute liquidations on perp markets
  - Collect exchange fee share for validators
"""

from __future__ import annotations

import logging
import time
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, List, Optional, Tuple

from .state_manager import ExchangeExecResult, ExchangeStateManager
from .transactions import ExchangeOpType, ExchangeTransaction
from ..constants import ACTIVATION_DELAY_EPOCHS, UNBONDING_PERIOD_EPOCHS

logger = logging.getLogger(__name__)

ZERO = Decimal("0")

# Phase E collateral rollout gate. False = OBSERVE (deltas computed/logged, not
# applied; positions not rejected). True = ENFORCE (reject under-collateralized
# opens + flush margin debits to account_state).
#
# ENABLED after the ledger unification: genesis now funds account_state for ALL
# addresses (PQ and 0x alike — see genesis_init._create_genesis_outputs), so a PQ
# trader's collateral lives in the same ledger the flush debits. The earlier
# dual-ledger no-op (flush found no account_state row for a PQ trader → debited
# nothing) is resolved. The flush is now wired into EVERY import path — proposer,
# bulk-sync, AND the live-broadcast paths (p2p submitBlock / REST submit_block via
# _apply_exchange_section_on_import) — so the margin debit lands in account_state
# before each node computes/verifies its E-D4 unified root, keeping account_state
# convergent across nodes (a flush on only the proposer/sync paths would diverge).
ENFORCE_EXCHANGE_COLLATERAL = True

# Phase E spot-settlement rollout gate. False = OBSERVE (a TOKEN_TRANSFER / swap
# that overspends warns but still executes). True = ENFORCE (reject the overspend).
# This gate is independent of whether token balances MOVE: token deploy/transfer
# always flush to the ledger (new consensus domain — see flush_token_balance_deltas);
# the gate only governs rejection strictness. ENABLED (inc6): token state is
# consensus-replicated (inc4) with its root bound + enforced in the unified root
# (inc3-final), and the spot-sufficiency checks read pre-loaded token balances
# (preload_token_balances) on every path, so rejection is deterministic + convergent.
ENFORCE_SPOT_SETTLEMENT = True

# CLOB order-book settlement gate (observe-first, SEPARATE from the AMM
# ENFORCE_SPOT_SETTLEMENT so it can be soaked independently). OFF: the book matches as
# before and moves no value (behaviour-neutral). ON: PLACE_ORDER escrows + matched
# trades settle real token moves + CANCEL refunds, with unaffordable/MARKET orders
# rejected before they mutate the book. Stays OFF until the escrow settlement is soaked.
ENFORCE_ORDERBOOK_SETTLEMENT = True

# Pool-creation stake gate (observe-first, SEPARATE gate so it soaks independently).
# OFF (default): CREATE_POOL is created as before and debits nothing (behaviour-neutral,
# but pool creation is "free"). ON: the creator's declared QRDX stake is debited from
# account_state (via the same collateral flush path) and held in pool.state.stake_amount
# for a future remove-pool return (staking pools) / forfeit (subsidized = burn); a creator
# who cannot afford the stake is rejected. ENABLED after the reorg-rebuild spot-enforce fix
# (9649931) unblocked it: a 6-run soak was 6/6 with 5 runs fully 4-node-converged (the debit
# is deterministic + reorg-safe), and the rebuild-vs-forward equivalence test proves the reorg
# rebuild reconstructs it byte-identically. See item 7 in docs/CONSENSUS_REMAINING_WORK.md.
ENFORCE_POOL_STAKE = True

# Validator-stake gate. A STAKE_DEPOSIT's CLAIMED stake_amount becomes the validator's
# effective_stake in the consensus `validators` table, and that figure weights BOTH
# stake-weighted proposer selection (consensus.select_proposer) and fork-choice
# attesting weight. The join path checked neither ownership nor the MIN_VALIDATOR_STAKE
# floor that the local registration API and epoch activation already apply — so an
# account holding NOTHING could register with an arbitrary stake and outweigh the whole
# honest set. That is a consensus-capture vector, not an accounting rounding error.
#
# ON: a deposit must clear MIN_VALIDATOR_STAKE, be backed by the sender's real
# account_state balance, and is DEBITED through the same collateral flush; the principal
# is refunded at the deterministic finalized exit epoch (epoch_loop). A SLASHED
# validator never reaches 'exited', so it forfeits the stake — which is what gives
# slashing teeth. Genesis validators are exempt: their stake is declared by the genesis
# file, the chain's trust root.
#
# ENABLED: every input is deterministic (a constant floor, and a balance pre-loaded from
# account_state by preload_sender_balances on every path), and the debit rides the
# already-enforced collateral flush, so it lands before each node computes its E-D4
# unified root. The reorg rebuild sets this flag identically — see the note at
# rebuild_exchange_state_from_chain, and tests/test_validator_stake_enforcement.py.
ENFORCE_VALIDATOR_STAKE = True

# Exchange fees (ExchangeStateManager.enforce_fees): every executed operation pays
# gas_used × gas_price wei in QRDX, burned; operations priced under
# constants.EXCHANGE_MIN_GAS_PRICE_WEI, or whose sender cannot cover gas_limit × gas_price, are
# refused before they execute. Deterministic (a constant floor, balances preloaded on every
# path); the debit rides the enforced collateral flush. Every path sets it, rebuilds included.
ENFORCE_EXCHANGE_FEES = True


def apply_enforcement(mgr: "ExchangeStateManager") -> None:
    """Set every consensus enforcement gate exactly as the network runs it. Every path that
    executes exchange sections — the proposer, each importer, both rebuilds — calls this and sets
    no gate itself, so a gate cannot be on for one path and off for another: a rebuild that
    accepts an operation the forward path refused diverges at equal tip, this codebase's most
    repeated consensus bug. Reads the module's flags at call time (tests patch them)."""
    mgr.enforce_collateral = ENFORCE_EXCHANGE_COLLATERAL
    mgr.enforce_spot_settlement = ENFORCE_SPOT_SETTLEMENT
    mgr.enforce_orderbook_settlement = ENFORCE_ORDERBOOK_SETTLEMENT
    mgr.enforce_pool_stake = ENFORCE_POOL_STAKE
    mgr.enforce_validator_stake = ENFORCE_VALIDATOR_STAKE
    mgr.enforce_fees = ENFORCE_EXCHANGE_FEES


async def ensure_oracle_committee(db, mgr: ExchangeStateManager) -> None:
    """Load the validator oracle's committee from the genesis block's validator set, once per
    manager. Every path that applies a block section calls this first (through
    ``preload_sender_balances``, or directly in the by-domain rebuild), so the committee is in
    place before any vote or staking op is judged — on every node, whatever height it loaded at.
    That is also why the committee is not hashed into the state root: a restarted node loads it
    at height 0, a long-running one at its first section, and between them it decides nothing."""
    if mgr.oracle_committee is not None and mgr.governance.genesis_loaded:
        return
    try:
        genesis = await db.get_block_by_id(0)
        if genesis:
            content = genesis.get("content") or genesis.get("block_content")
            mgr.load_oracle_committee(content)
            # Governance's genesis facts (whether system wallets exist) come from block 0 too.
            mgr.governance.load_genesis(content)
    except Exception as e:
        logger.debug("oracle committee not loaded: %s", e)


async def preload_sender_balances(db, txs, state_manager: Optional[ExchangeStateManager] = None) -> None:
    """
    Phase E: pre-load each exchange-tx sender's real account_state balance into the
    state manager's balance bridge BEFORE the (sync) section is processed, so the
    collateral check can read it. Called by the async block paths (proposer +
    importer). Deterministic: ``db.get_address_balance`` reads the same
    account_state every node has at this point in block application.
    """
    mgr = state_manager or ExchangeStateManager.get_instance()
    mgr.clear_available_balances()
    await ensure_oracle_committee(db, mgr)
    seen = set()
    for tx in txs or []:
        sender = getattr(tx, "sender", None)
        if not sender or sender in seen:
            continue
        seen.add(sender)
        try:
            mgr.set_available_balance(sender, await db.get_address_balance(sender))
        except Exception as e:
            logger.debug("preload_sender_balances: %s for %s", e, str(sender)[:20])
    # A governance system_spend debits a system wallet, not its sender: pre-load that wallet's
    # balance too, under the key the execution debits (the wallet's lowercase address).
    for tx in txs or []:
        if getattr(tx, "op_type", None) != ExchangeOpType.GOV_EXECUTE:
            continue
        try:
            proposal = mgr.governance.proposals.get(int((tx.params or {}).get("proposal_id")))
        except (TypeError, ValueError):
            proposal = None
        if proposal is None or proposal.action != "system_spend":
            continue
        wallet = proposal.params["wallet"]
        if wallet in seen:
            continue
        seen.add(wallet)
        try:
            mgr.set_available_balance(wallet, await db.get_address_balance(wallet))
        except Exception as e:
            logger.debug("preload_sender_balances: %s for system wallet %s", e, wallet)


async def preload_token_balances(db, txs, state_manager: Optional[ExchangeStateManager] = None) -> None:
    """
    Phase E (spot): pre-load the (holder, token) balances the block's spot ops will
    spend, from the real token ledger, BEFORE the (sync) section runs — so the
    sufficiency checks (swap token_in, transfer amount, add-liquidity token0/token1)
    can read them. Deterministic: ``db.get_token_balance`` reads the same ledger on
    every node at this point. Scans op params for the (sender, token) pairs to load.
    """
    mgr = state_manager or ExchangeStateManager.get_instance()
    mgr.clear_available_token_balances()
    from .transactions import ExchangeOpType
    wanted = set()
    for tx in txs or []:
        sender = getattr(tx, "sender", None)
        p = getattr(tx, "params", None) or {}
        op = getattr(tx, "op_type", None)
        if not sender:
            continue
        asset = mgr.canonical_asset          # "QRDX" for native, canonical token addresses
        if op == ExchangeOpType.SWAP and p.get("token_in"):
            wanted.add((sender, asset(p["token_in"])))
        elif op in (ExchangeOpType.TOKEN_TRANSFER, ExchangeOpType.TOKEN_BURN) \
                and p.get("token_address"):
            # Native tokens are keyed by their canonical (lowercase) address. A burn may name
            # another holder (``from``: an operator's or the permanent delegate's burn).
            wanted.add((str(p.get("from") or sender), str(p["token_address"]).lower()))
        elif op == ExchangeOpType.TOKEN_WITHDRAW_FEES and p.get("token_address"):
            # Withheld transfer fees are held by the token's own address.
            token = str(p["token_address"]).lower()
            wanted.add((token, token))
        elif op == ExchangeOpType.TOKEN_TRANSFER_FROM and p.get("token_address") and p.get("from"):
            wanted.add((str(p["from"]), str(p["token_address"]).lower()))
        elif op == ExchangeOpType.ADD_LIQUIDITY:
            for k in ("token0", "token1"):
                if p.get(k):
                    wanted.add((sender, asset(p[k])))
            # Named by pool id alone: the deposit spends that pool's two tokens.
            pool = mgr.pool_manager.get_pool(str(p["pool_id"])) if p.get("pool_id") else None
            if pool is not None:
                wanted.add((sender, pool.state.token0))
                wanted.add((sender, pool.state.token1))
        elif op == ExchangeOpType.PLACE_ORDER and ":" in str(p.get("pair", "")):
            # CLOB sufficiency: a buy spends quote, a sell spends base — load both.
            b, q = mgr._canonical_pair(str(p["pair"])).split(":", 1)
            wanted.add((sender, b))
            wanted.add((sender, q))
        elif op == ExchangeOpType.PERP_DEPOSIT:
            # Perps settled in a token (the stablecoin): the deposit spends it.
            collateral = mgr.perp_collateral_token()
            if collateral and collateral.upper() != "QRDX":
                wanted.add((sender, collateral))
        elif op == ExchangeOpType.PERP_WITHDRAW:
            collateral = mgr.perp_collateral_token()
            if collateral and collateral.upper() != "QRDX":
                wanted.add((mgr.perps_holder_address(), collateral))
        # The protocol's holders this operation may DEBIT — a pool's reserves, a book's
        # escrow — so the manager can refuse an operation they cannot cover.
        if op == ExchangeOpType.SWAP and p.get("token_in") and p.get("token_out"):
            a, b = asset(p["token_in"]), asset(p["token_out"])
            for pool in mgr.pool_manager.get_pools_for_pair(a, b):
                holder = mgr.pool_holder_address(pool.state.id)
                wanted.add((holder, a))
                wanted.add((holder, b))
            escrow = mgr.orderbook_escrow_address(min(a, b) + ":" + max(a, b))
            wanted.add((escrow, a))
            wanted.add((escrow, b))
        elif op in (ExchangeOpType.REMOVE_LIQUIDITY, ExchangeOpType.REMOVE_POOL) and p.get("pool_id"):
            pool = mgr.pool_manager.get_pool(str(p["pool_id"]))
            if pool is not None:
                holder = mgr.pool_holder_address(pool.state.id)
                wanted.add((holder, pool.state.token0))
                wanted.add((holder, pool.state.token1))
        elif op in (ExchangeOpType.PLACE_ORDER, ExchangeOpType.CANCEL_ORDER):
            pair = mgr._canonical_pair(str(p.get("pair", "")))
            if ":" in pair:
                escrow = mgr.orderbook_escrow_address(pair)
                for tok in pair.split(":", 1):
                    wanted.add((escrow, tok))
    from .tokens import is_native_asset
    for holder, token in sorted(wanted):
        try:
            if is_native_asset(token):        # native QRDX: the account balance
                mgr.set_available_balance(holder, await db.get_address_balance(holder))
                continue
            mgr.set_available_token_balance(holder, token, await db.get_token_balance(token, holder))
        except Exception as e:
            logger.debug("preload_token_balances: %s for (%s,%s)", e, str(holder)[:16], str(token)[:16])


async def flush_exchange_balance_deltas(db, state_manager: Optional[ExchangeStateManager] = None,
                                        enforce: bool = False) -> None:
    """
    Phase E: apply this block's accumulated exchange balance deltas (e.g. locked
    margin) to real ``account_state``. Called by the async block paths AFTER the
    section commits and BEFORE the unified state root is computed, so the root
    reflects the moved funds on every node. Does not commit — the block's
    ``add_block`` commits atomically.

    ``enforce=False`` (default) is OBSERVE: deltas are computed/logged but NOT
    applied, so there is no consensus impact during rollout.
    """
    mgr = state_manager or ExchangeStateManager.get_instance()
    deltas = mgr.balance_deltas()
    if not deltas:
        return
    if not enforce:
        logger.info("[Phase E observe] would apply %d balance delta(s): %s",
                    len(deltas), {a[:12]: str(d) for a, d in deltas.items()})
        return
    for addr, delta in deltas.items():
        try:
            applied = await db.apply_account_balance_delta(addr, delta)
            if not applied and delta < 0:
                # A debit on an account with no ledger row: nothing was taken, while the
                # paired credit (if any) still lands — value created from nothing.
                logger.error("[VALUE-LOST] flush_exchange_balance_deltas: debit of %s on %s "
                             "found no account_state row", delta, str(addr)[:24])
        except Exception as e:
            # A dropped delta LOSES VALUE silently. It is deterministic (every node
            # drops the same one, so no fork) which is exactly why it can hide: the
            # paired delta still applies, so funds vanish with only a log line.
            # ERROR-level and explicitly marked so a log scan or soak catches it —
            # this is how the 0xPOOL/0xCLOB holder break went unnoticed through a
            # green integration run.
            logger.error("[VALUE-LOST] flush_exchange_balance_deltas dropped %s for %s: %s",
                         delta, str(addr)[:24], e)


async def flush_token_balance_deltas(db, state_manager: Optional[ExchangeStateManager] = None) -> None:
    """
    Phase E (spot): apply this block's token-registry changes (deploys, supply, authorities
    — the DB mirror of the manager's registry) + token-balance deltas (token ops, spot,
    perps) to the durable token ledger. Called by the async block paths AFTER the section commits and
    BEFORE the unified state root is computed, so the token root reflects the moved
    tokens on every node. Does not commit — the block's ``add_block`` commits.

    Unlike the collateral flush this is NOT gated by an observe flag: token state
    is a brand-new consensus domain (additive — there is no prior balance to
    protect), so it always applies, which is what makes the ledger converge across
    nodes. The ``enforce_spot_settlement`` gate lives on the op (reject an
    over-spend), not here.
    """
    mgr = state_manager or ExchangeStateManager.get_instance()
    registry_ops = mgr.token_registry_ops()
    deltas = mgr.token_balance_deltas()
    if not registry_ops and not deltas:
        return
    for op in registry_ops:
        try:
            await db.apply_token_registry_op(op)
        except Exception as e:
            logger.warning("flush_token: registry %s for %s", e, str(op.get("token_address"))[:20])
    for (holder, token), delta in deltas.items():
        try:
            await db.apply_token_balance_delta(token, holder, delta)
        except Exception as e:
            # See the note in flush_exchange_balance_deltas: a dropped token delta
            # BURNS tokens while its paired debit applies. Loud and marked.
            logger.error("[VALUE-LOST] flush_token dropped %s of %s for holder %s: %s",
                         delta, str(token)[:24], str(holder)[:24], e)


async def flush_validator_lifecycle_deltas(
    db, state_manager: Optional[ExchangeStateManager] = None, block_epoch: Optional[int] = None,
    block_height: Optional[int] = None, block_hash: Optional[str] = None,
) -> None:
    """
    Validator-lifecycle Phase 3: apply this block's staking ops to the consensus
    ``validators`` table — a STAKE_DEPOSIT registers the sender as a PENDING validator,
    a STAKE_EXIT marks an active validator 'exiting' (still eligible through unbonding).
    Called AFTER the section commits, BEFORE the unified root, on every import path.

    The activation/exit epoch is derived DETERMINISTICALLY from ``block_epoch`` — the
    epoch of the block carrying the op (identical on every node that imports it):
      * activation_epoch = block_epoch + ACTIVATION_DELAY_EPOCHS
      * exit_epoch       = block_epoch + UNBONDING_PERIOD_EPOCHS
    The all-nodes epoch loop then activates/removes the validator when the FINALIZED
    epoch reaches that scheduled epoch. Computing the schedule from the block (not from
    when the epoch loop happens to observe the pending validator) is what makes it
    cross-node deterministic: an earlier loop-tick scheduler assigned different epochs
    on different nodes depending on import timing. ``block_epoch=None`` leaves it
    unscheduled (legacy/rebuild paths). Does not commit.
    """
    mgr = state_manager or ExchangeStateManager.get_instance()
    ops = mgr.validator_lifecycle_ops()
    if not ops:
        return
    act_epoch = (int(block_epoch) + ACTIVATION_DELAY_EPOCHS) if block_epoch is not None else None
    exit_epoch = (int(block_epoch) + UNBONDING_PERIOD_EPOCHS) if block_epoch is not None else None
    for op in ops:
        try:
            if op.get("type") == "deposit":
                # block_height/block_hash log the carrying block so an ORPHANED
                # deposit's registration can be reversed exactly on reorg rollback
                # (db.undo_validator_deposits_above) — the validators table itself is
                # not reconstructed from the chain.
                await db.register_pending_validator(
                    op["address"], op["public_key"], op["stake"], activation_epoch=act_epoch,
                    block_height=block_height, block_hash=block_hash)
            elif op.get("type") == "exit":
                # Phase 3c: a STAKE_EXIT moves an active validator to 'exiting'. This is
                # SAFE at live-import because 'exiting' stays ELIGIBLE for proposer
                # selection (it keeps validating through unbonding — see the ACTIVE/
                # PENDING/EXITING filter in node_integration + block_verification), so
                # the eligible SET is unchanged at import (only a status label flips;
                # benign table-hash churn, no proposer-selection flip → no halt). The
                # eligibility-REMOVING transition (exiting→exited) happens later, at the
                # deterministic FINALIZED exit_epoch in the all-nodes epoch loop
                # (get_validators_to_exit → exited), so every node drops the validator at
                # the same converged chain point.
                moved = await db.mark_validator_exiting(op["address"], exit_epoch=exit_epoch)
                # Log the exit against its carrying block so the principal can be returned
                # by an in-block withdrawal once exit_epoch is reached. Logged even when
                # `moved` is False: the withdrawal inputs must be a pure function of the
                # chain, and the validators table this flag comes from is rebuilt
                # asynchronously, so its state here can differ between nodes.
                if block_height is not None and exit_epoch is not None:
                    from ..validator.withdrawals import record_validator_exit
                    await record_validator_exit(db, op["address"], exit_epoch, block_height)
                logger.info("[Phase 3c] STAKE_EXIT by %s → %s (exit_epoch=%s)",
                            str(op.get("address"))[:20],
                            "exiting" if moved else "no-op (not active)", exit_epoch)
        except Exception as e:
            logger.warning("flush_validator_lifecycle: %s for %s", e, str(op.get("address"))[:20])


# ---------------------------------------------------------------------------
# Admission: authenticate exchange transactions
# ---------------------------------------------------------------------------

def verify_exchange_tx(tx: ExchangeTransaction) -> Tuple[bool, str]:
    """
    Authenticate an exchange transaction for mempool admission / block validation.

    The deterministic execution core (``ExchangeStateManager.process_transaction``)
    trusts ``tx.sender`` and does NOT verify signatures, so this MUST be enforced
    before a transaction is admitted to the mempool and again when validating a
    received block — otherwise any party can act as any address.

    Checks, in order:
      1. structural validity (``validate_basic``),
      2. post-quantum signature + sender-address binding (``tx.verify()``).

    Returns:
        (ok, error). ``error`` is empty on success.
    """
    try:
        tx.validate_basic()
    except ValueError as e:
        return False, f"invalid structure: {e}"
    chain_err = tx.chain_error()
    if chain_err:
        return False, chain_err
    if not tx.verify():
        return False, "signature verification failed (bad signature or sender mismatch)"
    return True, ""


# ---------------------------------------------------------------------------
# Block-level exchange processing
# ---------------------------------------------------------------------------

def process_exchange_transactions(
    block_height: int,
    block_timestamp: float,
    exchange_txs: List[ExchangeTransaction],
    state_manager: Optional[ExchangeStateManager] = None,
) -> Tuple[bool, str, str]:
    """
    Process all exchange transactions in a block.

    Called by the consensus layer during block validation and creation.

    Args:
        block_height: Height of the block being processed
        block_timestamp: Timestamp of the block
        exchange_txs: List of exchange transactions in the block
        state_manager: Optional state manager (uses singleton if None)

    Returns:
        Tuple of (success, error_message, exchange_state_root)
    """
    mgr = state_manager or ExchangeStateManager.get_instance()

    # Take snapshot for potential revert. A block with no transactions only runs the per-block
    # tick, which has nothing to revert — and a deep copy of every book on every block would
    # be the most expensive thing the node does.
    if exchange_txs:
        mgr.take_snapshot()

    # Begin block processing
    mgr.begin_block(block_height, block_timestamp)

    # Process each exchange transaction in order
    failed_txs = []
    for i, tx in enumerate(exchange_txs):
        try:
            result = mgr.process_transaction(tx)
            if not result.success:
                # Non-critical failure: tx fails but block continues
                # (like a reverted EVM transaction — gas is still charged)
                failed_txs.append((i, tx.tx_hash(), result.error))
                logger.debug(
                    "Exchange tx %d failed (non-critical): %s",
                    i, result.error,
                )
        except Exception as e:
            # Critical failure: block is invalid
            mgr.revert_block()
            return False, f"Critical exchange error at tx {i}: {e}", ""

    # Execute validator duties at block boundary
    try:
        _execute_block_boundary_duties(mgr, block_height, block_timestamp)
    except Exception as e:
        mgr.revert_block()
        return False, f"Block boundary duty error: {e}", ""

    # Finalize and compute state root
    state_root = mgr.finalize_block()

    if failed_txs:
        logger.info(
            "Block %d: %d/%d exchange txs failed (non-critical)",
            block_height, len(failed_txs), len(exchange_txs),
        )

    return True, "", state_root


def validate_exchange_state_root(
    block_height: int,
    block_timestamp: float,
    exchange_txs: List[ExchangeTransaction],
    expected_state_root: str,
    state_manager: Optional[ExchangeStateManager] = None,
) -> Tuple[bool, str]:
    """
    Validate that replaying exchange transactions produces the expected state root.

    Used during block sync to verify exchange state consistency.

    Args:
        block_height: Block height
        block_timestamp: Block timestamp
        exchange_txs: Exchange transactions from the block
        expected_state_root: The state root from the block header
        state_manager: Optional state manager

    Returns:
        Tuple of (is_valid, error_message)
    """
    success, error, computed_root = process_exchange_transactions(
        block_height, block_timestamp, exchange_txs, state_manager,
    )

    if not success:
        return False, f"Exchange processing failed: {error}"

    if computed_root != expected_state_root:
        return False, (
            f"Exchange state root mismatch at block {block_height}: "
            f"expected {expected_state_root[:16]}..., "
            f"computed {computed_root[:16]}..."
        )

    return True, ""


async def rebuild_exchange_state_from_chain(
    db,
    state_manager: Optional[ExchangeStateManager] = None,
    flush_to_account_state: bool = False,
) -> str:
    """
    Reconstruct exchange state by replaying every canonical block's exchange
    section in height order (Phase D3 — reorg safety + restart durability).

    Exchange state is thereby a deterministic function of the canonical chain:
      - **Restart durability:** on node startup, rebuild from the stored sections
        so account/exchange state survives a process restart or fresh resync.
      - **Reorg safety:** after the base layer rolls back to a common ancestor,
        rebuild to the new canonical tip — orphaned-block effects vanish and the
        canonical effects are re-applied, with no stale state left behind.

    Resets the singleton (when ``state_manager`` is None) and replays from
    genesis. O(total exchange txs); checkpointing is a future optimization.

    ``flush_to_account_state`` (Phase E reorg safety): when True, each block's
    accumulated collateral deltas (e.g. locked margin) are also flushed to the
    durable ``account_state`` ledger, mirroring live import. This MUST be used
    only when ``account_state`` has just been cleared + reseeded to genesis (the
    reorg path), because the durable ledger already holds these debits on a plain
    restart — flushing then would double-debit. ``begin_block`` (inside
    ``process_exchange_transactions``) resets the per-block deltas, so each flush
    applies exactly that block's debits; the per-block flush is uncommitted but
    same-connection-visible, so a later block's collateral preload reads the
    correct running balance. A single commit is issued at the end.

    Returns the resulting exchange_state_root.
    """
    if state_manager is None:
        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance()
    else:
        mgr = state_manager

    if flush_to_account_state:
        # Reorg rebuild (token_balances + account_state were just cleared+reseeded):
        # the replay must reconstruct the SAME ledger live import produced. Gated on
        # flush_to_account_state (like the collateral flush) because the plain-restart
        # path does NOT re-flush token deltas — the durable ledger already holds them,
        # and apply_token_balance_delta is additive, so re-applying would double them.
        #
        # CRITICAL: the rebuild MUST set the SAME enforce flags the forward import path
        # (_apply_exchange_section_on_import) uses, so it makes byte-identical accept/
        # reject decisions during replay. A canonical block can contain a spot op the
        # forward path REJECTS (an op unaffordable at that point — common under reorg
        # churn when re-queued orphan txs are re-included): forward moves no value for
        # it, so a rebuild that runs WITHOUT enforce_spot_settlement would instead
        # EXECUTE it → the reorged node's token ledger diverges from the network at
        # equal tip (the equal-tip derived-state divergence; token roots differ, E-D4
        # stays 0 because block history matches). enforce_orderbook_settlement gates the
        # CLOB escrow MOVE itself; enforce_pool_stake gates the stake debit. A canonical
        # op that forward ACCEPTED had sufficient balance, and the in-order preload
        # reconstructs that same balance, so enforcing here re-accepts it (no false
        # reject) — the flags only make the REJECTIONS match too. Verified by
        # tests/test_reorg_rebuild_equivalence.py.
        apply_enforcement(mgr)

    try:
        tip = (await db.get_next_block_id()) - 1
    except Exception as e:
        logger.warning("rebuild_exchange_state: cannot read chain tip: %s", e)
        return mgr.compute_state_root()

    applied = 0
    flushed = 0
    await ensure_oracle_committee(db, mgr)
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
        try:
            section = await db.get_block_exchange_txs(block_hash)
        except Exception:
            section = None
        if not section:
            if height >= 1:
                # No exchange transactions: the exchange still ticks, as on every forward
                # path (see run_exchange_tick).
                try:
                    run_exchange_tick(height, float(block.get("timestamp", 0) or 0), mgr)
                except Exception as e:
                    logger.error("rebuild_exchange_state: tick at %d failed: %s", height, e)
            continue
        txs = decode_exchange_txs(section)
        ts = float(block.get("timestamp", 0) or 0)
        # Phase E reorg safety: preload senders' (running) account_state balances
        # so the per-block collateral check reads the same view a live importer
        # would at this height. Must run BEFORE process_exchange_transactions.
        if flush_to_account_state:
            try:
                await preload_sender_balances(db, txs, mgr)
                await preload_token_balances(db, txs, mgr)
            except Exception as e:
                logger.debug("rebuild_exchange_state preload skipped at %d: %s", height, e)
        ok, err, _root = process_exchange_transactions(height, ts, txs, mgr)
        if ok:
            mgr.commit_block()
            applied += 1
            if flush_to_account_state:
                # Re-apply this block's collateral debits to the freshly reseeded
                # account_state ledger (enforce mode applies; observe just logs)
                # AND its token moves to the freshly cleared token ledger.
                await flush_exchange_balance_deltas(
                    db, mgr, enforce=ENFORCE_EXCHANGE_COLLATERAL)
                await flush_token_balance_deltas(db, mgr)
                flushed += 1
        else:
            logger.error("rebuild_exchange_state: block %d section failed: %s", height, err)

    if flush_to_account_state and flushed:
        try:
            await db.connection.commit()
        except Exception as e:
            logger.warning("rebuild_exchange_state: account_state flush commit failed: %s", e)

    # [reorg-diag] log UNCONDITIONALLY (incl. applied=0) so a heavy-reorg run reveals
    # whether the reflush re-applied the activity sections after a rollback+reseed.
    logger.info("[reorg-diag] rebuild_exchange: tip=%d applied=%d flushed=%d (flush_to_account=%s)",
                tip, applied, flushed, flush_to_account_state)
    return mgr.compute_state_root()


def apply_block_exchange_section(
    block_height: int,
    block_timestamp: float,
    section_items: Optional[List[Dict[str, Any]]],
    declared_state_root: Optional[str],
    state_manager: Optional[ExchangeStateManager] = None,
) -> Tuple[bool, str]:
    """
    Securely validate and apply a block's exchange section on import (Phase D3).

    This is the consensus enforcement an importing node runs before accepting a
    block. It is intentionally stricter than ``validate_exchange_state_root``:

      1. **Authenticate first** — every transaction must pass ``verify_exchange_tx``
         (PQ signature + sender binding) BEFORE any state is touched, so a
         malicious proposer cannot smuggle forged exchange txs into a block.
      2. **Require a declared root** — a section without a declared
         ``exchange_state_root`` is unverifiable and therefore rejected.
      3. **Execute + compare** — replay deterministically and compute the root.
      4. **Revert on any mismatch/failure** — restore the pre-block snapshot so a
         rejected block leaves the local exchange state untouched (the existing
         ``validate_exchange_state_root`` commits before comparing, which would
         corrupt state on a bad block).
      5. **Commit on success** — the replayed state is kept and finalized.

    An empty/absent section is a no-op success (nothing to apply).

    Returns:
        (ok, error). On ``False`` the block MUST be rejected and local exchange
        state is unchanged.
    """
    if not section_items:
        return True, ""

    if not declared_state_root:
        return False, "exchange section present but block declares no exchange_state_root"

    mgr = state_manager or ExchangeStateManager.get_instance()

    # 1. Authenticate every tx before mutating any state.
    txs = decode_exchange_txs(section_items)
    for i, tx in enumerate(txs):
        ok, err = verify_exchange_tx(tx)
        if not ok:
            return False, f"exchange tx {i} in block {block_height} failed verification: {err}"

    # 2–4. Execute (snapshots internally), compare, revert on mismatch.
    success, error, computed_root = process_exchange_transactions(
        block_height, block_timestamp, txs, mgr,
    )
    if not success:
        # process_exchange_transactions already reverted on critical failure.
        return False, error
    if computed_root != declared_state_root:
        mgr.revert_block()  # undo the wrongly-applied state
        return False, (
            f"exchange_state_root mismatch at block {block_height}: "
            f"declared {declared_state_root[:16]}..., computed {computed_root[:16]}..."
        )

    # 5. Accept: keep the replayed state, discard the revert point.
    mgr.commit_block()
    return True, ""


# ---------------------------------------------------------------------------
# Block boundary duties (executed by every validator)
# ---------------------------------------------------------------------------

def run_exchange_tick(block_height: int, block_timestamp: float,
                      state_manager: Optional[ExchangeStateManager] = None) -> str:
    """
    The exchange's per-block tick for a block that carries no exchange transactions.

    Clearinghouse duties — mark prices (docs/PERPS_CLEARINGHOUSE.md Phase 2), and later
    liquidations and funding — must advance on EVERY block, not only on blocks that happen to
    carry exchange transactions; otherwise prices, liquidations and funding freeze through a
    quiet stretch. Every path runs this for every block from height 1 (genesis is never
    processed by the exchange): the proposer, the sync/REST/p2p importers and both rebuilds.
    Returns the exchange state root.
    """
    mgr = state_manager or ExchangeStateManager.get_instance()
    ok, err, root = process_exchange_transactions(block_height, block_timestamp, [], mgr)
    if not ok:
        logger.error("exchange tick failed at block %d: %s", block_height, err)
    mgr.commit_block()
    return root


def _execute_block_boundary_duties(
    mgr: ExchangeStateManager,
    block_height: int,
    block_timestamp: float,
) -> None:
    """
    Execute protocol-level duties at block boundaries.

    These are NOT user-submitted transactions — they are deterministic
    protocol operations that every validator executes identically. They run on every block
    (see ``run_exchange_tick``).
    """
    # Perps clearinghouse: mark prices, funding at interval boundaries, then liquidations at
    # the new marks — all judged by block time.
    from .. import constants
    mgr.apply_oracle_votes(Decimal(str(block_timestamp)))
    events = mgr.clearinghouse.tick(Decimal(str(block_timestamp)),
                                    funding_interval=constants.PERP_FUNDING_INTERVAL_SECONDS)
    for ev in events:
        if ev["type"] == "liquidation":
            logger.info("Perp liquidation at height %d: %s %s (%s, filled %s on the book) "
                        "equity=%s maintenance=%s", block_height, ev["owner"],
                        ",".join(ev["markets"]), ev["stage"], ev["filled"], ev["equity"],
                        ev["maintenance"])
    # The node-local journal (receipts + events for wallets, the API and streams) records them
    # once the block commits.
    mgr.record_tick_events(events)


# ---------------------------------------------------------------------------
# Utility: extract exchange transactions from a block
# ---------------------------------------------------------------------------

def extract_exchange_transactions(block: Any) -> List[ExchangeTransaction]:
    """
    Extract exchange transactions from a block object.

    Scans block.transactions for objects that are ExchangeTransaction
    instances or have the is_exchange_transaction() marker.

    Args:
        block: Block object with .transactions attribute

    Returns:
        List of ExchangeTransaction objects
    """
    exchange_txs = []
    if not hasattr(block, "transactions") or not block.transactions:
        return exchange_txs

    for tx in block.transactions:
        if isinstance(tx, ExchangeTransaction):
            exchange_txs.append(tx)
        elif hasattr(tx, "is_exchange_transaction") and tx.is_exchange_transaction():
            exchange_txs.append(tx)

    return exchange_txs


# ---------------------------------------------------------------------------
# Block-body codec for exchange transactions  (Phase D2, sub-step 1)
# ---------------------------------------------------------------------------
#
# Exchange transactions ride in a dedicated, backward-compatible block-body
# section: ``block["exchange_transactions"] = [tx.to_dict(), ...]`` in the
# canonical order chosen by the proposer (ExchangeMempool.select_for_block).
# A block with no exchange activity simply omits the key. These helpers are the
# wire codec that the proposer (D2) and importing nodes (D3) will share; they do
# NOT yet touch live block production.

BLOCK_EXCHANGE_TXS_KEY = "exchange_transactions"


def encode_exchange_txs(txs: List[ExchangeTransaction]) -> List[Dict[str, Any]]:
    """
    Encode an ordered list of exchange transactions for the block body.

    Order is preserved exactly (it is consensus-relevant — the proposer's
    canonical selection order). Per-tx ``to_dict`` already serializes the PQ
    signature + public key, so authentication survives the round trip.
    """
    return [tx.to_dict() for tx in txs]


def decode_exchange_txs(items: Optional[List[Dict[str, Any]]]) -> List[ExchangeTransaction]:
    """
    Decode the block-body exchange section back into transactions.

    Backward compatible: a missing/empty section yields an empty list.
    """
    if not items:
        return []
    return [ExchangeTransaction.from_dict(d) for d in items]


def exchange_txs_canonical_bytes(txs: List[ExchangeTransaction]) -> bytes:
    """
    Deterministic byte encoding of the exchange section, for hashing / equality.

    Two validators with the same ordered transaction list MUST produce identical
    bytes. Uses each transaction's consensus-critical ``tx_hash`` in order, so
    any reordering or mutation changes the result. BLAKE3 per Whitepaper §3.6.
    """
    import blake3
    h = blake3.blake3()
    for tx in txs:
        h.update(bytes.fromhex(tx.tx_hash()))
    return h.digest(length=32)


def extract_exchange_transactions_from_dict(block: Dict[str, Any]) -> List[ExchangeTransaction]:
    """
    Recover exchange transactions from a serialized block dict (the wire form).

    Reads ``block[BLOCK_EXCHANGE_TXS_KEY]``; absent ⇒ empty list. Counterpart to
    ``extract_exchange_transactions`` (which scans an in-memory block object).
    """
    if not isinstance(block, dict):
        return []
    return decode_exchange_txs(block.get(BLOCK_EXCHANGE_TXS_KEY))


# ---------------------------------------------------------------------------
# Validator duty: build oracle update transactions
# ---------------------------------------------------------------------------

def build_oracle_update_tx(
    validator_address: str,
    pair: str,
    price: Decimal,
    nonce: int,
) -> ExchangeTransaction:
    """
    Build an oracle price update transaction for a validator to submit.

    Validators are responsible for submitting price updates for pairs
    they are assigned to.  The price is sourced from external feeds
    and submitted as a signed ExchangeTransaction.

    Args:
        validator_address: The validator's PQ address
        pair: Trading pair (e.g., "BTC:USDC")
        price: Current price from external oracle feed
        nonce: The validator's current exchange nonce

    Returns:
        An unsigned ExchangeTransaction (caller must sign)
    """
    return ExchangeTransaction(
        op_type=ExchangeOpType.UPDATE_ORACLE,
        sender=validator_address,
        nonce=nonce,
        params={"pair": pair, "price": str(price)},
        gas_limit=20_000,
    )


def get_validator_fee_share(
    block_fees: Decimal,
    validator_address: str,
) -> Decimal:
    """
    Calculate the validator's share of exchange fees for a block.

    Per whitepaper §7.3: validators receive 5% of exchange fees.

    Args:
        block_fees: Total exchange fees collected in the block
        validator_address: The block proposer's address

    Returns:
        The validator's fee share in QRDX
    """
    from ..constants import EXCHANGE_FEE_VALIDATOR_SHARE
    return (block_fees * EXCHANGE_FEE_VALIDATOR_SHARE).quantize(
        Decimal("0.00000001"), rounding=ROUND_HALF_UP,
    )
