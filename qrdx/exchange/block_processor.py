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

logger = logging.getLogger(__name__)

ZERO = Decimal("0")

# Phase E collateral rollout gate. False = OBSERVE (deltas computed/logged, not
# applied; positions not rejected). True = ENFORCE (reject under-collateralized
# opens + flush margin debits to account_state). Flip after observe-mode soak.
ENFORCE_EXCHANGE_COLLATERAL = False


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
            await db.apply_account_balance_delta(addr, delta)
        except Exception as e:
            logger.warning("flush_exchange_balance_deltas: %s for %s", e, str(addr)[:20])

# Funding settlement happens every epoch (32 slots × 12s = 384s ≈ 6.4 min)
FUNDING_SETTLEMENT_INTERVAL = 32  # slots


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

    # Take snapshot for potential revert
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


async def rebuild_exchange_state_from_chain(db, state_manager: Optional[ExchangeStateManager] = None) -> str:
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

    Returns the resulting exchange_state_root.
    """
    if state_manager is None:
        ExchangeStateManager.reset_instance()
        mgr = ExchangeStateManager.get_instance()
    else:
        mgr = state_manager

    try:
        tip = (await db.get_next_block_id()) - 1
    except Exception as e:
        logger.warning("rebuild_exchange_state: cannot read chain tip: %s", e)
        return mgr.compute_state_root()

    applied = 0
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
            continue
        txs = decode_exchange_txs(section)
        ts = float(block.get("timestamp", 0) or 0)
        ok, err, _root = process_exchange_transactions(height, ts, txs, mgr)
        if ok:
            mgr.commit_block()
            applied += 1
        else:
            logger.error("rebuild_exchange_state: block %d section failed: %s", height, err)

    if applied:
        logger.info("Rebuilt exchange state from %d canonical block section(s)", applied)
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

def _execute_block_boundary_duties(
    mgr: ExchangeStateManager,
    block_height: int,
    block_timestamp: float,
) -> None:
    """
    Execute protocol-level duties at block boundaries.

    These are NOT user-submitted transactions — they are deterministic
    protocol operations that every validator executes identically.
    """
    # 1. Funding rate settlement (every FUNDING_SETTLEMENT_INTERVAL slots)
    if block_height > 0 and block_height % FUNDING_SETTLEMENT_INTERVAL == 0:
        _settle_funding_rates(mgr, block_timestamp)

    # 2. Liquidation checks (every block)
    _check_liquidations(mgr)


def _settle_funding_rates(
    mgr: ExchangeStateManager,
    block_timestamp: float,
) -> None:
    """Apply funding rates on all perp markets."""
    for market_id in list(mgr.perp_engine._markets.keys()):
        try:
            snapshot = mgr.perp_engine.apply_funding(market_id)
            if snapshot is not None:
                logger.debug(
                    "Funding settled for %s: rate=%s",
                    market_id, snapshot.funding_rate,
                )
        except Exception as e:
            logger.error("Funding settlement failed for %s: %s", market_id, e)


def _check_liquidations(mgr: ExchangeStateManager) -> None:
    """Check and execute liquidations on all perp markets."""
    for market_id in list(mgr.perp_engine._markets.keys()):
        try:
            results = mgr.perp_engine.check_all_liquidations(market_id)
            for liq in results:
                logger.info(
                    "Liquidation: %s pos=%s pnl=%s adl=%s",
                    market_id, liq.position_id, liq.pnl, liq.adl_triggered,
                )
        except Exception as e:
            logger.error("Liquidation check failed for %s: %s", market_id, e)


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
        gas_price=Decimal("1"),
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
