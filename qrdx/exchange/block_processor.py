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

# Funding settlement happens every epoch (32 slots × 12s = 384s ≈ 6.4 min)
FUNDING_SETTLEMENT_INTERVAL = 32  # slots


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
