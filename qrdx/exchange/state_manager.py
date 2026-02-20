"""
QRDX Exchange State Manager  (Whitepaper §7 — State Layer)

Central singleton that bridges the blockchain layer with the exchange engine.
Every node maintains an identical exchange state by processing the same
sequence of ExchangeTransactions deterministically during block validation.

Responsibilities:
  - Owns all exchange engine instances (pools, books, oracles, perps)
  - Processes ExchangeTransactions deterministically
  - Computes exchange state root for block commitment
  - Serializes / deserializes state for persistence
  - Provides read-only query interface for API layer
  - Block-boundary lifecycle (new_block, finalize_block, revert_block)

Security:
  - All mutations go through process_transaction() — no direct engine access
  - State root is blake2b of sorted pool/book/position/oracle hashes
  - Revert support for chain reorganizations
  - Deterministic execution — identical inputs produce identical outputs
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, List, Optional, Tuple

from .amm import (
    ConcentratedLiquidityPool,
    FeeTier,
    PoolManager,
    PoolType,
    tick_to_sqrt_price,
)
from .hooks import CircuitBreaker, HookContext, HookRegistry
from .oracle import TWAPOracle
from .orderbook import Order, OrderBook, OrderSide, OrderType, SelfTradeAction
from .perpetual import PerpEngine, PerpSide
from .router import FillSource, UnifiedRouter
from .transactions import (
    EXCHANGE_GAS_COSTS,
    ExchangeOpType,
    ExchangeTransaction,
)

logger = logging.getLogger(__name__)

ZERO = Decimal("0")


# ---------------------------------------------------------------------------
# Transaction execution result
# ---------------------------------------------------------------------------

class ExchangeExecResult:
    """Result of executing a single exchange transaction."""

    __slots__ = ("success", "gas_used", "data", "error", "logs")

    def __init__(
        self,
        success: bool = True,
        gas_used: int = 0,
        data: Optional[Dict[str, Any]] = None,
        error: str = "",
        logs: Optional[List[Dict[str, Any]]] = None,
    ):
        self.success = success
        self.gas_used = gas_used
        self.data = data or {}
        self.error = error
        self.logs = logs or []


# ---------------------------------------------------------------------------
# Exchange State Manager
# ---------------------------------------------------------------------------

class ExchangeStateManager:
    """
    Singleton bridge between the blockchain consensus layer and the
    exchange engine.  Every validator runs an identical instance.

    Usage in block production / validation:

        mgr = ExchangeStateManager.instance
        mgr.begin_block(block_height, block_timestamp)
        for tx in exchange_txs:
            result = mgr.process_transaction(tx)
        state_root = mgr.finalize_block()
    """

    instance: Optional[ExchangeStateManager] = None

    def __init__(self) -> None:
        # --- Engine instances (consensus-critical state) ---
        self.pool_manager = PoolManager()
        self.perp_engine = PerpEngine()
        self.router = UnifiedRouter(pool_manager=self.pool_manager)
        self.hook_registry = HookRegistry()
        self.circuit_breaker = CircuitBreaker()

        # Register built-in hooks
        self.hook_registry.register(self.circuit_breaker)

        # Order books: pair_key → OrderBook
        self._order_books: Dict[str, OrderBook] = {}
        # Oracles: pair_key → TWAPOracle
        self._oracles: Dict[str, TWAPOracle] = {}
        # Per-sender nonces for replay protection
        self._nonces: Dict[str, int] = {}

        # --- Block-level tracking ---
        self._current_block_height: int = 0
        self._current_block_timestamp: float = 0.0
        self._block_exchange_txs: List[ExchangeTransaction] = []
        self._block_results: List[ExchangeExecResult] = []
        self._block_fees: Decimal = ZERO

        # --- State snapshot for revert ---
        self._snapshot: Optional[Dict[str, Any]] = None

        # --- Counters ---
        self._total_swaps: int = 0
        self._total_orders: int = 0
        self._total_pools: int = 0
        self._total_positions: int = 0

    @classmethod
    def get_instance(cls) -> ExchangeStateManager:
        """Get or create the singleton instance."""
        if cls.instance is None:
            cls.instance = cls()
            logger.info("Exchange state manager initialized")
        return cls.instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton (for testing)."""
        cls.instance = None

    # =====================================================================
    #  Block lifecycle
    # =====================================================================

    def begin_block(self, block_height: int, block_timestamp: float) -> None:
        """
        Called at the start of block processing.

        Resets per-block accumulators and rate-limit counters.
        """
        self._current_block_height = block_height
        self._current_block_timestamp = block_timestamp
        self._block_exchange_txs = []
        self._block_results = []
        self._block_fees = ZERO

        # Reset per-block rate limits on all order books
        for book in self._order_books.values():
            book.new_block()

        # Reset circuit breaker per-block counters
        self.circuit_breaker.new_block()

    def finalize_block(self) -> str:
        """
        Called after all transactions in a block are processed.

        Returns:
            The exchange state root hash for this block.
        """
        state_root = self.compute_state_root()
        logger.debug(
            "Block %d finalized: %d exchange txs, fees=%s, state_root=%s",
            self._current_block_height,
            len(self._block_exchange_txs),
            self._block_fees,
            state_root[:16],
        )
        return state_root

    def revert_block(self) -> None:
        """
        Revert the state changes from the current block.

        Called during chain reorganization.
        """
        if self._snapshot is not None:
            self._restore_snapshot(self._snapshot)
            self._snapshot = None
            logger.warning(
                "Block %d reverted — exchange state restored",
                self._current_block_height,
            )

    # =====================================================================
    #  Transaction processing (consensus-critical)
    # =====================================================================

    def process_transaction(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """
        Execute a single exchange transaction deterministically.

        This is the ONLY entry point for exchange state mutations.
        Every validator must produce identical results for identical inputs.

        Args:
            tx: The exchange transaction to execute

        Returns:
            ExchangeExecResult with success/failure and gas used
        """
        # 1. Basic structural validation
        try:
            tx.validate_basic()
        except ValueError as e:
            return ExchangeExecResult(success=False, gas_used=0, error=str(e))

        # 2. Nonce check (replay protection)
        expected_nonce = self._nonces.get(tx.sender, 0)
        if tx.nonce != expected_nonce:
            return ExchangeExecResult(
                success=False, gas_used=0,
                error=f"Invalid nonce: expected {expected_nonce}, got {tx.nonce}",
            )

        # 3. Gas limit check
        base_gas = EXCHANGE_GAS_COSTS.get(tx.op_type, 100_000)
        if tx.gas_limit < base_gas:
            return ExchangeExecResult(
                success=False, gas_used=0,
                error=f"Gas limit too low: need {base_gas}, got {tx.gas_limit}",
            )

        # 4. Execute the operation
        try:
            result = self._execute_op(tx)
        except Exception as e:
            logger.error("Exchange op %s failed: %s", tx.op_type.name, e)
            result = ExchangeExecResult(
                success=False, gas_used=base_gas, error=str(e)
            )

        # 5. Update nonce on success
        if result.success:
            self._nonces[tx.sender] = tx.nonce + 1

        # 6. Charge gas
        if result.gas_used == 0:
            result.gas_used = base_gas
        fee = Decimal(result.gas_used) * tx.gas_price
        self._block_fees += fee

        # 7. Record for block tracking
        tx.gas_used = result.gas_used
        tx.success = result.success
        tx.result = result.data
        tx.error = result.error
        self._block_exchange_txs.append(tx)
        self._block_results.append(result)

        return result

    def _execute_op(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Dispatch to the appropriate handler."""
        handlers = {
            ExchangeOpType.CREATE_POOL: self._op_create_pool,
            ExchangeOpType.ADD_LIQUIDITY: self._op_add_liquidity,
            ExchangeOpType.REMOVE_LIQUIDITY: self._op_remove_liquidity,
            ExchangeOpType.SWAP: self._op_swap,
            ExchangeOpType.PLACE_ORDER: self._op_place_order,
            ExchangeOpType.CANCEL_ORDER: self._op_cancel_order,
            ExchangeOpType.OPEN_POSITION: self._op_open_position,
            ExchangeOpType.CLOSE_POSITION: self._op_close_position,
            ExchangeOpType.PARTIAL_CLOSE: self._op_partial_close,
            ExchangeOpType.ADD_MARGIN: self._op_add_margin,
            ExchangeOpType.UPDATE_ORACLE: self._op_update_oracle,
        }
        handler = handlers.get(tx.op_type)
        if handler is None:
            return ExchangeExecResult(
                success=False, error=f"Unknown op type: {tx.op_type}"
            )
        return handler(tx)

    # =====================================================================
    #  Operation handlers
    # =====================================================================

    def _op_create_pool(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        fee_tier = FeeTier(int(p["fee_tier"]))
        pool_type = PoolType[p["pool_type"]] if isinstance(p["pool_type"], str) else PoolType(int(p["pool_type"]))
        sqrt_price = Decimal(str(p["initial_sqrt_price"]))
        stake = Decimal(str(p["stake_amount"]))

        pool = self.pool_manager.create_pool(
            p["token0"], p["token1"], fee_tier, pool_type,
            sqrt_price, tx.sender, stake,
        )

        # Create matching orderbook and oracle
        pair_key = f"{pool.state.token0}:{pool.state.token1}"
        if pair_key not in self._order_books:
            book = OrderBook(
                pool_id=pair_key,
                self_trade_action=SelfTradeAction.REJECT,
            )
            self._order_books[pair_key] = book
            self.router.register_order_book(pair_key, book)

        if pair_key not in self._oracles:
            oracle = TWAPOracle(pool_id=pair_key)
            self._oracles[pair_key] = oracle
            self.router.register_oracle(pair_key, oracle)

        self._total_pools += 1
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.CREATE_POOL],
            data={"pool_id": pool.state.id, "pair": pair_key},
        )

    def _op_add_liquidity(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        pool = self.pool_manager.get_pool(p["pool_id"])
        if pool is None:
            return ExchangeExecResult(success=False, error="Pool not found")

        position = pool.add_liquidity(
            tx.sender, int(p["tick_lower"]), int(p["tick_upper"]),
            Decimal(str(p["amount"])),
        )
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.ADD_LIQUIDITY],
            data={"position_id": position.id},
        )

    def _op_remove_liquidity(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        pool = self.pool_manager.get_pool(p["pool_id"])
        if pool is None:
            return ExchangeExecResult(success=False, error="Pool not found")

        amount = Decimal(str(p.get("amount", "0")))
        removed = pool.remove_liquidity(p["position_id"], amount if amount > 0 else None)
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.REMOVE_LIQUIDITY],
            data={"removed": str(removed)},
        )

    def _op_swap(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        amount_in = Decimal(str(p["amount_in"]))
        min_out = Decimal(str(p.get("min_amount_out", "0")))
        deadline = float(p.get("deadline", 0))

        result = self.router.execute(
            p["token_in"], p["token_out"], amount_in, tx.sender,
            min_amount_out=min_out,
            deadline=deadline,
        )

        self._total_swaps += 1
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.SWAP],
            data={
                "amount_out": str(result.amount_out),
                "fee_total": str(result.fee_total),
                "price": str(result.price),
                "source": result.source.value,
            },
        )

    def _op_place_order(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        pair = p["pair"]
        book = self._order_books.get(pair)
        if book is None:
            return ExchangeExecResult(success=False, error=f"No order book for {pair}")

        # Robust enum parsing: accept string values ("buy") or names ("BUY")
        raw_side = p["side"]
        try:
            side = OrderSide(raw_side)
        except ValueError:
            side = OrderSide[str(raw_side).upper()]

        raw_otype = p["order_type"]
        try:
            order_type = OrderType(raw_otype)
        except ValueError:
            order_type = OrderType[str(raw_otype).upper()]

        order = Order(
            id=tx.tx_hash()[:16],  # deterministic from tx hash
            owner=tx.sender,
            side=side,
            order_type=order_type,
            price=Decimal(str(p.get("price", "0"))),
            amount=Decimal(str(p["amount"])),
            stop_price=Decimal(str(p["stop_price"])) if p.get("stop_price") else None,
            nonce=tx.nonce,
        )
        trades = book.place_order(order)

        self._total_orders += 1
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PLACE_ORDER],
            data={
                "order_id": order.id,
                "trades": len(trades),
                "filled": str(order.filled),
            },
        )

    def _op_cancel_order(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        order_id = p["order_id"]
        pair = p.get("pair", "")

        # Search across all books if pair not specified
        if pair and pair in self._order_books:
            books_to_check = [self._order_books[pair]]
        else:
            books_to_check = list(self._order_books.values())

        for book in books_to_check:
            result = book.cancel_order(order_id, caller=tx.sender)
            if result is not None:
                return ExchangeExecResult(
                    success=True,
                    gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.CANCEL_ORDER],
                    data={"order_id": order_id, "status": "cancelled"},
                )

        return ExchangeExecResult(success=False, error=f"Order {order_id} not found")

    def _op_open_position(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        raw_side = p["side"]
        try:
            side = PerpSide(raw_side)
        except ValueError:
            side = PerpSide[str(raw_side).upper()]

        pos = self.perp_engine.open_position(
            p["market_id"], tx.sender, side,
            Decimal(str(p["size"])),
            Decimal(str(p["leverage"])),
            Decimal(str(p["price"])),
            reduce_only=p.get("reduce_only", False),
        )

        self._total_positions += 1
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.OPEN_POSITION],
            data={"position_id": pos.id, "margin": str(pos.margin)},
        )

    def _op_close_position(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        pnl = self.perp_engine.close_position(
            p["position_id"], Decimal(str(p["price"])),
        )
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.CLOSE_POSITION],
            data={"pnl": str(pnl)},
        )

    def _op_partial_close(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        pnl = self.perp_engine.partial_close(
            p["position_id"],
            Decimal(str(p["close_size"])),
            Decimal(str(p["price"])),
        )
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.PARTIAL_CLOSE],
            data={"pnl": str(pnl)},
        )

    def _op_add_margin(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        new_margin = self.perp_engine.add_margin(
            p["position_id"], Decimal(str(p["amount"])),
        )
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.ADD_MARGIN],
            data={"new_margin": str(new_margin)},
        )

    def _op_update_oracle(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        pair = p["pair"]
        price = Decimal(str(p["price"]))

        oracle = self._oracles.get(pair)
        if oracle is None:
            # Auto-create oracle for new pairs
            oracle = TWAPOracle(pool_id=pair)
            self._oracles[pair] = oracle
            self.router.register_oracle(pair, oracle)

        oracle.record(price, timestamp=self._current_block_timestamp)

        # Also update perp markets that track this pair
        market_id = f"{pair.split(':')[0]}-QRDX-PERP"
        market = self.perp_engine.get_market(market_id)
        if market is not None:
            self.perp_engine.update_price(market_id, price)

        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.UPDATE_ORACLE],
            data={"pair": pair, "price": str(price)},
        )

    # =====================================================================
    #  State root computation (consensus-critical)
    # =====================================================================

    def compute_state_root(self) -> str:
        """
        Compute a deterministic hash of the entire exchange state.

        This is included in the block header to commit to the exchange
        state at each block boundary.

        Returns:
            64-char hex string (blake2b-256)
        """
        hasher = hashlib.blake2b(digest_size=32)

        # 1. Pool state hashes (sorted by pool ID)
        pool_ids = sorted(self.pool_manager._pools.keys())
        for pid in pool_ids:
            pool = self.pool_manager._pools[pid]
            s = pool.state
            pool_hash = hashlib.blake2b(
                f"{pid}:{s.sqrt_price}:{s.tick}:{s.liquidity}:{s.fee_growth_global_0}:{s.fee_growth_global_1}".encode(),
                digest_size=16,
            ).digest()
            hasher.update(pool_hash)

        # 2. Order book state hashes (sorted by pair key)
        for pair_key in sorted(self._order_books.keys()):
            book = self._order_books[pair_key]
            book_hash = hashlib.blake2b(
                f"{pair_key}:{book.total_trades}:{book.total_volume}:{book.bid_depth}:{book.ask_depth}".encode(),
                digest_size=16,
            ).digest()
            hasher.update(book_hash)

        # 3. Oracle state hashes
        for pair_key in sorted(self._oracles.keys()):
            oracle = self._oracles[pair_key]
            price = oracle.latest_price or ZERO
            count = oracle.observation_count
            oracle_hash = hashlib.blake2b(
                f"{pair_key}:{price}:{count}".encode(),
                digest_size=16,
            ).digest()
            hasher.update(oracle_hash)

        # 4. Perp market state hashes
        for market_id in sorted(self.perp_engine._markets.keys()):
            market = self.perp_engine._markets[market_id]
            market_hash = hashlib.blake2b(
                (f"{market_id}:{market.index_price}:{market.mark_price}:"
                 f"{market.open_interest_long}:{market.open_interest_short}:"
                 f"{market.insurance_fund}").encode(),
                digest_size=16,
            ).digest()
            hasher.update(market_hash)

        # 5. Nonce state
        for addr in sorted(self._nonces.keys()):
            hasher.update(f"{addr}:{self._nonces[addr]}".encode())

        # 6. Block metadata
        hasher.update(self._current_block_height.to_bytes(8, "big"))

        return hasher.hexdigest()

    # =====================================================================
    #  Snapshot / restore (for revert)
    # =====================================================================

    def take_snapshot(self) -> Dict[str, Any]:
        """Capture current state for potential revert."""
        snapshot = {
            "nonces": dict(self._nonces),
            "block_height": self._current_block_height,
            "total_swaps": self._total_swaps,
            "total_orders": self._total_orders,
            "total_pools": self._total_pools,
            "total_positions": self._total_positions,
        }
        self._snapshot = snapshot
        return snapshot

    def _restore_snapshot(self, snapshot: Dict[str, Any]) -> None:
        """Restore state from snapshot."""
        self._nonces = snapshot["nonces"]
        self._total_swaps = snapshot["total_swaps"]
        self._total_orders = snapshot["total_orders"]
        self._total_pools = snapshot["total_pools"]
        self._total_positions = snapshot["total_positions"]

    # =====================================================================
    #  Query interface (read-only, for API layer)
    # =====================================================================

    def get_pool(self, pool_id: str) -> Optional[ConcentratedLiquidityPool]:
        return self.pool_manager.get_pool(pool_id)

    def get_order_book(self, pair: str) -> Optional[OrderBook]:
        return self._order_books.get(pair)

    def get_oracle(self, pair: str) -> Optional[TWAPOracle]:
        return self._oracles.get(pair)

    def get_perp_market(self, market_id: str):
        return self.perp_engine.get_market(market_id)

    def get_nonce(self, address: str) -> int:
        return self._nonces.get(address, 0)

    @property
    def pool_count(self) -> int:
        return len(self.pool_manager._pools)

    @property
    def pair_count(self) -> int:
        return len(self._order_books)

    @property
    def block_fees(self) -> Decimal:
        return self._block_fees

    def get_stats(self) -> Dict[str, Any]:
        """Exchange-wide statistics."""
        return {
            "pools": self.pool_count,
            "pairs": self.pair_count,
            "perp_markets": self.perp_engine.market_count,
            "total_swaps": self._total_swaps,
            "total_orders": self._total_orders,
            "total_positions": self._total_positions,
            "block_height": self._current_block_height,
        }
