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

        # --- EVM precompile state (consensus-safe, owned by this manager) ---
        # Exchange precompiles delegate to these dicts instead of module-level state.
        self._precompile_pools: Dict[bytes, dict] = {}
        self._precompile_orderbooks: Dict[str, dict] = {}

        # --- Block-level tracking ---
        self._current_block_height: int = 0
        self._current_block_timestamp: float = 0.0
        self._block_exchange_txs: List[ExchangeTransaction] = []
        self._block_results: List[ExchangeExecResult] = []
        self._block_fees: Decimal = ZERO

        # --- State snapshot for revert ---
        self._snapshot: Optional[Dict[str, Any]] = None

        # --- Phase E: real-balance bridge (collateralization) ---
        # Per-sender available QRDX balance, PRE-LOADED from account_state by the
        # async block paths before the (sync) section is processed. None ⇒ not
        # loaded (skip the check). These are inputs derived deterministically from
        # account_state, not state-root state, so they are not snapshotted.
        self._available_balances: Dict[str, Decimal] = {}
        # Per-block net balance deltas (address -> QRDX; negative = debit) the
        # block's exchange ops would apply to real account_state — e.g. margin
        # locked on open. Deterministic (derived from the same txs + pre-loaded
        # balances on every node). Reset per block; flushed to account_state
        # atomically with the block by the async wrapper when collateral is
        # enforced. Block-scoped, so not part of the exchange state root.
        self._balance_deltas: Dict[str, Decimal] = {}
        # Collateral enforcement gate (set by the node when enforcing): when True,
        # open_position rejects if margin exceeds available balance.
        self.enforce_collateral: bool = False

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
        self._balance_deltas = {}  # Phase E: reset per-block balance deltas

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

    def commit_block(self) -> None:
        """
        Accept the current block's state changes as final.

        Discards the pre-block revert snapshot so a later ``revert_block`` cannot
        undo committed state. Called once a block (its exchange section) has been
        validated and accepted by consensus.
        """
        self._snapshot = None

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
            ExchangeOpType.CREATE_MARKET: self._op_create_market,
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

    def _op_create_market(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        """Create a perpetual market so positions can be opened (consensus path).

        Idempotent-on-conflict: a duplicate market_id is a non-critical failure
        (the market already exists), not a block-breaking error.
        """
        p = tx.params
        base = str(p["base_token"])
        quote = str(p.get("quote_token", "QRDX"))
        kwargs = {}
        if "initial_margin_rate" in p:
            kwargs["initial_margin_rate"] = Decimal(str(p["initial_margin_rate"]))
        if "maintenance_margin_rate" in p:
            kwargs["maintenance_margin_rate"] = Decimal(str(p["maintenance_margin_rate"]))
        if "max_leverage" in p:
            kwargs["max_leverage"] = Decimal(str(p["max_leverage"]))
        try:
            market = self.perp_engine.create_market(base, quote, **kwargs)
        except ValueError as e:
            return ExchangeExecResult(success=False, error=str(e))
        self._total_positions += 0  # markets aren't positions
        return ExchangeExecResult(
            success=True,
            gas_used=EXCHANGE_GAS_COSTS[ExchangeOpType.CREATE_MARKET],
            data={"market_id": market.id},
        )

    def _op_open_position(self, tx: ExchangeTransaction) -> ExchangeExecResult:
        p = tx.params
        raw_side = p["side"]
        try:
            side = PerpSide(raw_side)
        except ValueError:
            side = PerpSide[str(raw_side).upper()]

        # Phase E: the position's margin must be backed by real collateral. We can
        # only check/lock when balances are pre-loaded; compute the required margin
        # the same way PerpEngine does so we can decide BEFORE opening.
        avail = self.available_balance(tx.sender)
        market = self.perp_engine.get_market(p["market_id"]) if hasattr(self.perp_engine, "get_market") else None
        size = Decimal(str(p["size"]))
        price = Decimal(str(p["price"]))
        leverage = Decimal(str(p["leverage"]))
        notional = size * price
        req_margin = notional / leverage
        if market is not None:
            min_margin = notional * market.initial_margin_rate
            if min_margin > req_margin:
                req_margin = min_margin

        if avail is not None and avail < req_margin:
            if self.enforce_collateral:
                return ExchangeExecResult(
                    success=False,
                    error=(f"insufficient collateral: need margin {req_margin}, "
                           f"available {avail}"),
                )
            logger.warning(
                "[Phase E observe] open_position by %s: margin %s exceeds available "
                "balance %s — would REJECT once collateral is enforced",
                tx.sender[:20], req_margin, avail,
            )

        pos = self.perp_engine.open_position(
            p["market_id"], tx.sender, side, size, leverage, price,
            reduce_only=p.get("reduce_only", False),
        )

        self._total_positions += 1
        # Lock the margin as a real-balance debit for this block (flushed to
        # account_state by the async wrapper when enforced).
        self._record_balance_delta(tx.sender, -pos.margin)

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
            128-char hex string (BLAKE3-512, Whitepaper §3.6 quantum-resistant
            state root). Internal per-component digests use blake2b as a
            deterministic compression step; the committed root is BLAKE3.
        """
        import blake3
        hasher = blake3.blake3()

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

        from ..crypto.hashing import STATE_ROOT_SIZE
        return hasher.digest(length=STATE_ROOT_SIZE).hex()

    # =====================================================================
    #  Snapshot / restore (for revert)
    # =====================================================================

    def take_snapshot(self) -> Dict[str, Any]:
        """
        Capture a COMPLETE deep copy of all consensus-critical state so that
        revert_block() restores the exact pre-block state — including entities
        CREATED during the block (new pools, order books, oracles, perp markets
        and positions), which a field-level snapshot cannot remove. Correctness
        over speed: a rejected block must leave local state byte-identical.
        """
        import copy

        snapshot = {
            "nonces": dict(self._nonces),
            "block_height": self._current_block_height,
            "block_timestamp": self._current_block_timestamp,
            "total_swaps": self._total_swaps,
            "total_orders": self._total_orders,
            "total_pools": self._total_pools,
            "total_positions": self._total_positions,
            # Full deep copies of the mutable engine containers.
            "pools": copy.deepcopy(self.pool_manager._pools),
            "pair_index": copy.deepcopy(self.pool_manager._pair_index),
            "pool_sequence": self.pool_manager._pool_sequence,
            "order_books": copy.deepcopy(self._order_books),
            "oracles": copy.deepcopy(self._oracles),
            "perp_markets": copy.deepcopy(self.perp_engine._markets),
            "perp_positions": copy.deepcopy(self.perp_engine._positions),
            "perp_owner_positions": copy.deepcopy(self.perp_engine._owner_positions),
            "perp_pos_sequence": self.perp_engine._pos_sequence,
            "perp_paused": self.perp_engine._paused,
            "precompile_pools": copy.deepcopy(self._precompile_pools),
            "precompile_orderbooks": copy.deepcopy(self._precompile_orderbooks),
        }
        self._snapshot = snapshot
        return snapshot

    def _restore_snapshot(self, snapshot: Dict[str, Any]) -> None:
        """
        Restore the EXACT pre-block state from a snapshot.

        Containers are restored IN PLACE (clear + repopulate) so external
        references stay valid — notably the router's order-book/oracle registries
        and its handle to ``pool_manager``.
        """
        import copy

        self._nonces = dict(snapshot["nonces"])
        self._current_block_height = snapshot["block_height"]
        self._current_block_timestamp = snapshot["block_timestamp"]
        self._total_swaps = snapshot["total_swaps"]
        self._total_orders = snapshot["total_orders"]
        self._total_pools = snapshot["total_pools"]
        self._total_positions = snapshot["total_positions"]

        # Pools (in place; the router shares this pool_manager).
        self.pool_manager._pools.clear()
        self.pool_manager._pools.update(copy.deepcopy(snapshot["pools"]))
        self.pool_manager._pair_index.clear()
        self.pool_manager._pair_index.update(copy.deepcopy(snapshot["pair_index"]))
        self.pool_manager._pool_sequence = snapshot["pool_sequence"]

        # Order books + oracles: put the SAME restored objects into both the
        # manager and the router registries so they remain consistent.
        restored_books = copy.deepcopy(snapshot["order_books"])
        self._order_books.clear()
        self._order_books.update(restored_books)
        self.router._order_books.clear()
        self.router._order_books.update(restored_books)

        restored_oracles = copy.deepcopy(snapshot["oracles"])
        self._oracles.clear()
        self._oracles.update(restored_oracles)
        self.router._oracles.clear()
        self.router._oracles.update(restored_oracles)

        # Perp engine.
        self.perp_engine._markets.clear()
        self.perp_engine._markets.update(copy.deepcopy(snapshot["perp_markets"]))
        self.perp_engine._positions.clear()
        self.perp_engine._positions.update(copy.deepcopy(snapshot["perp_positions"]))
        self.perp_engine._owner_positions.clear()
        self.perp_engine._owner_positions.update(copy.deepcopy(snapshot["perp_owner_positions"]))
        self.perp_engine._pos_sequence = snapshot["perp_pos_sequence"]
        self.perp_engine._paused = snapshot["perp_paused"]

        # Precompile EVM state.
        self._precompile_pools = copy.deepcopy(snapshot.get("precompile_pools", {}))
        self._precompile_orderbooks = copy.deepcopy(snapshot.get("precompile_orderbooks", {}))

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

    # --- Phase E: real-balance bridge ---

    def set_available_balance(self, address: str, qrdx: Decimal) -> None:
        """Pre-load a sender's available QRDX balance (from account_state) for the
        collateral check. Called by the async block paths before processing."""
        self._available_balances[address] = Decimal(qrdx)

    def available_balance(self, address: str) -> Optional[Decimal]:
        """Pre-loaded available balance, or None if not loaded (check is skipped)."""
        return self._available_balances.get(address)

    def clear_available_balances(self) -> None:
        """Reset the pre-loaded balances (call per block)."""
        self._available_balances.clear()

    def _record_balance_delta(self, address: str, delta_qrdx: Decimal) -> None:
        """Accumulate a real-balance delta for this block (negative = debit) and
        keep the in-memory available balance in step so later ops in the same
        block see the locked amount."""
        self._balance_deltas[address] = self._balance_deltas.get(address, ZERO) + delta_qrdx
        if address in self._available_balances:
            self._available_balances[address] = self._available_balances[address] + delta_qrdx

    def balance_deltas(self) -> Dict[str, Decimal]:
        """This block's accumulated per-address balance deltas (QRDX)."""
        return dict(self._balance_deltas)

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
