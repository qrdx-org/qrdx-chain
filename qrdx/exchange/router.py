"""
QRDX Unified Router  (Whitepaper §7.2 Component 3 + §7.4)

Best execution for a swap across the pair's AMM pools (every fee tier) and its order book.

The router PLANS: it quotes every venue exactly — each pool by simulating the swap on its own
curve (``ConcentratedLiquidityPool.quote``), the order book by walking resting orders in
price-time priority exactly as matching will (stopping at the trader's own order, as
self-trade prevention does) — and returns the best ``Route``. Executing a route
(``apply_route``) then does precisely what was quoted. The exchange manager checks slippage and
balances on the plan BEFORE anything changes, and settles each venue with its real counterparty:
the pool's reserves for an AMM route, the matched makers' escrow for an order-book route.

What it no longer does: record fills into the pair's reporter oracle (wall-clock timestamps there
made replays diverge; each pool now keeps its own block-time oracle), or run a price-deviation
"circuit breaker" after the trade had already mutated state (it failed every swap in the
opposite direction). A trader bounds their price with ``min_amount_out``.

Order-book side: a pair's book is keyed ``base:quote`` with the tokens sorted. Paying with the
base token is a SELL (walks the bids); paying with the quote token is a BUY of base (walks the
asks, buying as much base as the quote budget affords).
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from decimal import ROUND_DOWN, ROUND_FLOOR, ROUND_HALF_UP, Decimal
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

from qrdx.exchange.amm import (
    AMOUNT_QUANTUM,
    ConcentratedLiquidityPool,
    FEE_CREATOR_SHARE,
    FEE_LP_SHARE,
    FEE_TREASURY_SHARE,
    FEE_VALIDATOR_SHARE,
    PoolManager,
    SwapPlan,
)
from qrdx.exchange.orderbook import (
    MIN_ORDER_SIZE, Order, OrderBook, OrderSide, OrderType, Trade, _pinned,
)
from qrdx.exchange.oracle import TWAPOracle

logger = logging.getLogger(__name__)

ZERO = Decimal("0")
MAX_PRICE_DEVIATION = Decimal("0.10")  # kept for callers that pass it; no longer enforced
DEFAULT_DEADLINE_SECONDS = 120


class FillSource(str, Enum):
    AMM = "amm"
    CLOB = "clob"       # central limit order book
    HYBRID = "hybrid"   # reserved


@dataclass
class FillResult:
    """Result of a routed trade execution."""
    source: FillSource
    amount_in: Decimal
    amount_out: Decimal
    fee_total: Decimal
    fee_lp: Decimal
    fee_creator: Decimal
    fee_treasury: Decimal
    fee_validator: Decimal
    price: Decimal               # effective execution price (input per unit of output)
    trades: List[Trade]          # order book fills (if any)
    pool_id: Optional[str] = None
    order: Optional[Order] = None


@dataclass
class Route:
    """An exactly-quoted way to fill a swap."""
    source: FillSource
    token_in: str
    token_out: str
    amount_in: Decimal           # input it will consume (≤ requested; the rest stays with the trader)
    amount_out: Decimal
    fee_total: Decimal
    pool_id: Optional[str] = None
    plan: Optional[SwapPlan] = None
    pair: Optional[str] = None   # order book key
    side: Optional[OrderSide] = None
    size: Decimal = ZERO         # base units
    limit_price: Decimal = ZERO

    @property
    def price(self) -> Decimal:
        return self.amount_in / self.amount_out if self.amount_out > 0 else ZERO


class UnifiedRouter:
    """Best-execution router across AMM pools and the on-chain order book."""

    def __init__(
        self,
        pool_manager: Optional[PoolManager] = None,
        order_books: Optional[Dict[str, OrderBook]] = None,
        oracles: Optional[Dict[str, TWAPOracle]] = None,
        max_price_deviation: Decimal = MAX_PRICE_DEVIATION,
    ):
        self.pool_manager = pool_manager or PoolManager()
        self._order_books: Dict[str, OrderBook] = order_books or {}
        self._oracles: Dict[str, TWAPOracle] = oracles or {}
        self._max_price_deviation = max_price_deviation
        self._paused: bool = False
        self._clob_sequence: int = 0  # deterministic order ID counter
        # Consensus clock for the swap deadline (the exchange manager points it at the block).
        self.clock: Callable[[], float] = time.time

    # -- Emergency controls -------------------------------------------------

    def pause(self) -> None:
        self._paused = True

    def unpause(self) -> None:
        self._paused = False

    @property
    def is_paused(self) -> bool:
        return self._paused

    # -- Registries ---------------------------------------------------------

    def register_order_book(self, pair_key: str, book: OrderBook) -> None:
        self._order_books[pair_key] = book

    def unregister_order_book(self, pair_key: str) -> None:
        self._order_books.pop(pair_key, None)

    def register_oracle(self, pair_key: str, oracle: TWAPOracle) -> None:
        self._oracles[pair_key] = oracle

    def get_order_book(self, pair_key: str) -> Optional[OrderBook]:
        return self._order_books.get(pair_key)

    def get_oracle(self, pair_key: str) -> Optional[TWAPOracle]:
        return self._oracles.get(pair_key)

    # -- Quoting (read-only, exact) -----------------------------------------

    def amm_routes(self, token_in: str, token_out: str, amount_in: Decimal,
                   pool_id: Optional[str] = None) -> List[Route]:
        routes = []
        pools = ([self.pool_manager.get_pool(pool_id)] if pool_id
                 else self.pool_manager.get_pools_for_pair(token_in, token_out))
        for pool in sorted((p for p in pools if p is not None), key=lambda p: p.state.id):
            if {pool.state.token0, pool.state.token1} != {token_in, token_out}:
                continue
            try:
                plan = pool.quote(amount_in, zero_for_one=(token_in == pool.state.token0))
            except ValueError:
                continue
            routes.append(Route(FillSource.AMM, token_in, token_out, plan.amount_in,
                                plan.amount_out, plan.fee, pool_id=pool.state.id, plan=plan))
        return routes

    @_pinned
    def clob_route(self, token_in: str, token_out: str, amount_in: Decimal,
                   sender: str = "") -> Optional[Route]:
        """Walk the book exactly as matching will. None if it cannot fill anything."""
        pair = self._pair_key(token_in, token_out)
        book = self._order_books.get(pair)
        if book is None or amount_in <= 0:
            return None
        base = pair.split(":", 1)[0]
        selling = token_in == base
        side = OrderSide.SELL if selling else OrderSide.BUY
        levels = book._bids if selling else book._asks
        prices = sorted(levels, reverse=selling)
        size = spent = out = ZERO
        limit = ZERO
        done = False
        for price in prices:
            for order in levels[price].orders:
                if not order.is_active:
                    continue
                if order.owner == sender:          # self-trade prevention stops the taker here
                    done = True
                    break
                if selling:
                    take = min(order.remaining, amount_in - size)
                    out += take * price
                else:
                    affordable = ((amount_in - spent) / price).quantize(AMOUNT_QUANTUM,
                                                                        rounding=ROUND_DOWN)
                    take = min(order.remaining, affordable)
                    spent += take * price
                    out += take
                if take <= 0:
                    done = True
                    break
                size += take
                limit = price
                if (selling and size >= amount_in) or (not selling and amount_in - spent <= 0):
                    done = True
                    break
            if done:
                break
        if size < MIN_ORDER_SIZE or out <= 0:
            return None
        used = size if selling else spent
        return Route(FillSource.CLOB, token_in, token_out, used, out, ZERO, pair=pair,
                     side=side, size=size, limit_price=limit)

    def best_route(self, token_in: str, token_out: str, amount_in: Decimal, sender: str = "",
                   pool_id: Optional[str] = None, venue: str = "auto") -> Optional[Route]:
        """The route giving the most output (ties: the AMM, then the lowest pool id)."""
        amount_in = Decimal(str(amount_in))
        candidates: List[Route] = []
        if venue in ("auto", "amm"):
            candidates += self.amm_routes(token_in, token_out, amount_in, pool_id)
        if venue in ("auto", "clob") and not pool_id:
            r = self.clob_route(token_in, token_out, amount_in, sender)
            if r is not None:
                candidates.append(r)
        if not candidates:
            return None
        return max(candidates, key=lambda r: (r.amount_out, r.source == FillSource.AMM,
                                              [-ord(c) for c in (r.pool_id or "")]))

    # Back-compat quoting helpers ----------------------------------------------

    def quote_amm(self, token_in: str, token_out: str, amount_in: Decimal
                  ) -> Optional[Tuple[Decimal, Decimal, str]]:
        routes = self.amm_routes(token_in, token_out, Decimal(str(amount_in)))
        if not routes:
            return None
        best = max(routes, key=lambda r: r.amount_out)
        return best.amount_out, best.fee_total, best.pool_id

    def quote_clob(self, token_in: str, token_out: str, amount_in: Decimal
                   ) -> Optional[Tuple[Decimal, Decimal]]:
        r = self.clob_route(token_in, token_out, Decimal(str(amount_in)))
        return None if r is None else (r.amount_out, r.fee_total)

    # -- Execution ----------------------------------------------------------

    @_pinned
    def apply_route(self, route: Route, sender: str, now: Optional[int] = None) -> FillResult:
        """Execute a route from ``best_route`` against unchanged state: exactly what it quoted."""
        if self._paused:
            raise ValueError("Router is paused — emergency mode")
        if route.source == FillSource.AMM:
            pool = self.pool_manager.get_pool(route.pool_id)
            if pool is None:
                raise ValueError(f"Pool {route.pool_id} not found")
            pool.apply(route.plan, now)
            fees = self._fee_parts(route.plan.fee, route.plan.protocol_fee)
            return FillResult(source=FillSource.AMM, amount_in=route.amount_in,
                              amount_out=route.amount_out, fee_total=route.fee_total, **fees,
                              price=route.price, trades=[], pool_id=route.pool_id)
        book = self._order_books[route.pair]
        self._clob_sequence += 1
        order = Order(id=self._deterministic_clob_order_id(sender, self._clob_sequence),
                      owner=sender, side=route.side, order_type=OrderType.LIMIT,
                      price=route.limit_price, amount=route.size, nonce=0, timestamp=0.0)
        trades = book.place_order(order, protocol=True)
        if order.is_active:
            book.cancel_order(order.id, caller=sender)          # immediate-or-cancel
        filled = sum((t.amount for t in trades), ZERO)
        if filled != route.size:
            raise ValueError(f"order book fill {filled} differs from its quote {route.size}")
        fees = self._fee_parts(ZERO, ZERO)
        return FillResult(source=FillSource.CLOB, amount_in=route.amount_in,
                          amount_out=route.amount_out, fee_total=ZERO, **fees,
                          price=route.price, trades=trades, order=order)

    def execute(
        self,
        token_in: str,
        token_out: str,
        amount_in: Decimal,
        sender: str,
        max_slippage: Decimal = Decimal("0.01"),
        min_amount_out: Decimal = ZERO,
        deadline: float = 0.0,
    ) -> FillResult:
        """Route and execute (for callers outside the exchange manager). Every check runs on the
        quote, before anything changes."""
        if self._paused:
            raise ValueError("Router is paused — emergency mode")
        amount_in = Decimal(str(amount_in))
        if amount_in <= 0:
            raise ValueError("Amount must be positive")
        if not sender:
            raise ValueError("Sender address required")
        if deadline > 0 and self.clock() > deadline:
            raise ValueError("Transaction deadline expired")
        route = self.best_route(token_in, token_out, amount_in, sender)
        if route is None:
            raise ValueError("No liquidity available for this pair")
        if min_amount_out > 0 and route.amount_out < min_amount_out:
            raise ValueError(f"Slippage exceeded: got {route.amount_out}, minimum {min_amount_out}")
        return self.apply_route(route, sender)

    # -- Helpers ------------------------------------------------------------

    @staticmethod
    def _fee_parts(total: Decimal, protocol: Decimal) -> Dict[str, Decimal]:
        """The fee as the pool splits it (§7.6): LPs' share, and the protocol's divided between
        creator, treasury and validators in proportion 15 : 10 : 5."""
        lp = total - protocol
        protocol_shares = FEE_CREATOR_SHARE + FEE_TREASURY_SHARE + FEE_VALIDATOR_SHARE
        if protocol > 0:
            creator = (protocol * FEE_CREATOR_SHARE / protocol_shares).quantize(
                Decimal("1e-18"), rounding=ROUND_DOWN)
            treasury = (protocol * FEE_TREASURY_SHARE / protocol_shares).quantize(
                Decimal("1e-18"), rounding=ROUND_DOWN)
        else:
            creator = treasury = ZERO
        return {"fee_lp": lp, "fee_creator": creator, "fee_treasury": treasury,
                "fee_validator": protocol - creator - treasury}

    @staticmethod
    def _split_fees(total: Decimal) -> Dict[str, Decimal]:
        """Distribute a fee per §7.6 (70 / 15 / 10 / 5) — reporting helper."""
        lp = (total * FEE_LP_SHARE).quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)
        creator = (total * FEE_CREATOR_SHARE).quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)
        treasury = (total * FEE_TREASURY_SHARE).quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)
        validator = total - lp - creator - treasury
        return {"fee_lp": lp, "fee_creator": creator, "fee_treasury": treasury,
                "fee_validator": validator}

    @staticmethod
    def _pair_key(token_a: str, token_b: str) -> str:
        a, b = (token_a, token_b) if token_a < token_b else (token_b, token_a)
        return f"{a}:{b}"

    @staticmethod
    def _deterministic_clob_order_id(sender: str, seq: int) -> str:
        """Deterministic order ID for order-book fills via the router."""
        raw = f"router:{sender}:{seq}".encode()
        return hashlib.blake2b(raw, digest_size=8).hexdigest()
