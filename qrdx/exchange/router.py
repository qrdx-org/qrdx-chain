"""
QRDX Unified Router  (Whitepaper §7.2 Component 3 + §7.4)

Best execution for a swap across the pair's AMM pools (every fee tier) and its order book.

The router PLANS: it quotes every venue exactly — each pool by simulating the swap on its own
curve (``ConcentratedLiquidityPool.quote``), the order book by walking resting orders in
the priority matching uses (price, then displayed before hidden, then time) exactly as matching
will (stopping at the trader's own order, as
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
from decimal import ROUND_DOWN, Decimal
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from qrdx.exchange.amm import (
    AMOUNT_QUANTUM,
    FEE_CREATOR_SHARE,
    FEE_LP_SHARE,
    FEE_TREASURY_SHARE,
    FEE_VALIDATOR_SHARE,
    MAX_TICK,
    MIN_TICK,
    Q96,
    PoolManager,
    SwapPlan,
    _sqrt_ratio,
)
from qrdx.exchange.orderbook import (
    MIN_ORDER_SIZE,
    MatchBudget,
    Order,
    OrderBook,
    OrderSide,
    OrderType,
    Trade,
    _pinned,
)

logger = logging.getLogger(__name__)

ZERO = Decimal("0")
MAX_PRICE_DEVIATION = Decimal("0.10")  # kept for callers that pass it; no longer enforced
DEFAULT_DEADLINE_SECONDS = 120
# Bisection steps that split a fill between pools at the same price (docs/UNIFIED_SPOT_LIQUIDITY.md)
SPLIT_STEPS = 40


def _units(amount: Decimal) -> Decimal:
    """``amount`` in a token's units (18 decimals), rounded down only if it has more."""
    units = amount.quantize(AMOUNT_QUANTUM, rounding=ROUND_DOWN)
    return amount if units == amount else units


class FillSource(str, Enum):
    AMM = "amm"
    CLOB = "clob"  # central limit order book
    HYBRID = "hybrid"  # reserved


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
    price: Decimal  # effective execution price (input per unit of output)
    trades: List[Trade]  # order book fills (if any)
    pool_id: Optional[str] = None
    order: Optional[Order] = None
    makers_visited: int = 0  # resting orders an order-book fill visited (its matching gas)


@dataclass
class Leg:
    """One venue's part of a fill: the order book's (one leg, however many levels it takes) or
    one pool's (one plan, however many times the walk came back to it)."""

    source: FillSource
    amount_in: Decimal  # what the taker pays in (a pool's fee included)
    amount_out: Decimal  # what the taker receives (after the order book's taker fees)
    fee: Decimal  # a pool's fee, in the input; the order book's taker fees, in the output
    base: Decimal = ZERO  # base traded
    price: Decimal = ZERO  # the pair's price where it left the venue (quote per base)
    pool_id: Optional[str] = None
    plan: Optional[SwapPlan] = None
    limit_price: Decimal = ZERO  # the order book: the worst level it takes
    makers: int = 0  # the order book: resting orders it visits


@dataclass
class Route:
    """An exactly-quoted way to fill a swap."""

    source: FillSource
    token_in: str
    token_out: str
    amount_in: Decimal  # input it will consume (≤ requested; the rest stays with the trader)
    amount_out: Decimal
    fee_total: Decimal
    pool_id: Optional[str] = None
    plan: Optional[SwapPlan] = None
    pair: Optional[str] = None  # order book key
    side: Optional[OrderSide] = None
    size: Decimal = ZERO  # base units
    limit_price: Decimal = ZERO
    makers: int = 0  # resting orders the fill visits (an order-book route)
    parts: List[Leg] = field(default_factory=list)  # a combined route's legs (``plan_fill``)
    stopped: str = ""  # why a combined route stopped short: "self", "budget", "dust" or ""
    last_price: Decimal = ZERO  # the worst price the fill reached (quote per base)

    @property
    def price(self) -> Decimal:
        return self.amount_in / self.amount_out if self.amount_out > 0 else ZERO

    @property
    def legs(self) -> List[Leg]:
        """What executes: the combined route's legs, or a single venue's one."""
        if self.parts:
            return self.parts
        if self.source == FillSource.AMM:
            return [
                Leg(
                    FillSource.AMM,
                    self.amount_in,
                    self.amount_out,
                    self.fee_total,
                    pool_id=self.pool_id,
                    plan=self.plan,
                )
            ]
        return [
            Leg(
                FillSource.CLOB,
                self.amount_in,
                self.amount_out,
                self.fee_total,
                base=self.size,
                price=self.limit_price,
                limit_price=self.limit_price,
                makers=self.makers,
            )
        ]

    def amm(self) -> Tuple[str, SwapPlan]:
        """(pool id, plan) — set on every AMM route."""
        if self.pool_id is None or self.plan is None:
            raise ValueError("not an AMM route")
        return self.pool_id, self.plan

    def clob(self) -> Tuple[str, OrderSide]:
        """(order-book pair, side) — set on every order-book route."""
        if self.pair is None or self.side is None:
            raise ValueError("not an order-book route")
        return self.pair, self.side


class UnifiedRouter:
    """Best-execution router across AMM pools and the on-chain order book."""

    def __init__(
        self,
        pool_manager: Optional[PoolManager] = None,
        order_books: Optional[Dict[str, OrderBook]] = None,
        max_price_deviation: Decimal = MAX_PRICE_DEVIATION,
    ):
        self.pool_manager = pool_manager or PoolManager()
        self._order_books: Dict[str, OrderBook] = order_books or {}
        self._max_price_deviation = max_price_deviation
        self._paused: bool = False
        self._clob_sequence: int = 0  # deterministic order ID counter
        # (sender, value received) → the taker's spot fee on one fill, as settlement charges it
        # (the exchange manager sets it): a quote is net of it, fill by fill, exactly.
        self.taker_fee: Optional[Callable[[str, Decimal], Decimal]] = None
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

    def get_order_book(self, pair_key: str) -> Optional[OrderBook]:
        return self._order_books.get(pair_key)

    # -- Quoting (read-only, exact) -----------------------------------------

    def amm_routes(
        self, token_in: str, token_out: str, amount_in: Decimal, pool_id: Optional[str] = None
    ) -> List[Route]:
        routes = []
        pools = (
            [self.pool_manager.get_pool(pool_id)]
            if pool_id
            else self.pool_manager.get_pools_for_pair(token_in, token_out)
        )
        for pool in sorted((p for p in pools if p is not None), key=lambda p: p.state.id):
            if {pool.state.token0, pool.state.token1} != {token_in, token_out}:
                continue
            try:
                plan = pool.quote(amount_in, zero_for_one=(token_in == pool.state.token0))
            except ValueError:
                continue
            routes.append(
                Route(
                    FillSource.AMM,
                    token_in,
                    token_out,
                    plan.amount_in,
                    plan.amount_out,
                    plan.fee,
                    pool_id=pool.state.id,
                    plan=plan,
                )
            )
        return routes

    @_pinned
    def clob_route(
        self,
        token_in: str,
        token_out: str,
        amount_in: Decimal,
        sender: str = "",
        max_makers: Optional[int] = None,
    ) -> Optional[Route]:
        """Walk the book exactly as matching will — visiting no more than ``max_makers``
        resting orders, as matching on that budget would (``MatchBudget``). None if it cannot
        fill anything."""
        pair = self._pair_key(token_in, token_out)
        book = self._order_books.get(pair)
        if book is None or amount_in <= 0:
            return None
        base = pair.split(":", 1)[0]
        selling = token_in == base
        side = OrderSide.SELL if selling else OrderSide.BUY
        levels = book._bids if selling else book._asks
        prices = sorted(levels, reverse=selling)
        size = spent = out = fees = ZERO
        limit = ZERO
        visited = 0
        done = False
        fee_of = self.taker_fee
        for price in prices:
            # Displayed quantities first, then hidden ones — matching's priority.
            for order, offered in book.fill_queue(levels[price]):
                if order.owner == sender:  # self-trade prevention stops the taker here
                    done = True
                    break
                if max_makers is not None and visited >= max_makers:
                    done = True  # out of budget: matching stops here too
                    break
                visited += 1
                if selling:
                    take = min(offered, amount_in - size)
                    received = take * price
                else:
                    affordable = ((amount_in - spent) / price).quantize(
                        AMOUNT_QUANTUM, rounding=ROUND_DOWN
                    )
                    take = min(offered, affordable)
                    spent += take * price
                    received = take
                if take <= 0:
                    done = True
                    break
                fee = fee_of(sender, received) if fee_of is not None else ZERO
                out += received - fee
                fees += fee
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
        return Route(
            FillSource.CLOB,
            token_in,
            token_out,
            used,
            out,
            fees,
            pair=pair,
            side=side,
            size=size,
            limit_price=limit,
            makers=visited,
        )

    def taker_rate(self, sender: str) -> Decimal:
        """The order book's taker fee rate for ``sender``, as settlement charges it (it ranks the
        book against the pools; the fee itself is charged fill by fill)."""
        if self.taker_fee is None:
            return ZERO
        unit = Decimal(10**9)
        return self.taker_fee(sender, unit) / unit

    @_pinned
    def plan_fill(
        self,
        pair: str,
        buy: bool,
        amount: Decimal,
        *,
        exact_in: bool,
        limit: Optional[Decimal] = None,
        sender: str = "",
        max_makers: Optional[int] = None,
        pool_ids: Optional[List[str]] = None,
        book: bool = True,
        pools: bool = True,
    ) -> Optional[Route]:
        """The best fill of one taker on a pair's combined market — its order book and every
        pool — walked in price order (docs/UNIFIED_SPOT_LIQUIDITY.md). Read only: it returns the
        legs, and executing them does exactly what they say.

        ``buy``: the taker buys base (pays quote). ``amount``: with ``exact_in``, what it pays
        in; otherwise the base it buys (a sell's amount is always the base it sells).
        ``limit``: the worst price (quote per base) — a book level's own price, a pool's
        marginal price with its fee. Prices are ranked after each venue's fee; resting orders
        come first at the same price; pools at the same price move together, the amount split
        so they end at one marginal price. At the taker's own resting order the book closes to
        it (self-trade prevention; the pools may still fill it); at ``max_makers`` resting
        orders visited it stops, as matching does. None if nothing fills."""
        amount = Decimal(str(amount))
        if amount <= 0 or ":" not in pair:
            return None
        base, quote = pair.split(":", 1)
        ob = self._order_books.get(pair) if book else None
        candidates_pools = []
        if pools:
            for pool in sorted(
                self.pool_manager.get_pools_for_pair(base, quote), key=lambda p: p.state.id
            ):
                if pool.is_paused or (pool_ids is not None and pool.state.id not in pool_ids):
                    continue
                if (pool.state.token0, pool.state.token1) != (base, quote):
                    continue
                candidates_pools.append(pool)
        rate = self.taker_rate(sender)
        zfo = not buy  # selling base (token0) moves a pool's price down
        out_mode = buy and not exact_in  # pools quoted by the base they deliver

        def key(eff: Decimal) -> Decimal:  # lower is better, either way
            return eff if buy else -eff

        def pool_eff(pool, raw: Decimal) -> Decimal:
            f = pool.state.fee_tier.rate
            return raw / (1 - f) if buy else raw * (1 - f)

        def pool_limit(pool, eff: Optional[Decimal]) -> Decimal:
            """The plain √price where the pool's marginal price, fee included, is ``eff``."""
            if eff is None:
                return _sqrt_ratio(MIN_TICK if zfo else MAX_TICK)
            f = pool.state.fee_tier.rate
            raw = eff * (1 - f) if buy else eff / (1 - f)
            return raw.sqrt() if raw > 0 else _sqrt_ratio(MIN_TICK)

        def measure(plan: SwapPlan) -> Decimal:
            return plan.amount_out if out_mode else plan.amount_in

        # Pools: where each stands (its plan so far), and its marginal price (None: no more).
        state: Dict[str, Dict[str, Any]] = {}
        for pool in candidates_pools:
            s0 = pool.liquid_sqrt(zfo)
            state[pool.state.id] = {
                "pool": pool,
                "plan": None,
                "eff": None if s0 is None else pool_eff(pool, s0 * s0),
            }

        def refresh(ps: Dict[str, Any], reached: Optional[Decimal]) -> None:
            plan, pool = ps["plan"], ps["pool"]
            if plan.exhausted:
                ps["eff"] = None
            elif plan.liquidity > 0 and reached is not None:
                ps["eff"] = reached  # (exactly the price it was moved to: ties stay ties)
            else:
                s1 = pool.liquid_sqrt(zfo, start=plan)
                ps["eff"] = None if s1 is None else pool_eff(pool, s1 * s1)

        def quote_to(ps: Dict[str, Any], amt: Decimal, eff: Optional[Decimal]) -> SwapPlan:
            return ps["pool"].quote(
                amt,
                zfo,
                sqrt_limit=pool_limit(ps["pool"], eff),
                exact_out=out_mode,
                start=ps["plan"],
            )

        def commit(ps: Dict[str, Any], plan: SwapPlan, reached: Optional[Decimal]) -> None:
            ps["plan"] = plan if ps["plan"] is None else ps["plan"].then(plan)
            ps["chain"] = ps.get("chain", 0) + 1
            refresh(ps, reached)

        # The order book: its levels on the taker's opposite side, best first.
        side_levels = (ob._asks if buy else ob._bids) if ob is not None else {}
        levels = sorted(side_levels, reverse=not buy)
        li, qi = 0, 0
        queue: Optional[List[Tuple[Order, Decimal]]] = None
        book_open = ob is not None
        left = max_makers
        size = spent = got = fees = ZERO
        visited = 0
        book_limit = ZERO
        fee_of = self.taker_fee
        remaining = amount
        stopped = ""
        self_stop = False
        steps = 0
        while remaining > 0 and not stopped:
            steps += 1
            if steps > 64 + 4 * (len(levels) + len(state)):  # (each step passes a price)
                break
            level_price = None
            while book_open and li < len(levels):
                lp = levels[li]
                if limit is not None and (lp > limit if buy else lp < limit):
                    book_open = False
                    break
                if queue is None:
                    queue, qi = OrderBook.fill_queue(side_levels[lp]), 0
                if qi >= len(queue):
                    li, queue = li + 1, None
                    continue
                level_price = lp
                break
            options: List[Tuple[Decimal, int, str]] = []
            if level_price is not None:
                book_eff = level_price / (1 - rate) if buy else level_price * (1 - rate)
                options.append((key(book_eff), 0, ""))
            for pid, ps in state.items():
                if ps["eff"] is not None and (limit is None or key(ps["eff"]) < key(limit)):
                    options.append((key(ps["eff"]), 1, pid))
            if not options:
                break
            options.sort()
            best_key, kind, _pid = options[0]
            if kind == 0 and queue is not None and level_price is not None:
                # The book's level: maker by maker, as matching takes them.
                while qi < len(queue) and remaining > 0:
                    order, offered = queue[qi]
                    if order.owner == sender:
                        # Self-trade prevention: the book is closed to the taker from here; the
                        # pools may still fill it (it passes only its own order).
                        book_open, self_stop = False, True
                        break
                    if left is not None and left <= 0:  # out of budget: matching stops here
                        stopped = "budget"
                        break
                    if buy and exact_in:
                        affordable = (remaining / level_price).quantize(
                            AMOUNT_QUANTUM, rounding=ROUND_DOWN
                        )
                        take = min(offered, affordable)
                    else:
                        take = min(offered, remaining)
                    if take <= 0:
                        stopped = "dust"
                        break
                    if left is not None:
                        left -= 1
                    visited += 1
                    received = take if buy else take * level_price
                    fee = fee_of(sender, received) if fee_of is not None else ZERO
                    size += take
                    spent += take * level_price if buy else take
                    got += received - fee
                    fees += fee
                    book_limit = level_price
                    remaining -= take * level_price if (buy and exact_in) else take
                    if take < offered:
                        queue[qi] = (order, offered - take)
                    else:
                        qi += 1
                continue
            # Pools: every pool at the best price moves to the next price anything else offers
            # (the book's next level, another pool, the limit) — together.
            active = [pid for k, t, pid in options if t == 1 and k == best_key]
            beyond = [k for k, _t, _p in options if k > best_key]
            if limit is not None:
                beyond.append(key(limit))
            target_key = min(beyond) if beyond else None
            target = None if target_key is None else (target_key if buy else -target_key)
            amt = _units(remaining)
            if amt <= 0:
                stopped = "dust"
                break
            plans = {pid: quote_to(state[pid], amt, target) for pid in active}
            total = sum((measure(q) for q in plans.values()), ZERO)
            if any(q.amount_out <= 0 < q.amount_in for q in plans.values()):
                stopped = "dust"  # (input too small to buy anything)
                break
            if total <= amt:
                for pid, q in plans.items():
                    commit(state[pid], q, target)
                remaining -= total
                continue
            # More than is left: split it so they end at one marginal price.
            ends = [
                pool_eff(state[pid]["pool"], (q.sqrt_price / Q96) ** 2) for pid, q in plans.items()
            ]
            lo = best_key
            hi = target_key if target_key is not None else max(key(e) for e in ends)
            for _ in range(SPLIT_STEPS):
                mid = (lo + hi) / 2
                eff = mid if buy else -mid
                f_mid = sum((measure(quote_to(state[pid], amt, eff)) for pid in active), ZERO)
                if f_mid <= remaining:
                    lo = mid
                else:
                    hi = mid
            at = lo if buy else -lo
            used = ZERO
            for pid in active:
                q = quote_to(state[pid], amt, at)
                used += measure(q)
                commit(state[pid], q, at)
            remaining -= used
            rest = _units(remaining)
            if rest > 0:  # the exact rest to the deepest of them
                deepest = max(
                    active,
                    key=lambda pid: (state[pid]["plan"].liquidity, [-ord(c) for c in pid]),
                )
                q = quote_to(state[deepest], rest, target)
                if q.amount_out <= 0 < q.amount_in:
                    stopped = "dust"
                    break
                commit(state[deepest], q, target)
                remaining -= measure(q)

        legs: List[Leg] = []
        last = ZERO
        if size > 0:
            legs.append(
                Leg(
                    FillSource.CLOB,
                    spent,
                    got,
                    fees,
                    base=size,
                    price=book_limit,
                    limit_price=book_limit,
                    makers=visited,
                )
            )
            last = book_limit
        for pid in sorted(state):
            plan = state[pid]["plan"]
            if plan is None or plan.amount_out <= 0:
                continue  # (it only crossed empty ranges: nothing to apply)
            end = (plan.sqrt_price / Q96) ** 2
            legs.append(
                Leg(
                    FillSource.AMM,
                    plan.amount_in,
                    plan.amount_out,
                    plan.fee,
                    base=plan.amount_out if buy else plan.amount_in,
                    price=end,
                    pool_id=pid,
                    plan=plan,
                )
            )
            if last == 0 or (end > last if buy else end < last):
                last = end
        if not legs:
            return None
        token_in, token_out = (quote, base) if buy else (base, quote)
        sources = {leg.source for leg in legs}
        amm_legs = [leg for leg in legs if leg.source == FillSource.AMM]
        book_leg = legs[0] if legs[0].source == FillSource.CLOB else None
        return Route(
            (FillSource.HYBRID if len(sources) > 1 or len(amm_legs) > 1 else next(iter(sources))),
            token_in,
            token_out,
            sum((leg.amount_in for leg in legs), ZERO),
            sum((leg.amount_out for leg in legs), ZERO),
            sum((leg.fee for leg in legs), ZERO),
            pool_id=amm_legs[0].pool_id if amm_legs else None,
            plan=amm_legs[0].plan if len(legs) == 1 and amm_legs else None,
            pair=pair,
            side=OrderSide.BUY if buy else OrderSide.SELL,
            size=sum((leg.base for leg in legs), ZERO),
            limit_price=book_leg.limit_price if book_leg else ZERO,
            makers=book_leg.makers if book_leg else 0,
            parts=legs,
            stopped=stopped or ("self" if self_stop else ""),
            last_price=last,
        )

    def best_route(
        self,
        token_in: str,
        token_out: str,
        amount_in: Decimal,
        sender: str = "",
        pool_id: Optional[str] = None,
        venue: str = "auto",
        max_makers: Optional[int] = None,
    ) -> Optional[Route]:
        """The best exact-input fill of ``token_in`` for ``token_out`` on their pair's combined
        market (``plan_fill``). ``pool_id``: that pool only; ``venue`` "clob": the book only,
        "amm": the pools — resting orders at better prices still fill first (no swap trades
        through a resting order). The book visits no more than ``max_makers`` resting orders."""
        amount_in = Decimal(str(amount_in))
        if token_in == token_out:
            return None
        pair = self._pair_key(token_in, token_out)
        return self.plan_fill(
            pair,
            token_in != pair.split(":", 1)[0],
            amount_in,
            exact_in=True,
            sender=sender,
            max_makers=max_makers,
            pool_ids=[pool_id] if pool_id else None,
            pools=venue != "clob",
        )

    # Back-compat quoting helpers ----------------------------------------------

    def quote_amm(
        self, token_in: str, token_out: str, amount_in: Decimal
    ) -> Optional[Tuple[Decimal, Decimal, str]]:
        routes = self.amm_routes(token_in, token_out, Decimal(str(amount_in)))
        if not routes:
            return None
        best = max(routes, key=lambda r: r.amount_out)
        return best.amount_out, best.fee_total, best.amm()[0]

    def quote_clob(
        self, token_in: str, token_out: str, amount_in: Decimal
    ) -> Optional[Tuple[Decimal, Decimal]]:
        r = self.clob_route(token_in, token_out, Decimal(str(amount_in)))
        return None if r is None else (r.amount_out, r.fee_total)

    # -- Execution ----------------------------------------------------------

    @_pinned
    def apply_leg(
        self, route: Route, leg: Leg, sender: str, now: Optional[int] = None
    ) -> Tuple[List[Trade], Optional[Order], int]:
        """Execute one leg of a route against unchanged state, exactly as quoted: (the order
        book's trades, its immediate-or-cancel order, the resting orders it visited)."""
        if self._paused:
            raise ValueError("Router is paused — emergency mode")
        if leg.source == FillSource.AMM:
            pool = self.pool_manager.get_pool(leg.pool_id or "")
            if pool is None or leg.plan is None:
                raise ValueError(f"Pool {leg.pool_id} not found")
            pool.apply(leg.plan, now)
            return [], None, 0
        pair, side = route.clob()
        book = self._order_books[pair]
        self._clob_sequence += 1
        order = Order(
            id=self._deterministic_clob_order_id(sender, self._clob_sequence),
            owner=sender,
            side=side,
            order_type=OrderType.LIMIT,
            price=leg.limit_price,
            amount=leg.base,
            nonce=0,
            timestamp=0.0,
            tif="ioc",
        )
        budget = MatchBudget(leg.makers)
        trades = book.place_order(order, protocol=True, budget=budget)
        filled = sum((t.amount for t in trades), ZERO)
        if filled != leg.base:
            raise ValueError(f"order book fill {filled} differs from its quote {leg.base}")
        return trades, order, budget.visited

    @_pinned
    def apply_route(self, route: Route, sender: str, now: Optional[int] = None) -> FillResult:
        """Execute a route from ``best_route`` against unchanged state: exactly what it quoted."""
        trades: List[Trade] = []
        order: Optional[Order] = None
        visited = 0
        for leg in route.legs:
            leg_trades, leg_order, leg_visited = self.apply_leg(route, leg, sender, now)
            trades += leg_trades
            order = leg_order or order
            visited += leg_visited
        pool_fee = sum((leg.fee for leg in route.legs if leg.source == FillSource.AMM), ZERO)
        protocol = sum((leg.plan.protocol_fee for leg in route.legs if leg.plan is not None), ZERO)
        return FillResult(
            makers_visited=visited,
            source=route.source,
            amount_in=route.amount_in,
            amount_out=route.amount_out,
            fee_total=route.fee_total if route.source == FillSource.AMM else ZERO,
            **self._fee_parts(pool_fee, protocol),
            price=route.price,
            trades=trades,
            pool_id=route.pool_id,
            order=order,
        )

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
    def _fee_parts(total: Decimal, protocol: Decimal) -> Dict[str, Any]:
        """The fee as the pool splits it (§7.6): LPs' share, and the protocol's divided between
        creator, treasury and validators in proportion 15 : 10 : 5."""
        lp = total - protocol
        protocol_shares = FEE_CREATOR_SHARE + FEE_TREASURY_SHARE + FEE_VALIDATOR_SHARE
        if protocol > 0:
            creator = (protocol * FEE_CREATOR_SHARE / protocol_shares).quantize(
                Decimal("1e-18"), rounding=ROUND_DOWN
            )
            treasury = (protocol * FEE_TREASURY_SHARE / protocol_shares).quantize(
                Decimal("1e-18"), rounding=ROUND_DOWN
            )
        else:
            creator = treasury = ZERO
        return {
            "fee_lp": lp,
            "fee_creator": creator,
            "fee_treasury": treasury,
            "fee_validator": protocol - creator - treasury,
        }

    @staticmethod
    def _split_fees(total: Decimal) -> Dict[str, Decimal]:
        """Distribute a fee per §7.6 (70 / 15 / 10 / 5) — reporting helper."""
        lp = (total * FEE_LP_SHARE).quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)
        creator = (total * FEE_CREATOR_SHARE).quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)
        treasury = (total * FEE_TREASURY_SHARE).quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)
        validator = total - lp - creator - treasury
        return {
            "fee_lp": lp,
            "fee_creator": creator,
            "fee_treasury": treasury,
            "fee_validator": validator,
        }

    @staticmethod
    def _pair_key(token_a: str, token_b: str) -> str:
        a, b = (token_a, token_b) if token_a < token_b else (token_b, token_a)
        return f"{a}:{b}"

    @staticmethod
    def _deterministic_clob_order_id(sender: str, seq: int) -> str:
        """Deterministic order ID for order-book fills via the router."""
        raw = f"router:{sender}:{seq}".encode()
        return hashlib.blake2b(raw, digest_size=8).hexdigest()
