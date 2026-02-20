"""
QRDX On-Chain Order Book  (Whitepaper §7.2 Component 2)

Fully on-chain order book with:
  - Limit orders — placed at specific prices
  - Stop-loss orders — triggered when price crosses threshold
  - Price-time priority — deterministic matching enforced by consensus
  - Partial fills — orders can be partially filled
  - Maker/taker fee model (§7.6)
  - Anti-front-running — consensus-enforced deterministic matching

Order book depth is configurable per pool (default 500 price levels/side).
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_DOWN, ROUND_HALF_UP
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

ZERO = Decimal("0")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class OrderSide(str, Enum):
    BUY = "buy"
    SELL = "sell"


class OrderType(str, Enum):
    LIMIT = "limit"
    MARKET = "market"
    STOP_LOSS = "stop_loss"


class OrderStatus(str, Enum):
    OPEN = "open"
    PARTIALLY_FILLED = "partially_filled"
    FILLED = "filled"
    CANCELLED = "cancelled"
    TRIGGERED = "triggered"  # stop-loss converted to market


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Order:
    """A single order on the book."""
    id: str
    owner: str                  # PQ address
    side: OrderSide
    order_type: OrderType
    price: Decimal              # limit price (0 for market)
    amount: Decimal             # original size
    filled: Decimal = ZERO      # how much has been filled
    status: OrderStatus = OrderStatus.OPEN
    timestamp: float = field(default_factory=time.time)
    stop_price: Optional[Decimal] = None  # for stop-loss orders
    signature: bytes = b""      # Dilithium signature

    @property
    def remaining(self) -> Decimal:
        return self.amount - self.filled

    @property
    def is_active(self) -> bool:
        return self.status in (OrderStatus.OPEN, OrderStatus.PARTIALLY_FILLED)


@dataclass
class Trade:
    """A completed trade between two orders."""
    id: str
    maker_order_id: str
    taker_order_id: str
    price: Decimal
    amount: Decimal
    maker_fee: Decimal
    taker_fee: Decimal
    timestamp: float
    buyer: str
    seller: str


# ---------------------------------------------------------------------------
# Price Level
# ---------------------------------------------------------------------------

@dataclass
class PriceLevel:
    """Orders at a single price point, in time-priority order."""
    price: Decimal
    orders: List[Order] = field(default_factory=list)

    @property
    def total_amount(self) -> Decimal:
        return sum(o.remaining for o in self.orders if o.is_active)

    def add_order(self, order: Order) -> None:
        self.orders.append(order)

    def remove_order(self, order_id: str) -> Optional[Order]:
        for i, o in enumerate(self.orders):
            if o.id == order_id:
                return self.orders.pop(i)
        return None


# ---------------------------------------------------------------------------
# Order Book
# ---------------------------------------------------------------------------

class OrderBook:
    """
    On-chain order book with price-time priority matching.

    Supports limit, market, and stop-loss orders.
    Matching is deterministic and consensus-enforced.
    """

    def __init__(
        self,
        pool_id: str = "",
        max_depth: int = 500,
        maker_fee_rate: Decimal = Decimal("0.0002"),   # 0.02%
        taker_fee_rate: Decimal = Decimal("0.0005"),   # 0.05%
    ):
        self.pool_id = pool_id
        self.max_depth = max_depth
        self.maker_fee_rate = maker_fee_rate
        self.taker_fee_rate = taker_fee_rate

        # Sorted price levels: bids (descending), asks (ascending)
        self._bids: Dict[Decimal, PriceLevel] = {}  # buy side
        self._asks: Dict[Decimal, PriceLevel] = {}   # sell side

        # Quick order lookup
        self._orders: Dict[str, Order] = {}

        # Stop-loss orders (not on the book until triggered)
        self._stop_orders: Dict[str, Order] = {}

        # Trade history
        self._trades: List[Trade] = []

        # Cumulative stats
        self.total_volume: Decimal = ZERO
        self.total_trades: int = 0

    # -- Properties ---------------------------------------------------------

    @property
    def best_bid(self) -> Optional[Decimal]:
        active = [p for p, lvl in self._bids.items() if lvl.total_amount > 0]
        return max(active) if active else None

    @property
    def best_ask(self) -> Optional[Decimal]:
        active = [p for p, lvl in self._asks.items() if lvl.total_amount > 0]
        return min(active) if active else None

    @property
    def spread(self) -> Optional[Decimal]:
        bb, ba = self.best_bid, self.best_ask
        if bb is not None and ba is not None:
            return ba - bb
        return None

    @property
    def mid_price(self) -> Optional[Decimal]:
        bb, ba = self.best_bid, self.best_ask
        if bb is not None and ba is not None:
            return (ba + bb) / 2
        return None

    @property
    def bid_depth(self) -> int:
        return len([p for p, lvl in self._bids.items() if lvl.total_amount > 0])

    @property
    def ask_depth(self) -> int:
        return len([p for p, lvl in self._asks.items() if lvl.total_amount > 0])

    # -- Order placement ----------------------------------------------------

    def place_order(self, order: Order) -> List[Trade]:
        """
        Place an order on the book. Attempts immediate matching.

        Args:
            order: Order to place

        Returns:
            List of trades generated (empty if fully resting)

        Raises:
            ValueError: on invalid order parameters
        """
        self._validate_order(order)

        # Stop-loss: park it until trigger price hit
        if order.order_type == OrderType.STOP_LOSS:
            return self._place_stop_order(order)

        # Market order: match immediately, reject remainder
        if order.order_type == OrderType.MARKET:
            return self._match_market(order)

        # Limit order: match what we can, rest goes on the book
        return self._match_limit(order)

    def cancel_order(self, order_id: str) -> Optional[Order]:
        """
        Cancel an open order.

        Returns:
            The cancelled order, or None if not found
        """
        # Check stop orders
        if order_id in self._stop_orders:
            order = self._stop_orders.pop(order_id)
            order.status = OrderStatus.CANCELLED
            return order

        order = self._orders.get(order_id)
        if order is None:
            return None

        if not order.is_active:
            return None

        order.status = OrderStatus.CANCELLED

        # Remove from price level
        book = self._bids if order.side == OrderSide.BUY else self._asks
        level = book.get(order.price)
        if level:
            level.remove_order(order_id)
            if level.total_amount == 0:
                del book[order.price]

        del self._orders[order_id]
        return order

    # -- Matching engine ----------------------------------------------------

    def _match_market(self, taker: Order) -> List[Trade]:
        """Match a market order against the book."""
        trades = []
        opposite = self._asks if taker.side == OrderSide.BUY else self._bids
        prices = sorted(opposite.keys()) if taker.side == OrderSide.BUY else sorted(opposite.keys(), reverse=True)

        for price in list(prices):
            if taker.remaining <= 0:
                break
            level = opposite[price]
            trades.extend(self._match_at_level(taker, level, price))
            if level.total_amount == 0:
                del opposite[price]

        # Market orders: remaining is discarded (no resting)
        if taker.remaining > 0:
            taker.status = OrderStatus.FILLED if taker.filled > 0 else OrderStatus.CANCELLED
        else:
            taker.status = OrderStatus.FILLED

        self._check_stop_triggers()
        return trades

    def _match_limit(self, taker: Order) -> List[Trade]:
        """Match a limit order against the book, rest on the book."""
        trades = []
        opposite = self._asks if taker.side == OrderSide.BUY else self._bids

        if taker.side == OrderSide.BUY:
            matchable_prices = sorted([p for p in opposite if p <= taker.price])
        else:
            matchable_prices = sorted([p for p in opposite if p >= taker.price], reverse=True)

        for price in list(matchable_prices):
            if taker.remaining <= 0:
                break
            level = opposite[price]
            trades.extend(self._match_at_level(taker, level, price))
            if level.total_amount == 0:
                del opposite[price]

        # Rest on the book if unfilled
        if taker.remaining > 0:
            taker.status = OrderStatus.OPEN if taker.filled == 0 else OrderStatus.PARTIALLY_FILLED
            self._add_to_book(taker)
        else:
            taker.status = OrderStatus.FILLED

        self._check_stop_triggers()
        return trades

    def _match_at_level(self, taker: Order, level: PriceLevel, price: Decimal) -> List[Trade]:
        """Match taker against all makers at a price level (time priority)."""
        trades = []
        for maker in list(level.orders):
            if taker.remaining <= 0:
                break
            if not maker.is_active:
                continue

            fill_amount = min(taker.remaining, maker.remaining)

            maker_fee = (fill_amount * price * self.maker_fee_rate).quantize(
                Decimal("0.00000001"), rounding=ROUND_HALF_UP
            )
            taker_fee = (fill_amount * price * self.taker_fee_rate).quantize(
                Decimal("0.00000001"), rounding=ROUND_HALF_UP
            )

            # Determine buyer/seller
            buyer = taker.owner if taker.side == OrderSide.BUY else maker.owner
            seller = maker.owner if taker.side == OrderSide.BUY else taker.owner

            trade = Trade(
                id=uuid.uuid4().hex[:16],
                maker_order_id=maker.id,
                taker_order_id=taker.id,
                price=price,
                amount=fill_amount,
                maker_fee=maker_fee,
                taker_fee=taker_fee,
                timestamp=time.time(),
                buyer=buyer,
                seller=seller,
            )
            trades.append(trade)
            self._trades.append(trade)
            self.total_volume += fill_amount * price
            self.total_trades += 1

            maker.filled += fill_amount
            taker.filled += fill_amount

            if maker.remaining <= 0:
                maker.status = OrderStatus.FILLED
                level.remove_order(maker.id)
                self._orders.pop(maker.id, None)
            else:
                maker.status = OrderStatus.PARTIALLY_FILLED

        return trades

    # -- Stop-loss ----------------------------------------------------------

    def _place_stop_order(self, order: Order) -> List[Trade]:
        """Park stop order; it will be triggered when price hits stop_price."""
        if order.stop_price is None:
            raise ValueError("Stop-loss order requires stop_price")
        self._stop_orders[order.id] = order
        return []

    def _check_stop_triggers(self) -> None:
        """Check if any stop-loss orders should trigger."""
        last_price = self._trades[-1].price if self._trades else None
        if last_price is None:
            return

        triggered = []
        for oid, order in list(self._stop_orders.items()):
            if order.stop_price is None:
                continue
            # Buy stop: triggers when price >= stop_price
            if order.side == OrderSide.BUY and last_price >= order.stop_price:
                triggered.append(oid)
            # Sell stop: triggers when price <= stop_price
            elif order.side == OrderSide.SELL and last_price <= order.stop_price:
                triggered.append(oid)

        for oid in triggered:
            order = self._stop_orders.pop(oid)
            order.order_type = OrderType.MARKET
            order.status = OrderStatus.TRIGGERED
            self._match_market(order)

    # -- Book management ----------------------------------------------------

    def _add_to_book(self, order: Order) -> None:
        """Add an order to the book at its price level."""
        book = self._bids if order.side == OrderSide.BUY else self._asks

        # Enforce max depth
        if order.price not in book and len(book) >= self.max_depth:
            raise ValueError(
                f"Order book depth limit reached ({self.max_depth} levels)"
            )

        if order.price not in book:
            book[order.price] = PriceLevel(price=order.price)

        book[order.price].add_order(order)
        self._orders[order.id] = order

    def _validate_order(self, order: Order) -> None:
        """Validate order parameters."""
        if order.amount <= 0:
            raise ValueError("Order amount must be positive")
        if order.order_type == OrderType.LIMIT and order.price <= 0:
            raise ValueError("Limit order price must be positive")
        if order.order_type == OrderType.STOP_LOSS and (order.stop_price is None or order.stop_price <= 0):
            raise ValueError("Stop-loss requires positive stop_price")
        if not order.owner:
            raise ValueError("Order must have an owner address")
        if not order.id:
            raise ValueError("Order must have an ID")

    # -- Query --------------------------------------------------------------

    def get_order(self, order_id: str) -> Optional[Order]:
        order = self._orders.get(order_id)
        if order is None:
            order = self._stop_orders.get(order_id)
        return order

    def get_bids(self, depth: int = 10) -> List[Tuple[Decimal, Decimal]]:
        """Top N bid levels as (price, total_amount)."""
        active = [(p, lvl.total_amount) for p, lvl in self._bids.items() if lvl.total_amount > 0]
        active.sort(key=lambda x: x[0], reverse=True)
        return active[:depth]

    def get_asks(self, depth: int = 10) -> List[Tuple[Decimal, Decimal]]:
        """Top N ask levels as (price, total_amount)."""
        active = [(p, lvl.total_amount) for p, lvl in self._asks.items() if lvl.total_amount > 0]
        active.sort(key=lambda x: x[0])
        return active[:depth]

    def get_recent_trades(self, count: int = 50) -> List[Trade]:
        return self._trades[-count:]

    def get_open_orders(self, owner: Optional[str] = None) -> List[Order]:
        """All open orders, optionally filtered by owner."""
        orders = [o for o in self._orders.values() if o.is_active]
        if owner:
            orders = [o for o in orders if o.owner == owner]
        return orders
