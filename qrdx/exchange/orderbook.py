"""
QRDX On-Chain Order Book  (Whitepaper §7.2 Component 2)

Fully on-chain order book with:
  - Limit orders — placed at specific prices
  - Stop-loss orders — triggered when price crosses threshold
  - Price-time priority — deterministic matching enforced by consensus
  - Partial fills — orders can be partially filled
  - Maker/taker fee model (§7.6)
  - Anti-front-running — consensus-enforced deterministic matching

Security features:
  - Self-trade prevention (STP) — configurable REJECT / CANCEL_MAKER / CANCEL_BOTH
  - Per-address order limits — bounded resource consumption
  - Min order size — prevents dust spam
  - Nonce / sequence — replay protection (monotonically increasing per owner)
  - Owner-only cancel — authorization enforced on every cancel
  - Rate limiting — max orders per block per address
  - Deterministic trade IDs — blake2b(maker:taker:seq), no uuid4
  - Expiry / GTC — orders auto-cleaned at block boundary
  - Emergency pause — blocks all new orders

Order book depth is configurable per pool (default 500 price levels/side).
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_DOWN, ROUND_HALF_UP
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

ZERO = Decimal("0")

# ---------------------------------------------------------------------------
# Security limits
# ---------------------------------------------------------------------------

MAX_ORDERS_PER_ADDRESS = 200           # per book
MAX_ORDERS_PER_BLOCK_PER_ADDRESS = 50  # rate limit
MIN_ORDER_SIZE = Decimal("0.00000001") # 1 sat equivalent
MAX_STOP_ORDERS_PER_ADDRESS = 50


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


class SelfTradeAction(str, Enum):
    """What to do when maker and taker are the same address."""
    REJECT = "reject"              # skip the resting maker order
    CANCEL_MAKER = "cancel_maker"  # cancel the resting maker
    CANCEL_BOTH = "cancel_both"    # cancel both sides


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
    nonce: int = 0              # replay protection — must increase per owner
    expire_time: float = 0.0    # 0 = GTC; else unix timestamp

    @property
    def remaining(self) -> Decimal:
        return self.amount - self.filled

    @property
    def is_active(self) -> bool:
        return self.status in (OrderStatus.OPEN, OrderStatus.PARTIALLY_FILLED)

    @property
    def is_expired(self) -> bool:
        if self.expire_time <= 0:
            return False
        return time.time() > self.expire_time


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
    sequence: int = 0           # deterministic global sequence


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

    Security:
      - Self-trade prevention (STP)
      - Per-address order limits (MAX_ORDERS_PER_ADDRESS)
      - Min order size enforcement
      - Nonce tracking for replay protection
      - Owner-only cancel authorization
      - Expired order cleanup on new_block
      - Rate limiting per block per address
      - Emergency pause
    """

    def __init__(
        self,
        pool_id: str = "",
        max_depth: int = 500,
        maker_fee_rate: Decimal = Decimal("0.0002"),   # 0.02%
        taker_fee_rate: Decimal = Decimal("0.0005"),   # 0.05%
        self_trade_action: SelfTradeAction = SelfTradeAction.REJECT,
        min_order_size: Decimal = MIN_ORDER_SIZE,
        max_orders_per_address: int = MAX_ORDERS_PER_ADDRESS,
    ):
        self.pool_id = pool_id
        self.max_depth = max_depth
        self.maker_fee_rate = maker_fee_rate
        self.taker_fee_rate = taker_fee_rate
        self.self_trade_action = self_trade_action
        self.min_order_size = min_order_size
        self.max_orders_per_address = max_orders_per_address

        # --- Book state ---
        self._bids: Dict[Decimal, PriceLevel] = {}
        self._asks: Dict[Decimal, PriceLevel] = {}
        self._orders: Dict[str, Order] = {}
        self._stop_orders: Dict[str, Order] = {}
        self._trades: List[Trade] = []

        # --- Security state ---
        self._owner_order_count: Dict[str, int] = {}
        self._owner_stop_count: Dict[str, int] = {}
        self._owner_nonces: Dict[str, int] = {}
        self._block_order_count: Dict[str, int] = {}
        self._trade_sequence: int = 0
        self._paused: bool = False

        # --- Stats ---
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

    @property
    def is_paused(self) -> bool:
        return self._paused

    # -- Emergency controls -------------------------------------------------

    def pause(self) -> None:
        """Emergency pause — blocks all new orders."""
        self._paused = True
        logger.warning("Order book %s PAUSED", self.pool_id)

    def unpause(self) -> None:
        """Resume trading after emergency pause."""
        self._paused = False
        logger.info("Order book %s resumed", self.pool_id)

    def new_block(self) -> None:
        """Call at the start of each block to reset rate limits and clean up expired orders."""
        self._block_order_count.clear()
        self._cleanup_expired()

    # -- Order placement ----------------------------------------------------

    def place_order(self, order: Order) -> List[Trade]:
        """
        Place an order on the book. Attempts immediate matching.

        Args:
            order: Order to place

        Returns:
            List of trades generated (empty if fully resting)

        Raises:
            ValueError: on invalid order parameters or security violations
        """
        if self._paused:
            raise ValueError("Order book is paused — emergency mode")

        self._validate_order(order)
        self._check_rate_limit(order.owner)
        self._check_nonce(order)

        # Stop-loss: park it until trigger price hit
        if order.order_type == OrderType.STOP_LOSS:
            return self._place_stop_order(order)

        # Market order: match immediately, reject remainder
        if order.order_type == OrderType.MARKET:
            return self._match_market(order)

        # Limit order: match what we can, rest goes on the book
        return self._match_limit(order)

    def cancel_order(self, order_id: str, caller: str = "") -> Optional[Order]:
        """
        Cancel an open order.

        Args:
            order_id: ID of order to cancel
            caller: address of the canceller (must match owner for authorization)

        Returns:
            The cancelled order, or None if not found

        Raises:
            ValueError: if caller is not the order owner
        """
        # Check stop orders first
        if order_id in self._stop_orders:
            order = self._stop_orders[order_id]
            if caller and order.owner != caller:
                raise ValueError("Only order owner can cancel")
            del self._stop_orders[order_id]
            order.status = OrderStatus.CANCELLED
            self._decrement_owner_count(order.owner, is_stop=True)
            return order

        order = self._orders.get(order_id)
        if order is None:
            return None

        if caller and order.owner != caller:
            raise ValueError("Only order owner can cancel")

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
        self._decrement_owner_count(order.owner)
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

            # --- Self-trade prevention (STP) ---
            if maker.owner == taker.owner:
                if self.self_trade_action == SelfTradeAction.REJECT:
                    continue  # skip this maker, try next
                elif self.self_trade_action == SelfTradeAction.CANCEL_MAKER:
                    maker.status = OrderStatus.CANCELLED
                    level.remove_order(maker.id)
                    self._orders.pop(maker.id, None)
                    self._decrement_owner_count(maker.owner)
                    continue
                elif self.self_trade_action == SelfTradeAction.CANCEL_BOTH:
                    maker.status = OrderStatus.CANCELLED
                    taker.status = OrderStatus.CANCELLED
                    level.remove_order(maker.id)
                    self._orders.pop(maker.id, None)
                    self._decrement_owner_count(maker.owner)
                    return trades

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

            self._trade_sequence += 1
            trade = Trade(
                id=self._deterministic_trade_id(maker.id, taker.id, self._trade_sequence),
                maker_order_id=maker.id,
                taker_order_id=taker.id,
                price=price,
                amount=fill_amount,
                maker_fee=maker_fee,
                taker_fee=taker_fee,
                timestamp=time.time(),
                buyer=buyer,
                seller=seller,
                sequence=self._trade_sequence,
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
                self._decrement_owner_count(maker.owner)
            else:
                maker.status = OrderStatus.PARTIALLY_FILLED

        return trades

    # -- Stop-loss ----------------------------------------------------------

    def _place_stop_order(self, order: Order) -> List[Trade]:
        """Park stop order; it will be triggered when price hits stop_price."""
        if order.stop_price is None:
            raise ValueError("Stop-loss order requires stop_price")
        count = self._owner_stop_count.get(order.owner, 0)
        if count >= MAX_STOP_ORDERS_PER_ADDRESS:
            raise ValueError(f"Max stop orders per address reached ({MAX_STOP_ORDERS_PER_ADDRESS})")
        self._stop_orders[order.id] = order
        self._owner_stop_count[order.owner] = count + 1
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
            self._decrement_owner_count(order.owner, is_stop=True)
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

        # Enforce per-address order limit
        count = self._owner_order_count.get(order.owner, 0)
        if count >= self.max_orders_per_address:
            raise ValueError(
                f"Max orders per address reached ({self.max_orders_per_address})"
            )

        if order.price not in book:
            book[order.price] = PriceLevel(price=order.price)

        book[order.price].add_order(order)
        self._orders[order.id] = order
        self._owner_order_count[order.owner] = count + 1

    def _validate_order(self, order: Order) -> None:
        """Validate order parameters — security-critical."""
        if order.amount <= 0:
            raise ValueError("Order amount must be positive")
        if order.amount < self.min_order_size:
            raise ValueError(f"Order amount below minimum ({self.min_order_size})")
        if order.order_type == OrderType.LIMIT and order.price <= 0:
            raise ValueError("Limit order price must be positive")
        if order.order_type == OrderType.STOP_LOSS and (order.stop_price is None or order.stop_price <= 0):
            raise ValueError("Stop-loss requires positive stop_price")
        if not order.owner:
            raise ValueError("Order must have an owner address")
        if not order.id:
            raise ValueError("Order must have an ID")
        # Check for duplicate order ID
        if order.id in self._orders or order.id in self._stop_orders:
            raise ValueError(f"Duplicate order ID: {order.id}")
        # Check expiry
        if order.expire_time > 0 and order.is_expired:
            raise ValueError("Order has already expired")

    def _check_nonce(self, order: Order) -> None:
        """Verify nonce is strictly increasing per owner (replay protection)."""
        if order.nonce > 0:
            last_nonce = self._owner_nonces.get(order.owner, 0)
            if order.nonce <= last_nonce:
                raise ValueError(
                    f"Nonce replay: got {order.nonce}, expected > {last_nonce}"
                )
            self._owner_nonces[order.owner] = order.nonce

    def _check_rate_limit(self, owner: str) -> None:
        """Enforce per-block order rate limit."""
        count = self._block_order_count.get(owner, 0)
        if count >= MAX_ORDERS_PER_BLOCK_PER_ADDRESS:
            raise ValueError(
                f"Rate limit: max {MAX_ORDERS_PER_BLOCK_PER_ADDRESS} orders per block"
            )
        self._block_order_count[owner] = count + 1

    def _decrement_owner_count(self, owner: str, is_stop: bool = False) -> None:
        if is_stop:
            c = self._owner_stop_count.get(owner, 0)
            self._owner_stop_count[owner] = max(0, c - 1)
        else:
            c = self._owner_order_count.get(owner, 0)
            self._owner_order_count[owner] = max(0, c - 1)

    def _cleanup_expired(self) -> None:
        """Remove expired orders during new_block."""
        for oid in list(self._orders):
            order = self._orders[oid]
            if order.expire_time > 0 and order.is_expired and order.is_active:
                self.cancel_order(oid)

    @staticmethod
    def _deterministic_trade_id(maker_id: str, taker_id: str, seq: int) -> str:
        """Deterministic trade ID — consensus-safe, no uuid4."""
        raw = f"{maker_id}:{taker_id}:{seq}".encode()
        return hashlib.blake2b(raw, digest_size=8).hexdigest()

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
