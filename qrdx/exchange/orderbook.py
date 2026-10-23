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
  - Expiry / GTC — orders auto-cleaned at block boundary, judged by BLOCK time
  - Emergency pause — blocks all new orders

Order book depth is configurable per pool (default 500 price levels/side).

Determinism: matching runs in a pinned Decimal context (never the caller's), the only clock is
the block time handed to ``new_block``, and ``state_digest`` commits every consensus-relevant
field. The trade history kept for display is bounded and never consensus state.
"""

from __future__ import annotations

import copy
import functools
import hashlib
import itertools
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, ROUND_HALF_UP, Context, Decimal, localcontext
from enum import Enum
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from ..crypto import lthash
from . import undo
from .commitment import CommittedDict, _apply, _vector, as_committed_dict, encode_value

logger = logging.getLogger(__name__)

ZERO = Decimal("0")

# ---------------------------------------------------------------------------
# Security limits
# ---------------------------------------------------------------------------

MAX_ORDERS_PER_ADDRESS = 200  # per book
MAX_ORDERS_PER_BLOCK_PER_ADDRESS = 50  # rate limit
MIN_ORDER_SIZE = Decimal("0.00000001")  # 1 sat equivalent
MAX_STOP_ORDERS_PER_ADDRESS = 50
MAX_RECENT_TRADES = 1000  # display history per book — bounded, never consensus

# Every book computation runs in this context, whatever the caller's: a result must not depend
# on the precision of the thread or task that happens to call in.
_CTX = Context(prec=78, rounding=ROUND_HALF_EVEN)


def _pinned(method):
    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        with localcontext(_CTX):
            return method(*args, **kwargs)

    return wrapper


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

    REJECT = "reject"  # skip the resting maker order (the taker may then rest
    # ACROSS its own order: a crossed book — not for consensus)
    CANCEL_MAKER = "cancel_maker"  # cancel the resting maker
    CANCEL_BOTH = "cancel_both"  # cancel both sides
    CANCEL_TAKER = "cancel_taker"  # stop matching and cancel the taker's remainder; fills
    # already made stand, resting orders are untouched. The
    # consensus books use this: the book can never cross.


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class Order:
    """A single order on the book."""

    id: str
    owner: str  # PQ address
    side: OrderSide
    order_type: OrderType
    price: Decimal  # limit price (0 for market)
    amount: Decimal  # original size
    filled: Decimal = ZERO  # how much has been filled
    status: OrderStatus = OrderStatus.OPEN
    timestamp: float = field(default_factory=time.time)
    stop_price: Optional[Decimal] = None  # for stop-loss orders
    signature: bytes = b""  # Dilithium signature
    nonce: int = 0  # replay protection — must increase per owner
    expire_time: float = 0.0  # 0 = GTC; else unix timestamp
    # Time in force: "gtc" rests what it does not fill; "ioc" cancels it; "fok" fills whole or
    # not at all (the operation fails); "alo" (post-only) never takes — refused if it would match.
    tif: str = "gtc"
    # Hidden: matches like any order but shows nothing in the book's depth. Iceberg
    # (``display_size``): shows a slice of ``display_size`` at a time (``shown`` is what is left
    # of it); the rest is hidden. Neither is private: the order's parameters are on the chain.
    hidden: bool = False
    display_size: Decimal = ZERO
    shown: Decimal = ZERO

    @property
    def remaining(self) -> Decimal:
        return self.amount - self.filled

    @property
    def is_iceberg(self) -> bool:
        return self.display_size > 0

    @property
    def visible(self) -> Decimal:
        """What the order shows: nothing if hidden, the slice left if an iceberg."""
        if self.hidden:
            return ZERO
        if self.is_iceberg:
            return min(self.shown, self.remaining)
        return self.remaining

    @property
    def reserve(self) -> Decimal:
        """What it holds back: all of a hidden order, an iceberg's undisplayed rest."""
        return self.remaining - self.visible

    @property
    def is_active(self) -> bool:
        return self.status in (OrderStatus.OPEN, OrderStatus.PARTIALLY_FILLED)

    def expired(self, now: Optional[float]) -> bool:
        """Past its expiry at block time ``now`` (None — no block yet — expires nothing)."""
        return self.expire_time > 0 and now is not None and now > self.expire_time

    def __deepcopy__(self, memo: Dict[int, Any]) -> "Order":
        # Every field is an immutable value: a field-for-field copy is a deep one. Registered in
        # ``memo`` so an order reached through its price level and through the book's index is
        # copied once (undo scopes rely on it).
        new = Order.__new__(Order)
        new.__dict__.update(self.__dict__)
        memo[id(self)] = new
        return new


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
    sequence: int = 0  # deterministic global sequence


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
        """Everything resting at the level, hidden quantities included."""
        return sum((o.remaining for o in self.orders if o.is_active), ZERO)

    @property
    def visible_amount(self) -> Decimal:
        """What the level shows: hidden orders and icebergs' reserves left out."""
        return sum((o.visible for o in self.orders if o.is_active), ZERO)

    def add_order(self, order: Order) -> None:
        self.orders.append(order)

    def remove_order(self, order_id: str) -> Optional[Order]:
        for i, o in enumerate(self.orders):
            if o.id == order_id:
                return self.orders.pop(i)
        return None

    def __deepcopy__(self, memo: Dict[int, Any]) -> "PriceLevel":
        new = PriceLevel.__new__(PriceLevel)
        new.__dict__.update(self.__dict__)
        new.orders = [copy.deepcopy(o, memo) for o in self.orders]
        memo[id(self)] = new
        return new


# ---------------------------------------------------------------------------
# Order Book
# ---------------------------------------------------------------------------


class MatchBudget:
    """How many resting orders one placement may visit — filled, skipped or cancelled alike,
    since each costs the matching engine the same — paid for by its transaction's gas
    (``EXCHANGE_GAS_PER_MAKER``, docs/BLOCK_LIMITS.md). When it runs out the order stops
    matching and its remainder is cancelled, never rested (it would cross the book). An order
    used to sweep any number of makers for its base gas: 1,600 makers took ~38 ms."""

    __slots__ = ("left", "visited", "exhausted")

    def __init__(self, makers: int):
        self.left = max(0, int(makers))
        self.visited = 0
        self.exhausted = False

    def take(self) -> bool:
        """One more maker visited — False (and exhausted) if none is left."""
        if self.left <= 0:
            self.exhausted = True
            return False
        self.left -= 1
        self.visited += 1
        return True


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

    # Set by the perps clearinghouse for the length of one match: called as
    # ``maker_guard(maker, amount)`` before a maker fills; False cancels the maker (it no longer
    # qualifies for the fill) and matching moves on. Never left set (the book is pickled).
    maker_guard: Optional[Callable[[Order, Decimal], bool]] = None

    def __init__(
        self,
        pool_id: str = "",
        max_depth: int = 500,
        maker_fee_rate: Decimal = Decimal("0.0002"),  # 0.02%
        taker_fee_rate: Decimal = Decimal("0.0005"),  # 0.05%
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
        self._trades: Deque[Trade] = deque(maxlen=MAX_RECENT_TRADES)
        self.last_price: Optional[Decimal] = None  # the stop-order trigger (consensus)
        self._now: Optional[float] = None  # the current block's time

        # --- Security state ---
        self._owner_order_count: Dict[str, int] = {}
        self._owner_stop_count: Dict[str, int] = {}
        # Committed per owner (it grows with every owner who ever traded on the book).
        self._owner_nonces: Dict[str, int] = as_committed_dict(
            {}, "book.nonces", encode_value, mutable=False
        )
        self._block_order_count: Dict[str, int] = {}
        self._trade_sequence: int = 0
        self._paused: bool = False

        # --- Stats ---
        self.total_volume: Decimal = ZERO
        self.total_trades: int = 0

        # --- Commitment cache: state_digest() as of _digest_version; every mutating entry
        # point bumps _version (qrdx/exchange/commitment.py) ---
        self._version: int = 0
        self._digest: Optional[bytes] = None
        self._digest_version: int = -1
        # Per price level (qrdx/exchange/commitment.py): each level's digest, their LtHash, and
        # the levels touched since — so a block costs the levels it changed, not the book.
        self._level_digests: Optional[Dict[Tuple[str, Decimal], bytes]] = None
        self._level_acc: bytes = lthash.ZERO
        self._dirty_levels: set = set()
        self._has_expiring = False  # an order with an expiry was ever added

    # -- Properties ---------------------------------------------------------

    @property
    def best_bid(self) -> Optional[Decimal]:
        return next((p for p, _amount in self.iter_levels(bids=True)), None)

    @property
    def best_ask(self) -> Optional[Decimal]:
        return next((p for p, _amount in self.iter_levels(bids=False)), None)

    def iter_levels(self, bids: bool):
        """(price, displayed amount) of each level that shows something, best first, lazily: a
        reader that needs the top of the book stops there (every block's tick reads it; summing
        every level's orders cost 4 ms at 4,000 resting orders). Hidden orders and icebergs'
        reserves are left out — the depth everyone sees, and what the mark and funding prices
        read."""
        levels = self._bids if bids else self._asks
        for price in sorted(levels, reverse=bids):
            with localcontext(_CTX):  # a generator: pinned per step, whoever iterates it
                amount = levels[price].visible_amount
            if amount > 0:
                yield price, amount

    @staticmethod
    def fill_queue(level: "PriceLevel") -> List[Tuple["Order", Decimal]]:
        """The level's resting orders in matching priority, with what each offers: first every
        displayed quantity in time order (an iceberg's current slice), then every hidden one in
        time order (an iceberg's reserve, a hidden order). Read only — the router quotes with
        it exactly as ``_match_at_level`` fills."""
        orders = [o for o in level.orders if o.is_active]
        queue = [(o, o.visible) for o in orders if o.visible > 0]
        queue += [(o, o.reserve) for o in orders if o.reserve > 0]
        return queue

    @property
    def spread(self) -> Optional[Decimal]:
        bb, ba = self.best_bid, self.best_ask
        if bb is not None and ba is not None:
            return ba - bb
        return None

    @property
    @_pinned
    def mid_price(self) -> Optional[Decimal]:
        bb, ba = self.best_bid, self.best_ask
        if bb is not None and ba is not None:
            return (ba + bb) / 2
        return None

    @property
    def bid_depth(self) -> int:
        return len([p for p, lvl in self._bids.items() if lvl.visible_amount > 0])

    @property
    def ask_depth(self) -> int:
        return len([p for p, lvl in self._asks.items() if lvl.visible_amount > 0])

    @property
    def is_paused(self) -> bool:
        return self._paused

    # -- Emergency controls -------------------------------------------------

    def pause(self) -> None:
        """Emergency pause — blocks all new orders."""
        self._keep_scalars()
        self._version += 1
        self._paused = True
        logger.warning("Order book %s PAUSED", self.pool_id)

    def unpause(self) -> None:
        """Resume trading after emergency pause."""
        self._keep_scalars()
        self._version += 1
        self._paused = False
        logger.info("Order book %s resumed", self.pool_id)

    @_pinned
    def new_block(self, now: Optional[float] = None) -> None:
        """Start a block: reset the per-block rate limits and drop the orders that have expired
        by ``now`` — the block's timestamp, never the wall clock."""
        self._keep_scalars()
        self._block_order_count.clear()
        if now is not None:
            self._now = float(now)
        self._cleanup_expired()

    # -- Atomicity and commitment -------------------------------------------

    def snapshot(self) -> Any:
        """Everything but the display history, which is append-only and copied shallowly."""
        state = {k: v for k, v in self.__dict__.items() if k != "_trades"}
        return copy.deepcopy(state), list(self._trades)

    def restore(self, snap: Any) -> None:
        state, trades = snap
        self.__dict__.clear()
        self.__dict__.update(state)
        self._trades = deque(trades, maxlen=MAX_RECENT_TRADES)
        self._level_digests = None  # recomputed in full
        self._version += 1

    # -- Undo (qrdx/exchange/undo.py): inside an atomic scope, the book records what it was
    #    the first time the scope touches each part — never a copy of the whole book.

    _SCALARS = (
        "_trade_sequence",
        "last_price",
        "total_volume",
        "total_trades",
        "_paused",
        "_now",
        "_has_expiring",
        "_block_order_count",
        "_trades",
    )

    def _keep_scalars(self) -> None:
        """The book's own fields and its display history, once per scope (cheap: no orders)."""
        scope = undo.active()
        if scope is None or not scope.first(self, "book"):
            return
        saved = {
            "_trade_sequence": self._trade_sequence,
            "last_price": self.last_price,
            "total_volume": self.total_volume,
            "total_trades": self.total_trades,
            "_paused": self._paused,
            "_now": self._now,
            "_has_expiring": self.__dict__.get("_has_expiring", True),
            "_block_order_count": dict(self._block_order_count),
            "_trades": list(self._trades),
        }

        def restore() -> None:
            for name, value in saved.items():
                if name == "_trades":
                    self._trades = deque(value, maxlen=MAX_RECENT_TRADES)
                elif name == "_block_order_count":
                    self._block_order_count = dict(value)
                else:
                    setattr(self, name, value)
            self._version += 1
            self._digest = None

        scope.record(self, "book", restore)

    def _keep_order(self, index: Dict[str, Order], oid: str) -> None:
        """An entry of the order index or the stop-order index, before it changes (and, before
        the first removal from the stop-order index, its order: stop orders trigger in the order
        they were placed). The order index's and the price levels' own order is never read (the
        levels are always sorted by price), so it is not kept."""
        scope = undo.active()
        if scope is None:
            return
        if oid in index and index is self._stop_orders:
            undo.keep_order(index)  # stop orders trigger in the order they were placed
        if not scope.first(index, ("order", oid)):
            return
        if oid in index:
            old = scope.copy(index[oid])  # the same copy as in its captured price level

            def restore() -> None:
                index[oid] = old

        else:

            def restore() -> None:
                index.pop(oid, None)

        scope.record(index, ("order", oid), restore)

    def _keep_count(self, counts: Dict[str, int], owner: str) -> None:
        undo.keep_entry(counts, owner, mutable=False)

    def _touch(self, side: OrderSide, price: Decimal) -> None:
        """A resting level changed: an order added, filled, cancelled or removed, or the level
        itself dropped. Its digest is redone at the next ``cached_digest``. Inside an undo
        scope the level is first recorded as it was."""
        tag = "b" if side == OrderSide.BUY else "a"
        dirty = self.__dict__.get("_dirty_levels")
        if dirty is not None:
            dirty.add((tag, price))
        scope = undo.active()
        if scope is None or not scope.first(self, ("level", tag, price)):
            return
        levels = self._bids if side == OrderSide.BUY else self._asks
        old = scope.copy(levels[price]) if price in levels else None

        def restore() -> None:
            now = self._bids if tag == "b" else self._asks
            if old is None:
                now.pop(price, None)
            else:
                now[price] = old
                # The order index must hold the restored orders themselves (a maker filled in
                # part stayed indexed while it changed in place).
                for o in old.orders:
                    if o.is_active:
                        self._orders[o.id] = o
            marks = self.__dict__.get("_dirty_levels")
            if marks is not None:
                marks.add((tag, price))
            self._version += 1
            self._digest = None

        scope.record(self, ("level", tag, price), restore)

    def _level_digest(self, tag: str, price: Decimal, level: PriceLevel) -> bytes:
        return hashlib.blake2b(self._level_payload(tag, price, level), digest_size=32).digest()

    @staticmethod
    def level_key(tag: str, price: Any) -> bytes:
        """A price level's key in the book's proof tree (docs/STATE_PROOFS.md)."""
        from ..crypto import smt

        return smt.key_of(b"\x21" + f"{tag}{price}".encode())

    def _level_payload(self, tag: str, price: Decimal, level: PriceLevel) -> bytes:
        """A level's canonical bytes: its orders in time priority (what its digest hashes)."""
        parts = [f"{tag}{price}"]
        for o in level.orders:  # time priority
            entry = (
                f"{o.id}:{o.owner}:{o.side.value}:{o.order_type.value}:"
                f"{o.price}:{o.amount}:{o.filled}:{o.status.value}:{o.nonce}:"
                f"{o.expire_time}"
            )
            if o.hidden:
                entry += ":hidden"
            elif o.is_iceberg:
                entry += f":iceberg:{o.display_size}:{o.shown}"
            parts.append(entry)
        return "|".join(parts).encode()

    def _compose(self, levels: bytes, nonces: bytes) -> bytes:
        """The book digest from its parts: the header fields, the levels' LtHash, every parked
        stop order (few), the owners' nonces."""
        h = hashlib.blake2b(digest_size=32)
        h.update("|".join(self.header()).encode())
        h.update(levels)
        h.update(nonces)
        return h.digest()

    def _nonces(self) -> CommittedDict:
        if not isinstance(self._owner_nonces, CommittedDict):  # a book from before
            self._owner_nonces = as_committed_dict(
                dict(self._owner_nonces), "book.nonces", encode_value, mutable=False
            )
        return self._owner_nonces

    @_pinned
    def state_digest(self) -> bytes:
        """Every consensus-relevant field, from scratch: each resting order in priority order
        (per price level, then time), each parked stop order, the owners' order nonces, the
        trade sequence, the last trade price and the totals — not the display history or any
        wall-clock stamp. ``cached_digest`` keeps the same value up to date incrementally."""
        acc = lthash.Accumulator()
        for tag, levels in (("b", self._bids), ("a", self._asks)):
            for price, level in levels.items():
                acc.add(_vector("book.level", self._level_digest(tag, price, level)))
        return self._compose(acc.digest(), self._nonces().full_commitment())

    @_pinned
    def cached_digest(self) -> bytes:
        """``state_digest()``, redoing only the levels touched since the last call (a book used
        to be re-digested whole — 6 ms at 4,000 resting orders — whenever a block touched it)."""
        if self._digest is not None and self._digest_version == self._version:
            return self._digest
        from ..crypto import smt
        from .commitment import trees_on

        held = self.__dict__.get("_level_digests")
        full = held is None
        digests: Dict[Tuple[str, Decimal], bytes] = {} if held is None else held
        if full:
            self._level_acc = lthash.ZERO
            dirty = {("b", p) for p in self._bids} | {("a", p) for p in self._asks}
        else:
            dirty = self.__dict__.get("_dirty_levels") or set()
        trees = trees_on()
        removed, added = lthash.Accumulator(), lthash.Accumulator()
        tree_changes = []
        for key in dirty:
            tag, price = key
            old = digests.pop(key, None)
            level = (self._bids if tag == "b" else self._asks).get(price)
            payload = self._level_payload(tag, price, level) if level is not None else None
            new = hashlib.blake2b(payload, digest_size=32).digest() if payload else None
            if new is not None:
                digests[key] = new
            if old != new:
                if old is not None:
                    removed.add(_vector("book.level", old))
                if new is not None:
                    added.add(_vector("book.level", new))
                if trees:
                    tree_changes.append((self.level_key(tag, price), payload))
        self._level_acc = _apply(self._level_acc, removed, added)
        self._level_digests = digests
        self._dirty_levels = set()
        # The levels' proof tree, from the same changes (rebuilt whole when the digests were).
        if not trees:
            self._level_tree, self._level_tree_on = None, False
        elif full or not self.__dict__.get("_level_tree_on", False):
            self._level_tree = smt.m_build(sorted(self._all_level_payloads()))
            self._level_tree_on = True
        elif tree_changes:
            self._level_tree = smt.m_update(self.__dict__.get("_level_tree"), sorted(tree_changes))
        self._digest = self._compose(self._level_acc, self._nonces().commitment())
        self._digest_version = self._version
        return self._digest

    def _all_level_payloads(self) -> List[Tuple[bytes, bytes]]:
        out = []
        for tag, levels in (("b", self._bids), ("a", self._asks)):
            for price, level in levels.items():
                out.append((self.level_key(tag, price), self._level_payload(tag, price, level)))
        return out

    @property
    def level_tree(self):
        """The resting levels' proof tree, up to date."""
        self.cached_digest()
        return self.__dict__.get("_level_tree")

    def header(self) -> List[Any]:
        """The book's own fields (its levels and nonces are proven by their trees)."""
        parts: List[Any] = [
            self.pool_id,
            str(self._trade_sequence),
            str(self.total_trades),
            str(self.total_volume),
            str(self.last_price),
        ]
        for oid in sorted(self._stop_orders):
            o = self._stop_orders[oid]
            parts.append(
                f"s{o.id}:{o.owner}:{o.side.value}:{o.stop_price}:{o.amount}:"
                f"{o.filled}:{o.status.value}:{o.nonce}:{o.expire_time}"
            )
        return parts

    def verify_digest(self) -> None:
        from ..crypto import smt
        from .commitment import CommitmentMismatch, trees_on

        if self.cached_digest() != self.state_digest():
            raise CommitmentMismatch(f"order book {self.pool_id}: cached digest is stale")
        if trees_on():
            full = smt.m_build(sorted(self._all_level_payloads()))
            if smt.m_root(self.__dict__.get("_level_tree")) != smt.m_root(full):
                raise CommitmentMismatch(f"order book {self.pool_id}: the level tree is stale")

    # -- Order placement ----------------------------------------------------

    @_pinned
    def place_order(
        self, order: Order, *, protocol: bool = False, budget: Optional[MatchBudget] = None
    ) -> List[Trade]:
        """
        Place an order on the book. Attempts immediate matching.

        Args:
            order: Order to place
            protocol: the protocol's own order (a liquidation), not the owner's. It is not
                subject to the owner's per-block rate limit or nonce sequence — a liquidation
                must not fail because the account traded heavily this block.
            budget: how many resting orders it may visit (``MatchBudget``); None: any number.

        Returns:
            List of trades generated (empty if fully resting)

        Raises:
            ValueError: on invalid order parameters or security violations, and when a
                fill-or-kill order cannot fill whole (the book is then as it was)
        """
        if order.tif == "fok":
            # Undone here, not only by the caller's operation: the book stays consistent
            # whoever places it.
            with undo.atomic():
                return self._place(order, protocol, budget)
        return self._place(order, protocol, budget)

    def _place(self, order: Order, protocol: bool, budget: Optional[MatchBudget]) -> List[Trade]:
        self._keep_scalars()
        self._version += 1  # everything below may change the book
        if self._paused:
            raise ValueError("Order book is paused — emergency mode")

        self._validate_order(order)
        # Post-only: refused, changing nothing, if anything would fill it now.
        if order.tif == "alo" and self._would_match(order):
            raise ValueError("post-only order would match a resting order")
        if not protocol:
            self._check_rate_limit(order.owner)
            self._check_nonce(order)

        # Stop-loss: park it until trigger price hit
        if order.order_type == OrderType.STOP_LOSS:
            return self._place_stop_order(order)

        # Market order: match immediately, reject remainder
        if order.order_type == OrderType.MARKET:
            trades = self._match_market(order, budget)
        else:
            # Limit order: match what we can, rest goes on the book (unless IOC / FOK)
            trades = self._match_limit(order, budget)
        if order.tif == "fok" and order.remaining > 0:
            raise ValueError("fill-or-kill order could not fill completely")
        return trades

    def _would_match(self, order: Order) -> bool:
        """Does a resting order cross ``order``'s limit (hidden ones included)?"""
        buy = order.side == OrderSide.BUY
        opposite = self._asks if buy else self._bids
        crossing = [p for p in opposite if (p <= order.price if buy else p >= order.price)]
        return any(opposite[p].total_amount > 0 for p in crossing)

    @_pinned
    def reduce_order(self, order_id: str, amount: Decimal, caller: str) -> Order:
        """Lower a resting order's amount in place (still above what has filled): it keeps its
        place in the queue, as a smaller order would have had it. Anything else about an
        order changes by replacing it (and queuing again)."""
        self._keep_scalars()
        self._version += 1
        order = self._orders.get(order_id)
        if order is None or not order.is_active:
            raise ValueError(f"no resting order {order_id}")
        if order.owner != caller:
            raise ValueError("Only order owner can modify")
        amount = Decimal(str(amount))
        if not order.filled < amount < order.amount:
            raise ValueError("a reduced order must be smaller, and above what has filled")
        if order.is_iceberg and order.display_size >= amount:
            raise ValueError("an iceberg's display size must be below its amount")
        self._touch(order.side, order.price)  # (records the level, this very order with it)
        order.amount = amount
        if order.is_iceberg:
            order.shown = min(order.shown, order.remaining)
        return order

    @_pinned
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
        self._keep_scalars()
        self._version += 1
        # Check stop orders first
        if order_id in self._stop_orders:
            order = self._stop_orders[order_id]
            if caller and order.owner != caller:
                raise ValueError("Only order owner can cancel")
            self._keep_order(self._stop_orders, order_id)
            del self._stop_orders[order_id]
            order.status = OrderStatus.CANCELLED
            self._decrement_owner_count(order.owner, is_stop=True)
            return order

        found = self._orders.get(order_id)
        if found is None:
            return None
        order = found

        if caller and order.owner != caller:
            raise ValueError("Only order owner can cancel")

        if not order.is_active:
            return None

        # Remove from price level (recorded first: the level holds this very order)
        self._touch(order.side, order.price)
        self._keep_order(self._orders, order_id)
        order.status = OrderStatus.CANCELLED
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

    def _match_market(self, taker: Order, budget: Optional[MatchBudget] = None) -> List[Trade]:
        """Match a market order against the book."""
        trades = []
        opposite = self._asks if taker.side == OrderSide.BUY else self._bids
        prices = (
            sorted(opposite.keys())
            if taker.side == OrderSide.BUY
            else sorted(opposite.keys(), reverse=True)
        )

        for price in list(prices):
            if taker.remaining <= 0 or taker.status == OrderStatus.CANCELLED:
                break
            if budget is not None and budget.exhausted:
                break
            level = opposite[price]
            trades.extend(self._match_at_level(taker, level, price, budget))
            if level.total_amount == 0:
                del opposite[price]

        # Market orders: remaining is discarded (no resting)
        if taker.status == OrderStatus.CANCELLED:
            pass  # self-trade prevention cancelled it
        elif taker.remaining > 0:
            taker.status = OrderStatus.FILLED if taker.filled > 0 else OrderStatus.CANCELLED
        else:
            taker.status = OrderStatus.FILLED

        self._check_stop_triggers()
        return trades

    def _match_limit(self, taker: Order, budget: Optional[MatchBudget] = None) -> List[Trade]:
        """Match a limit order against the book, rest on the book — unless its budget ran out:
        then the remainder is cancelled (it could still cross the book)."""
        trades = []
        opposite = self._asks if taker.side == OrderSide.BUY else self._bids

        if taker.side == OrderSide.BUY:
            matchable_prices = sorted([p for p in opposite if p <= taker.price])
        else:
            matchable_prices = sorted([p for p in opposite if p >= taker.price], reverse=True)

        for price in list(matchable_prices):
            if taker.remaining <= 0 or taker.status == OrderStatus.CANCELLED:
                break
            if budget is not None and budget.exhausted:
                break
            level = opposite[price]
            trades.extend(self._match_at_level(taker, level, price, budget))
            if level.total_amount == 0:
                del opposite[price]

        # Rest on the book if unfilled (never once self-trade prevention cancelled it, never
        # once its budget ran out: the remainder could still cross the book; never an IOC or
        # FOK order)
        if taker.status == OrderStatus.CANCELLED:
            pass
        elif taker.remaining > 0 and (
            (budget is not None and budget.exhausted) or taker.tif in ("ioc", "fok")
        ):
            taker.status = OrderStatus.FILLED if taker.filled > 0 else OrderStatus.CANCELLED
        elif taker.remaining > 0:
            taker.status = OrderStatus.OPEN if taker.filled == 0 else OrderStatus.PARTIALLY_FILLED
            self._add_to_book(taker)
        else:
            taker.status = OrderStatus.FILLED

        self._check_stop_triggers()
        return trades

    def _match_at_level(
        self,
        taker: Order,
        level: PriceLevel,
        price: Decimal,
        budget: Optional[MatchBudget] = None,
    ) -> List[Trade]:
        """Match taker against the makers at a price level, in ``fill_queue`` priority: every
        displayed quantity in time order, then every hidden one. An iceberg whose slice runs
        out shows a new one from the back of the queue once the taker is done here."""
        self._touch(OrderSide.SELL if taker.side == OrderSide.BUY else OrderSide.BUY, price)
        trades: List[Trade] = []
        spent: List[Order] = []  # icebergs whose slice ran out
        self._fill_from_level(taker, level, price, budget, trades, spent)
        # A spent iceberg shows its next slice — at the back of the queue, like a new order —
        # however the taker stopped (filled, out of budget, self-trade prevention).
        for maker in spent:
            if maker.is_active and maker.remaining > 0 and maker.shown <= 0:
                maker.shown = min(maker.display_size, maker.remaining)
                level.remove_order(maker.id)
                level.add_order(maker)
        return trades

    def _fill_from_level(
        self,
        taker: Order,
        level: PriceLevel,
        price: Decimal,
        budget: Optional[MatchBudget],
        trades: List[Trade],
        spent: List[Order],
    ) -> None:
        for tier in ("shown", "reserve"):
            for maker in list(level.orders):
                if taker.remaining <= 0 or taker.status == OrderStatus.CANCELLED:
                    break
                if not maker.is_active:
                    continue
                available = maker.visible if tier == "shown" else maker.reserve
                if available <= 0:
                    continue
                if budget is not None and not budget.take():
                    break

                # --- Self-trade prevention (STP) ---
                if maker.owner == taker.owner:
                    if self.self_trade_action == SelfTradeAction.REJECT:
                        continue  # skip this maker, try next
                    elif self.self_trade_action == SelfTradeAction.CANCEL_MAKER:
                        self._keep_order(self._orders, maker.id)
                        maker.status = OrderStatus.CANCELLED
                        level.remove_order(maker.id)
                        self._orders.pop(maker.id, None)
                        self._decrement_owner_count(maker.owner)
                        continue
                    elif self.self_trade_action == SelfTradeAction.CANCEL_BOTH:
                        self._keep_order(self._orders, maker.id)
                        maker.status = OrderStatus.CANCELLED
                        taker.status = OrderStatus.CANCELLED
                        level.remove_order(maker.id)
                        self._orders.pop(maker.id, None)
                        self._decrement_owner_count(maker.owner)
                        return
                    elif self.self_trade_action == SelfTradeAction.CANCEL_TAKER:
                        taker.status = OrderStatus.CANCELLED
                        return

                fill_amount = min(taker.remaining, available)
                if self.maker_guard is not None and not self.maker_guard(maker, fill_amount):
                    self._keep_order(self._orders, maker.id)
                    maker.status = OrderStatus.CANCELLED
                    level.remove_order(maker.id)
                    self._orders.pop(maker.id, None)
                    self._decrement_owner_count(maker.owner)
                    continue

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
                self.last_price = price
                self.total_volume += fill_amount * price
                self.total_trades += 1

                maker.filled += fill_amount
                taker.filled += fill_amount
                if maker.is_iceberg and tier == "shown":
                    maker.shown = max(ZERO, maker.shown - fill_amount)

                if maker.remaining <= 0:
                    self._keep_order(self._orders, maker.id)
                    maker.status = OrderStatus.FILLED
                    level.remove_order(maker.id)
                    self._orders.pop(maker.id, None)
                    self._decrement_owner_count(maker.owner)
                else:
                    maker.status = OrderStatus.PARTIALLY_FILLED
                    if maker.is_iceberg and maker.shown <= 0 and maker not in spent:
                        spent.append(maker)
            if taker.remaining <= 0 or taker.status == OrderStatus.CANCELLED:
                return
            if budget is not None and budget.exhausted:
                return

    # -- Stop-loss ----------------------------------------------------------

    def _place_stop_order(self, order: Order) -> List[Trade]:
        """Park stop order; it will be triggered when price hits stop_price."""
        if order.stop_price is None:
            raise ValueError("Stop-loss order requires stop_price")
        count = self._owner_stop_count.get(order.owner, 0)
        if count >= MAX_STOP_ORDERS_PER_ADDRESS:
            raise ValueError(f"Max stop orders per address reached ({MAX_STOP_ORDERS_PER_ADDRESS})")
        self._keep_order(self._stop_orders, order.id)
        self._keep_count(self._owner_stop_count, order.owner)
        self._stop_orders[order.id] = order
        self._owner_stop_count[order.owner] = count + 1
        return []

    def _check_stop_triggers(self) -> None:
        """Check if any stop-loss orders should trigger."""
        last_price = self.last_price
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
            # Matching a triggered stop checks the triggers again (its fills move the last
            # price), so a stop listed here may already have been triggered and removed by that
            # inner check. It used to raise KeyError out of the order book — any two stop orders
            # could make a block's exchange section fail.
            if oid not in self._stop_orders:
                continue
            self._keep_order(self._stop_orders, oid)
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
            raise ValueError(f"Order book depth limit reached ({self.max_depth} levels)")

        # Enforce per-address order limit
        count = self._owner_order_count.get(order.owner, 0)
        if count >= self.max_orders_per_address:
            raise ValueError(f"Max orders per address reached ({self.max_orders_per_address})")

        self._touch(order.side, order.price)  # (recorded before the level may be created)
        if order.price not in book:
            book[order.price] = PriceLevel(price=order.price)

        if order.expire_time:
            self._has_expiring = True
        if order.is_iceberg:
            order.shown = min(order.display_size, order.remaining)
        book[order.price].add_order(order)
        self._keep_order(self._orders, order.id)
        self._keep_count(self._owner_order_count, order.owner)
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
        if order.order_type == OrderType.STOP_LOSS and (
            order.stop_price is None or order.stop_price <= 0
        ):
            raise ValueError("Stop-loss requires positive stop_price")
        if order.tif not in ("gtc", "ioc", "fok", "alo"):
            raise ValueError(f"unknown time in force {order.tif!r} (gtc, ioc, fok, alo)")
        if order.tif == "alo" and order.order_type != OrderType.LIMIT:
            raise ValueError("a post-only order must be a limit order")
        if order.tif != "gtc" and order.order_type == OrderType.STOP_LOSS:
            raise ValueError("a stop order is good till cancelled")
        if order.hidden or order.is_iceberg:
            if order.order_type != OrderType.LIMIT or order.tif not in ("gtc", "alo"):
                raise ValueError("only a resting limit order (gtc or alo) can be hidden")
        if order.display_size < 0:
            raise ValueError("display size must not be negative")
        if order.is_iceberg:
            if order.hidden:
                raise ValueError("an order is hidden or an iceberg, not both")
            if order.display_size < self.min_order_size or order.display_size >= order.amount:
                raise ValueError("an iceberg's display size must be below its amount")
        if not order.owner:
            raise ValueError("Order must have an owner address")
        if not order.id:
            raise ValueError("Order must have an ID")
        # Check for duplicate order ID
        if order.id in self._orders or order.id in self._stop_orders:
            raise ValueError(f"Duplicate order ID: {order.id}")
        # Check expiry (against the block's time)
        if order.expired(self._now):
            raise ValueError("Order has already expired")

    def _check_nonce(self, order: Order) -> None:
        """Verify nonce is strictly increasing per owner (replay protection)."""
        if order.nonce > 0:
            last_nonce = self._owner_nonces.get(order.owner, 0)
            if order.nonce <= last_nonce:
                raise ValueError(f"Nonce replay: got {order.nonce}, expected > {last_nonce}")
            self._owner_nonces[order.owner] = order.nonce

    def _check_rate_limit(self, owner: str) -> None:
        """Enforce per-block order rate limit. (Its counter is among the scalars a scope keeps.)"""
        count = self._block_order_count.get(owner, 0)
        if count >= MAX_ORDERS_PER_BLOCK_PER_ADDRESS:
            raise ValueError(f"Rate limit: max {MAX_ORDERS_PER_BLOCK_PER_ADDRESS} orders per block")
        self._block_order_count[owner] = count + 1

    def _decrement_owner_count(self, owner: str, is_stop: bool = False) -> None:
        counts = self._owner_stop_count if is_stop else self._owner_order_count
        self._keep_count(counts, owner)
        counts[owner] = max(0, counts.get(owner, 0) - 1)

    def _cleanup_expired(self) -> None:
        """Remove expired orders during new_block. (No exchange operation sets an expiry today;
        one that did would also have to refund an expired spot order's escrow.)"""
        if not self.__dict__.get("_has_expiring", True):
            return  # nothing resting can expire: no walk over every order each block
        for oid in list(self._orders):
            order = self._orders[oid]
            if order.expired(self._now) and order.is_active:
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

    @_pinned
    def get_bids(self, depth: int = 10) -> List[Tuple[Decimal, Decimal]]:
        """Top N bid levels as (price, total_amount)."""
        return list(itertools.islice(self.iter_levels(bids=True), max(0, depth)))

    @_pinned
    def get_asks(self, depth: int = 10) -> List[Tuple[Decimal, Decimal]]:
        """Top N ask levels as (price, total_amount)."""
        return list(itertools.islice(self.iter_levels(bids=False), max(0, depth)))

    def get_recent_trades(self, count: int = 50) -> List[Trade]:
        return list(self._trades)[-count:] if count > 0 else []

    def get_open_orders(self, owner: Optional[str] = None) -> List[Order]:
        """All open orders, optionally filtered by owner."""
        orders = [o for o in self._orders.values() if o.is_active]
        if owner:
            orders = [o for o in orders if o.owner == owner]
        return orders
