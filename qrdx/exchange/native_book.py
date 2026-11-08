"""
A spot order book held natively (native/qrdx-native/src/book.rs; docs/EXCHANGE_ENGINE.md, E3a).

The Python book (``orderbook.OrderBook``) is the reference: the native one computes exactly what
it computes (``tests/test_native_book.py``). This class puts the Python book's interface over the
native one, so that every caller — the router planning a fill, the spot handler, triggers, views,
undo scopes, snapshots, proofs — runs unchanged, and the state has one owner:

* **Orders** the book hands out (``get_order``, ``_orders``, a level's queue, ``cancel_order``…)
  are ``Order`` objects, and stay what the book holds: every native call reports each order it
  changed, and the objects handed out are updated in place — as the Python book's own objects
  are changed in place. A placed order is the object its caller passed.
* **Views** stand in for the Python book's dicts (``_orders``, ``_stop_orders``, ``_bids``,
  ``_asks``, ``_owner_order_count``): read-only mappings over the native state.
* **Undo**: the first change inside an undo scope records the native state (a pointer copy:
  it is persistent) and the scope's restore puts it back. Every object handed out before is then
  detached: the book hands out new ones. A failed call changes nothing (it rolls itself back)
  and records nothing. A Python book differs only in which handed-out objects a failure
  detaches — those in the levels it touched, which it restores as copies — so the two can
  differ only for an order held across a failure, and no caller does that: each reads its
  orders within one operation, and ``uncross_spot_books`` reads its order after a fill only
  when the fill succeeded.
* **Nonces** stay Python's: a committed dict (``_nonces``), committed and provable as before.
  The native book reads an owner's last nonce and returns the new one.
* **The digest** is ``_compose`` over the native book's header and levels' LtHash and the
  nonces' commitment; the level tree is native. Copies are pointer copies; a pickle is the
  book's data (``export``), which a node without native books loads as the same book in Python.

Only spot books are native: a perps book is given a ``maker_guard`` (a Python callback run
inside matching), which a native book refuses.
"""

from __future__ import annotations

import hashlib
import weakref
from collections import deque
from collections.abc import Mapping
from decimal import Decimal
from typing import Any, Dict, Iterator, List, Optional, Tuple

from . import undo
from .commitment import as_committed_dict, encode_value
from .orderbook import (
    MAX_ORDERS_PER_ADDRESS,
    MAX_RECENT_TRADES,
    MIN_ORDER_SIZE,
    MatchBudget,
    Order,
    OrderBook,
    OrderSide,
    OrderStatus,
    OrderType,
    PriceLevel,
    SelfTradeAction,
    Trade,
)

_SET = ("amount", "filled", "status", "order_type", "shown")


def available() -> bool:
    """Whether spot books are held natively here (the module, and not ``QRDX_NATIVE_BOOK=0``)."""
    import os

    from .. import native

    if os.environ.get("QRDX_NATIVE_BOOK", "1").strip().lower() in ("0", "false", "no", "off"):
        return False
    return native.AVAILABLE and hasattr(native._native, "NativeBook")


def _dict_of(o: Order) -> Dict[str, Any]:
    return {
        "id": o.id,
        "owner": o.owner,
        "side": o.side.value,
        "order_type": o.order_type.value,
        "price": str(o.price),
        "amount": str(o.amount),
        "filled": str(o.filled),
        "status": o.status.value,
        "timestamp": float(o.timestamp),
        "stop_price": None if o.stop_price is None else str(o.stop_price),
        "nonce": int(o.nonce),
        "expire_time": float(o.expire_time),
        "tif": o.tif,
        "hidden": bool(o.hidden),
        "display_size": str(o.display_size),
        "shown": str(o.shown),
    }


def _new_order(d: Dict[str, Any]) -> Order:
    return Order(
        id=d["id"],
        owner=d["owner"],
        side=OrderSide(d["side"]),
        order_type=OrderType(d["order_type"]),
        price=Decimal(d["price"]),
        amount=Decimal(d["amount"]),
        filled=Decimal(d["filled"]),
        status=OrderStatus(d["status"]),
        timestamp=d["timestamp"],
        stop_price=None if d["stop_price"] is None else Decimal(d["stop_price"]),
        nonce=d["nonce"],
        expire_time=d["expire_time"],
        tif=d["tif"],
        hidden=d["hidden"],
        display_size=Decimal(d["display_size"]),
        shown=Decimal(d["shown"]),
    )


def _update(o: Order, d: Dict[str, Any]) -> None:
    """What the book may change of an order, as the book now holds it."""
    o.amount = Decimal(d["amount"])
    o.filled = Decimal(d["filled"])
    o.status = OrderStatus(d["status"])
    o.order_type = OrderType(d["order_type"])
    o.shown = Decimal(d["shown"])


def _trade(d: Dict[str, Any]) -> Trade:
    return Trade(
        id=d["id"],
        maker_order_id=d["maker_order_id"],
        taker_order_id=d["taker_order_id"],
        price=Decimal(d["price"]),
        amount=Decimal(d["amount"]),
        maker_fee=Decimal(d["maker_fee"]),
        taker_fee=Decimal(d["taker_fee"]),
        timestamp=d["timestamp"],  # (the wall clock when it traded: display only)
        buyer=d["buyer"],
        seller=d["seller"],
        sequence=d["sequence"],
    )


class _BookTrade(Trade):
    """A trade a native book handed out. Settlement writes each side's fee on it
    (``_settle_spot_trade``), and a Python book's trade objects are its display history's own: so
    the fees written here reach the native book's history too."""

    def __setattr__(self, name: str, value: Any) -> None:
        object.__setattr__(self, name, value)
        if name in ("maker_fee", "taker_fee"):
            ref = self.__dict__.get("_book")
            book = ref() if ref is not None else None
            if book is not None:
                book._set_trade_fee(self.id, name == "maker_fee", value)

    def __reduce__(self) -> Any:  # (a copy or a pickle is a plain trade)
        return (Trade, tuple(getattr(self, f) for f in Trade.__dataclass_fields__))


class _Index(Mapping):
    """The resting orders (``_orders``) or the parked stop orders (``_stop_orders``)."""

    def __init__(self, book: "NativeSpotBook", stops: bool) -> None:
        self._book, self._stops = book, stops

    def _read(self, oid: Any) -> Optional[Dict[str, Any]]:
        nb = self._book._native
        if not isinstance(oid, str):
            return None
        return nb.stop_order(oid) if self._stops else nb.resting_order(oid)

    def __getitem__(self, oid: Any) -> Order:
        d = self._read(oid)
        if d is None:
            raise KeyError(oid)
        return self._book._order(d)

    def __contains__(self, oid: Any) -> bool:
        if self._stops:
            return self._read(oid) is not None
        return isinstance(oid, str) and self._book._native.has_order(oid)

    def __iter__(self) -> Iterator[str]:
        nb = self._book._native
        return iter(nb.stop_ids() if self._stops else nb.order_ids())

    def __len__(self) -> int:
        nb = self._book._native
        return len(nb.stop_ids()) if self._stops else nb.order_count()


class _Side(Mapping):
    """One side's price levels (``_bids`` / ``_asks``): price → its level, as a ``PriceLevel``
    of the orders handed out."""

    def __init__(self, book: "NativeSpotBook", bids: bool) -> None:
        self._book, self._bids = book, bids

    def __getitem__(self, price: Any) -> PriceLevel:
        nb = self._book._native
        key = str(Decimal(str(price)))
        orders = nb.level_orders(self._bids, key)
        if orders is None:
            raise KeyError(price)
        return PriceLevel(
            price=Decimal(nb.level_price(self._bids, key)),
            orders=[self._book._order(d) for d in orders],
        )

    def __contains__(self, price: Any) -> bool:
        try:
            key = str(Decimal(str(price)))
        except Exception:
            return False
        return self._book._native.level_price(self._bids, key) is not None

    def prices(self) -> List[Decimal]:
        """Ascending (``PriceLevels.prices``)."""
        out = [Decimal(p) for p in self._book._native.level_prices(self._bids)]
        return out[::-1] if self._bids else out

    def __iter__(self) -> Iterator[Decimal]:
        return iter(self.prices())

    def __len__(self) -> int:
        return int(self._book._native.level_count(self._bids))


class _Counts(Mapping):
    """Each owner's resting orders (``_owner_order_count``)."""

    def __init__(self, book: "NativeSpotBook") -> None:
        self._book = book

    def __getitem__(self, owner: Any) -> int:
        counts = dict(self._book._native.owner_counts())
        return counts[owner]

    def get(self, owner: Any, default: Any = None) -> Any:
        n = self._book._native.owner_count(str(owner))
        return n if n or owner in self else default

    def __contains__(self, owner: Any) -> bool:
        return any(o == owner for o, _n in self._book._native.owner_counts())

    def __iter__(self) -> Iterator[str]:
        return iter([o for o, _n in self._book._native.owner_counts()])

    def __len__(self) -> int:
        return len(self._book._native.owner_counts())


class NativeSpotBook(OrderBook):
    """``OrderBook``'s interface over the native book (see the module doc)."""

    def __init__(
        self,
        pool_id: str = "",
        max_depth: int = 500,
        maker_fee_rate: Decimal = Decimal("0.0002"),
        taker_fee_rate: Decimal = Decimal("0.0005"),
        self_trade_action: SelfTradeAction = SelfTradeAction.REJECT,
        min_order_size: Decimal = MIN_ORDER_SIZE,
        max_orders_per_address: int = MAX_ORDERS_PER_ADDRESS,
    ) -> None:
        # (not OrderBook.__init__: the state is the native book's)
        from .. import native

        self.pool_id = pool_id
        self.max_depth = max_depth
        self.maker_fee_rate = maker_fee_rate
        self.taker_fee_rate = taker_fee_rate
        self.self_trade_action = self_trade_action
        self.min_order_size = min_order_size
        self.max_orders_per_address = max_orders_per_address
        self._native = native._native.NativeBook(*self._config())
        self._owner_nonces = as_committed_dict({}, "book.nonces", encode_value, mutable=False)
        self._handed: "weakref.WeakValueDictionary[str, Order]" = weakref.WeakValueDictionary()

    def _config(self) -> Tuple[Any, ...]:
        return _config_of(self)

    # ── a perps book's callback is not run natively ────────────────────────────────────────

    @property
    def maker_guard(self) -> None:  # type: ignore[override]
        return None

    @maker_guard.setter
    def maker_guard(self, guard: Any) -> None:
        if guard is not None:
            raise TypeError("a native book runs no maker guard (perps books are Python's)")

    # ── orders handed out ──────────────────────────────────────────────────────────────────

    def _order(self, d: Dict[str, Any]) -> Order:
        """The order object for ``d`` (its id's, if handed out before: updated in place)."""
        o = self._handed.get(d["id"])
        if o is None:
            o = _new_order(d)
            self._handed[d["id"]] = o
        else:
            _update(o, d)
        return o

    def _changed(self, changed: List[Dict[str, Any]], skip: Optional[Order] = None) -> None:
        for d in changed:
            o = self._handed.get(d["id"])
            if o is not None and o is not skip:
                _update(o, d)

    def _before(self) -> Any:
        """The native state before a change, if an undo scope may need it (a pointer copy)."""
        return self._native.copy() if undo.active() is not None else None

    def _kept(self, saved: Any) -> None:
        """After a change succeeded: the first in its undo scope records the state before it.
        (A failed native call changes nothing — it rolls itself back — so it records nothing,
        as a Python book's refusal records nothing.)"""
        scope = undo.active()
        if saved is None or scope is None or not scope.first(self, "native"):
            return

        def restore() -> None:
            self._native = saved
            self._handed = weakref.WeakValueDictionary()  # (detached, as restored copies are)

        scope.record(self, "native", restore)

    # ── views of the state ─────────────────────────────────────────────────────────────────

    @property
    def _orders(self) -> _Index:  # type: ignore[override]
        return _Index(self, stops=False)

    @property
    def _stop_orders(self) -> _Index:  # type: ignore[override]
        return _Index(self, stops=True)

    @property
    def _bids(self) -> _Side:  # type: ignore[override]
        return _Side(self, bids=True)

    @property
    def _asks(self) -> _Side:  # type: ignore[override]
        return _Side(self, bids=False)

    @property
    def _owner_order_count(self) -> _Counts:  # type: ignore[override]
        return _Counts(self)

    @property
    def last_price(self) -> Optional[Decimal]:  # type: ignore[override]
        p = self._native.totals()[3]
        return None if p is None else Decimal(p)

    @property
    def total_volume(self) -> Decimal:  # type: ignore[override]
        return Decimal(self._native.totals()[2])

    @property
    def total_trades(self) -> int:  # type: ignore[override]
        return int(self._native.totals()[1])

    @property
    def _trade_sequence(self) -> int:  # type: ignore[override]
        return int(self._native.totals()[0])

    @property
    def _paused(self) -> bool:  # type: ignore[override]
        return bool(self._native.is_paused)

    @property
    def is_paused(self) -> bool:
        return bool(self._native.is_paused)

    @property
    def has_expiring(self) -> bool:
        return bool(self._native.has_expiring)

    # ── reads ──────────────────────────────────────────────────────────────────────────────

    @property
    def best_bid(self) -> Optional[Decimal]:
        p = self._native.best(True)
        return None if p is None else Decimal(p)

    @property
    def best_ask(self) -> Optional[Decimal]:
        p = self._native.best(False)
        return None if p is None else Decimal(p)

    def _best(self, bids: bool) -> Optional[Decimal]:
        return self.best_bid if bids else self.best_ask

    def level_prices(self, bids: bool) -> List[Decimal]:
        return [Decimal(p) for p in self._native.level_prices(bids)]

    def iter_levels(self, bids: bool):
        for price, amount in self._native.iter_levels(bids):
            yield Decimal(price), Decimal(amount)

    @property
    def bid_depth(self) -> int:
        return len(self._native.iter_levels(True))

    @property
    def ask_depth(self) -> int:
        return len(self._native.iter_levels(False))

    def get_order(self, order_id: str) -> Optional[Order]:
        d = self._native.get_order(str(order_id))
        return None if d is None else self._order(d)

    @property
    def _trades(self) -> "deque[Trade]":  # type: ignore[override]
        """The display history (never consensus)."""
        from .orderbook import MAX_RECENT_TRADES

        return deque(
            (_trade(d) for d in self._native.recent_trades(MAX_RECENT_TRADES)),
            maxlen=MAX_RECENT_TRADES,
        )

    def canonical_state(self) -> Tuple[Any, ...]:
        """The book as data — what two books with the same state agree on (comparisons of the
        whole exchange's state; the native book itself is opaque)."""
        return (self._config(), dict(self._native.export()), dict(self._nonces().peek_items()))

    def get_recent_trades(self, count: int = 50) -> List[Trade]:
        return [_trade(d) for d in self._native.recent_trades(max(0, int(count)))]

    def get_open_orders(self, owner: Optional[str] = None) -> List[Order]:
        orders = [o for o in self._orders.values() if o.is_active]
        if owner:
            orders = [o for o in orders if o.owner == owner]
        return orders

    # ── changes ────────────────────────────────────────────────────────────────────────────

    def place_order(
        self, order: Order, *, protocol: bool = False, budget: Optional[MatchBudget] = None
    ) -> List[Trade]:
        saved = self._before()
        last = self._nonces().peek(order.owner, 0) if not protocol else 0
        try:
            trades, ended, used, changed, nonce = self._native.place_order(
                _dict_of(order),
                protocol,
                None if budget is None else budget.left,
                int(last or 0),
            )
        except ValueError as e:
            if budget is not None:
                visited = int(getattr(e, "makers_visited", 0))
                budget.visited += visited
                budget.left -= visited
            state = getattr(e, "order_state", None)
            if state is not None:  # (the caller's order keeps what matching did, as in Python)
                _update(order, state)
            raise
        self._kept(saved)
        if budget is not None and used is not None:
            budget.visited += used[0]
            budget.left -= used[0]
            budget.exhausted = bool(used[1])
        if nonce is not None:
            self._owner_nonces[order.owner] = nonce
        _update(order, ended)
        self._changed(changed, skip=order)
        if self._native.has_order(order.id) or self._native.stop_order(order.id) is not None:
            self._handed[order.id] = order  # (it rests or waits: the book's object is the caller's)
        out: List[Trade] = []
        for d in trades:
            t = _BookTrade(**_trade(d).__dict__)
            object.__setattr__(t, "_book", weakref.ref(self))
            out.append(t)
        return out

    def _set_trade_fee(self, trade_id: str, maker: bool, fee: Decimal) -> None:
        saved = self._before()
        self._native.set_trade_fee(trade_id, maker, str(fee))
        self._kept(saved)

    def cancel_order(self, order_id: str, caller: str = "") -> Optional[Order]:
        saved = self._before()
        d = self._native.cancel_order(str(order_id), caller)
        self._kept(saved)
        return None if d is None else self._order(d)

    def reduce_order(self, order_id: str, amount: Decimal, caller: str) -> Order:
        saved = self._before()
        d = self._native.reduce_order(str(order_id), str(Decimal(str(amount))), caller)
        self._kept(saved)
        return self._order(d)

    def fill_resting(self, order_id: str, amount: Decimal) -> Order:
        saved = self._before()
        d = self._native.fill_resting(str(order_id), str(Decimal(str(amount))))
        self._kept(saved)
        return self._order(d)

    def record_price(self, price: Decimal) -> None:
        saved = self._before()
        self._native.record_price(str(Decimal(str(price))))
        self._kept(saved)

    def enter_block(self, height: int, now: float) -> None:
        if self._native.block_height == height:
            return
        saved = self._before()
        changed = self._native.enter_block(int(height), float(now))
        self._kept(saved)
        self._changed(changed)

    def new_block(self, now: Optional[float] = None) -> None:
        saved = self._before()
        changed = self._native.new_block(None if now is None else float(now))
        self._kept(saved)
        self._changed(changed)

    def pause(self) -> None:
        saved = self._before()
        self._native.pause()
        self._kept(saved)

    def unpause(self) -> None:
        saved = self._before()
        self._native.unpause()
        self._kept(saved)

    # ── the commitment ─────────────────────────────────────────────────────────────────────

    def _nonces(self):
        return self._owner_nonces

    def header(self) -> List[Any]:
        return list(self._native.header())

    def _compose(self, levels: bytes, nonces: bytes) -> bytes:
        h = hashlib.blake2b(digest_size=32)
        h.update("|".join(self.header()).encode())
        h.update(levels)
        h.update(nonces)
        return h.digest()

    def cached_digest(self) -> bytes:
        from .commitment import trees_on

        levels = bytes(self._native.commitment(trees_on()))
        return self._compose(levels, self._nonces().commitment())

    def state_digest(self) -> bytes:
        nonces = [(str(k), int(v)) for k, v in self._nonces().peek_items()]
        return bytes(self._native.state_digest(nonces))

    @property
    def level_tree(self):
        self.cached_digest()
        return self._native.level_tree

    def verify_digest(self) -> None:
        from ..crypto import smt
        from .commitment import CommitmentMismatch, trees_on

        if self.cached_digest() != self.state_digest():
            raise CommitmentMismatch(f"order book {self.pool_id}: cached digest is stale")
        if trees_on():
            full = smt._py_build(
                sorted((bytes(k), bytes(p)) for k, p in self._native.level_entries())
            )
            if smt.m_root(self._native.level_tree) != smt.m_root(full):
                raise CommitmentMismatch(f"order book {self.pool_id}: the level tree is stale")

    # ── copies ─────────────────────────────────────────────────────────────────────────────

    def snapshot(self) -> Any:
        import copy

        return self._native.copy(), copy.deepcopy(self._owner_nonces)

    def restore(self, snap: Any) -> None:
        import copy

        self._native = snap[0].copy()
        self._owner_nonces = copy.deepcopy(snap[1])
        self._handed = weakref.WeakValueDictionary()

    def __deepcopy__(self, memo: Dict[int, Any]) -> "NativeSpotBook":
        import copy

        new = NativeSpotBook.__new__(NativeSpotBook)
        memo[id(self)] = new
        for k in (
            "pool_id",
            "max_depth",
            "maker_fee_rate",
            "taker_fee_rate",
            "self_trade_action",
            "min_order_size",
            "max_orders_per_address",
        ):
            object.__setattr__(new, k, getattr(self, k))
        new._native = self._native.copy()
        new._owner_nonces = copy.deepcopy(self._owner_nonces, memo)
        new._handed = weakref.WeakValueDictionary()
        return new

    def __reduce__(self):
        return (
            _rebuild_native_book,
            (self._config(), dict(self._native.export()), dict(self._owner_nonces.peek_items())),
        )


def _rebuild_native_book(config: Tuple[Any, ...], data: Dict[str, Any], nonces: Dict[str, int]):
    if not available():  # (a checkpoint or a published snapshot, loaded without native books)
        return _python_book(config, data, nonces)
    from .. import native

    pool_id, max_depth, maker, taker, stp, minimum, per_address = config
    book = NativeSpotBook.__new__(NativeSpotBook)
    book.pool_id = pool_id
    book.max_depth = max_depth
    book.maker_fee_rate = Decimal(maker)
    book.taker_fee_rate = Decimal(taker)
    book.self_trade_action = SelfTradeAction(stp)
    book.min_order_size = Decimal(minimum)
    book.max_orders_per_address = per_address
    book._native = native._native.NativeBook.from_export(*config, data)
    book._owner_nonces = as_committed_dict(dict(nonces), "book.nonces", encode_value, mutable=False)
    book._handed = weakref.WeakValueDictionary()
    return book


def _config_of(book: OrderBook) -> Tuple[Any, ...]:
    return (
        book.pool_id,
        int(book.max_depth),
        str(book.maker_fee_rate),
        str(book.taker_fee_rate),
        SelfTradeAction(book.self_trade_action).value,
        str(book.min_order_size),
        int(book.max_orders_per_address),
    )


def as_spot_book(book: OrderBook) -> OrderBook:
    """A spot book as this node holds them: a Python one (from a checkpoint or a published
    snapshot written without native books) becomes native where native books are available —
    the same book (``_python_book`` in reverse)."""
    if type(book) is not OrderBook or not available():
        return book
    data = {
        "levels": [
            (tag, str(level.price), [_dict_of(o) for o in level.orders])
            for tag, side in (("b", book._bids), ("a", book._asks))
            for level in side.values()
        ],
        "order_ids": list(book._orders),
        "stops": [_dict_of(o) for o in book._stop_orders.values()],
        "owner_order_count": list(book._owner_order_count.items()),
        "owner_stop_count": list(book._owner_stop_count.items()),
        "block_order_count": list(book._block_order_count.items()),
        "trade_sequence": book._trade_sequence,
        "last_price": None if book.last_price is None else str(book.last_price),
        "total_volume": str(book.total_volume),
        "total_trades": book.total_trades,
        "paused": book._paused,
        "now": book._now,
        "has_expiring": book.has_expiring,
        "block_height": book.__dict__.get("_block_height"),
        "recent": [
            {
                "id": t.id,
                "maker_order_id": t.maker_order_id,
                "taker_order_id": t.taker_order_id,
                "price": str(t.price),
                "amount": str(t.amount),
                "maker_fee": str(t.maker_fee),
                "taker_fee": str(t.taker_fee),
                "buyer": t.buyer,
                "seller": t.seller,
                "sequence": t.sequence,
                "timestamp": float(t.timestamp),
            }
            for t in book._trades
        ],
    }
    return _rebuild_native_book(_config_of(book), data, dict(book._nonces().peek_items()))


def _python_book(
    config: Tuple[Any, ...], data: Dict[str, Any], nonces: Dict[str, int]
) -> OrderBook:
    """The book a native book's data (``export``) describes, held by Python: the same levels and
    queues, order index, stop orders, counts, fields and history. Its commitment caches start
    empty (the next digest computes them in full)."""
    pool_id, max_depth, maker, taker, stp, minimum, per_address = config
    book = OrderBook(
        pool_id=pool_id,
        max_depth=max_depth,
        maker_fee_rate=Decimal(maker),
        taker_fee_rate=Decimal(taker),
        self_trade_action=SelfTradeAction(stp),
        min_order_size=Decimal(minimum),
        max_orders_per_address=per_address,
    )
    resting: Dict[str, Order] = {}
    for tag, price, orders in data["levels"]:
        level = PriceLevel(price=Decimal(price))
        for d in orders:
            order = resting[d["id"]] = _new_order(d)
            level.add_order(order)
        (book._bids if tag == "b" else book._asks)[level.price] = level
    for oid in data["order_ids"]:
        if oid not in resting:
            raise ValueError(f"an indexed order {oid} rests nowhere")
        book._orders[oid] = resting.pop(oid)
    if resting:
        raise ValueError(f"a resting order {next(iter(resting))} is not indexed")
    for d in data["stops"]:
        book._stop_orders[d["id"]] = _new_order(d)
    book._owner_order_count = dict(data["owner_order_count"])
    book._owner_stop_count = dict(data["owner_stop_count"])
    book._block_order_count = dict(data["block_order_count"])
    book._owner_nonces = as_committed_dict(dict(nonces), "book.nonces", encode_value, mutable=False)
    book._trade_sequence = data["trade_sequence"]
    book.last_price = None if data["last_price"] is None else Decimal(data["last_price"])
    book.total_volume = Decimal(data["total_volume"])
    book.total_trades = data["total_trades"]
    book._paused = data["paused"]
    book._now = data["now"]
    book._has_expiring = data["has_expiring"]
    if data["block_height"] is not None:
        book._block_height = data["block_height"]
    book._trades = deque((_trade(t) for t in data["recent"]), maxlen=MAX_RECENT_TRADES)
    return book


def new_spot_book(pool_id: str, self_trade_action: SelfTradeAction) -> OrderBook:
    """A spot pair's book: native where it can be (``available``), Python's otherwise."""
    if available():
        return NativeSpotBook(pool_id=pool_id, self_trade_action=self_trade_action)
    return OrderBook(pool_id=pool_id, self_trade_action=self_trade_action)
