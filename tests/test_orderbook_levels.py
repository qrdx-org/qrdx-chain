"""
A book's sides keep their prices sorted (qrdx/exchange/orderbook.py ``PriceLevels``).

Every order read its book's sides in price order several times, and each read sorted up to 500
levels. The sides now keep their prices in order as levels come and go. What must hold: the kept
order is ``sorted(keys)`` after every way a dict changes — including an undo's restore, a deep
copy and a pickle through the snapshot loader — and a book run with them trades, rests and
commits exactly as a book whose sides are plain dicts (sorted on every read, as before).
"""

import copy
import pickle
import random
from decimal import Decimal as D

import pytest

from qrdx.exchange import undo
from qrdx.exchange.orderbook import (
    Order,
    OrderBook,
    OrderSide,
    OrderType,
    PriceLevel,
    PriceLevels,
    SelfTradeAction,
)
from qrdx.snapshot import safe_loads


def _check(levels):
    assert levels.prices() == sorted(dict.keys(levels))


@pytest.mark.parametrize("seed", range(6))
def test_the_kept_order_is_the_sorted_order_after_any_change(seed):
    rng = random.Random(seed)
    levels = PriceLevels()
    prices = [D(rng.randint(1, 60)) / D(rng.choice([1, 10, 100])) for _ in range(40)]
    for _ in range(3000):
        p = rng.choice(prices)
        k = rng.random()
        if k < 0.35:
            levels[p] = PriceLevel(price=p)
        elif k < 0.5 and p in levels:
            del levels[p]
        elif k < 0.6:
            levels.pop(p, None)
        elif k < 0.65 and levels:
            levels.popitem()
        elif k < 0.7:
            levels.setdefault(p, PriceLevel(price=p))
        elif k < 0.75:
            levels.update({q: PriceLevel(price=q) for q in rng.sample(prices, 3)})
        elif k < 0.77:
            levels.clear()
        elif k < 0.8:
            levels = copy.deepcopy(levels)
        elif k < 0.83:
            levels = levels.copy()
        elif k < 0.86:
            levels = safe_loads(pickle.dumps(levels))
            assert type(levels) is PriceLevels
        _check(levels)
    # an equal price under another spelling is the same level, kept once
    levels.clear()
    levels[D("2.0")] = PriceLevel(price=D("2.0"))
    levels[D("2.00")] = PriceLevel(price=D("2.00"))
    assert levels.prices() == [D("2")] and len(levels) == 1


def _book():
    return OrderBook(pool_id="t", self_trade_action=SelfTradeAction.CANCEL_TAKER,
                     max_orders_per_address=10_000)


def _run(book, rng, n, owners):
    out = []
    for i in range(n):
        owner = rng.choice(owners)
        side = rng.choice([OrderSide.BUY, OrderSide.SELL])
        k = rng.random()
        if k < 0.2 and book._orders:
            oid = rng.choice(sorted(book._orders))
            o = book._orders[oid]
            out.append(("cancel", oid, getattr(book.cancel_order(oid, o.owner), "status", None)))
            continue
        kind = OrderType.MARKET if k < 0.3 else OrderType.LIMIT
        price = D(0) if kind == OrderType.MARKET else D(rng.randint(90, 110)) / D(100)
        order = Order(id=f"o{i}", owner=owner, side=side, order_type=kind, price=price,
                      amount=D(rng.randint(1, 40)), timestamp=1.0, nonce=0)
        with undo.atomic():
            try:
                trades = book.place_order(order, protocol=True)
                out.append(("place", order.id, order.status, order.filled,
                            [(t.price, t.amount, t.maker_order_id) for t in trades]))
            except ValueError as e:
                out.append(("refused", order.id, str(e)))
        out.append(("top", book.best_bid, book.best_ask, book.get_bids(5), book.get_asks(5)))
    return out


@pytest.mark.parametrize("seed", range(5))
def test_a_book_runs_as_one_whose_sides_are_sorted_on_every_read(seed):
    owners = [f"0xPQ{i:064x}" for i in range(6)]
    new, old = _book(), _book()
    old._bids, old._asks = dict(old._bids), dict(old._asks)    # (sorted on every read)
    for block in range(6):
        a = _run(new, random.Random(seed * 100 + block), 300, owners)
        b = _run(old, random.Random(seed * 100 + block), 300, owners)
        assert a == b
        assert new.cached_digest() == old.cached_digest() == new.state_digest()
        _check(new._bids), _check(new._asks)


def test_an_undone_order_leaves_the_kept_order_as_it_was():
    book = _book()
    for i, px in enumerate(["1.00", "1.10", "0.90"]):
        book.place_order(Order(id=f"r{i}", owner="0xPQa", side=OrderSide.SELL,
                               order_type=OrderType.LIMIT, price=D(px), amount=D(5),
                               timestamp=1.0), protocol=True)
    before = list(book._asks.prices())
    with pytest.raises(RuntimeError):
        with undo.atomic():
            book.place_order(Order(id="t", owner="0xPQb", side=OrderSide.BUY,
                                   order_type=OrderType.LIMIT, price=D("1.20"), amount=D(12),
                                   timestamp=1.0), protocol=True)
            assert book._asks.prices() != before                 # (levels taken)
            raise RuntimeError("roll back")
    assert book._asks.prices() == before
    _check(book._asks)


def test_one_price_in_any_spelling_is_one_level_to_the_digest():
    """Orders at "2.0" and "2.00" rest at one level. Its payload named the level by whichever
    spelling touched it, so the incremental digest differed from a full recomputation — a
    restarted node's — and one order could split the network."""
    book = _book()
    for i, px in enumerate(["2.0", "2.00", "2", "2.000", "20E-1"]):
        book.place_order(Order(id=f"s{i}", owner=f"0xPQ{i}", side=OrderSide.SELL,
                               order_type=OrderType.LIMIT, price=D(px), amount=D(3),
                               timestamp=1.0), protocol=True)
        assert book.cached_digest() == book.state_digest(), px
    book.place_order(Order(id="t", owner="0xPQt", side=OrderSide.BUY, order_type=OrderType.LIMIT,
                           price=D("2.0000"), amount=D(4), timestamp=1.0), protocol=True)
    assert len(book._asks) == 1
    assert book.cached_digest() == book.state_digest()
    book.verify_digest()                                       # (the level tree too)
