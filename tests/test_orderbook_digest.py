"""
Order books are committed per price level (qrdx/exchange/orderbook.py ``cached_digest``).

A book used to be re-digested whole whenever a block touched it: 6 ms at 4,000 resting orders, on
every block of an active market. Each level's digest is now kept, the book holds their LtHash,
and the entry points mark the levels they change (added to, matched at, cancelled from); owner
nonces are a committed dict. What must hold: after any sequence of operations the cached digest
equals the from-scratch ``state_digest``, and a block that touches one level costs that level.
"""
import random
import time
from decimal import Decimal as D

import pytest

from qrdx.exchange.orderbook import Order, OrderBook, OrderSide, OrderType, SelfTradeAction


def _limit(oid, owner, side, price, amount, nonce=0):
    return Order(id=oid, owner=owner, side=side, order_type=OrderType.LIMIT, price=D(price),
                 amount=D(amount), nonce=nonce)


@pytest.mark.parametrize("seed", range(5))
def test_the_cached_digest_follows_every_operation(seed):
    rng = random.Random(seed)
    book = OrderBook("p", self_trade_action=rng.choice(list(SelfTradeAction)),
                     max_orders_per_address=10**6)
    owners = [f"o{i}" for i in range(8)]
    nonce = {o: 0 for o in owners}
    placed = []
    for i in range(600):
        book.new_block(float(i))
        r = rng.random()
        owner = rng.choice(owners)
        try:
            if r < 0.65:
                side = rng.choice([OrderSide.BUY, OrderSide.SELL])
                price = D(100) + D(rng.randint(-15, 15))
                use_nonce = rng.random() < 0.3
                if use_nonce:
                    nonce[owner] += 1
                book.place_order(_limit(f"x{i}", owner, side, price, rng.choice(["1", "2", "3.5"]),
                                        nonce[owner] if use_nonce else 0))
                placed.append(f"x{i}")
            elif r < 0.9 and placed:
                book.cancel_order(rng.choice(placed))
            else:
                side = rng.choice([OrderSide.BUY, OrderSide.SELL])
                book.place_order(Order(id=f"s{i}", owner=owner, side=side,
                                       order_type=OrderType.STOP_LOSS, price=D(0), amount=D(1),
                                       stop_price=D(100) + D(rng.randint(-10, 10))))
        except ValueError:
            pass
        assert book.cached_digest() == book.state_digest(), f"step {i}"


def test_a_touch_costs_its_level_not_the_book():
    book = OrderBook("p", max_depth=10_000, max_orders_per_address=10**9)
    n = 0
    for lvl in range(500):
        for _ in range(8):
            n += 1
            side = OrderSide.BUY if lvl % 2 else OrderSide.SELL
            price = D(29000 - lvl) if side == OrderSide.BUY else D(31000 + lvl)
            book.place_order(_limit(f"o{n}", f"u{n % 300}", side, price, "0.5"))
    book.cached_digest()
    t0 = time.perf_counter()
    full = book.state_digest()
    full_cost = time.perf_counter() - t0
    book.place_order(_limit("taker", "t", OrderSide.BUY, "31000", "0.25"))   # one level
    t0 = time.perf_counter()
    cached = book.cached_digest()
    touch_cost = time.perf_counter() - t0
    assert cached == book.state_digest() != full
    assert touch_cost < full_cost / 20, f"{touch_cost * 1e3:.2f} ms vs {full_cost * 1e3:.2f} ms"


def test_stops_triggered_inside_a_triggered_stop_do_not_break_the_book():
    """A triggered stop is matched as a market order, whose fills re-check the triggers and
    can trigger (and remove) the other stops the outer check had listed. That used to raise
    KeyError out of place_order: two stop orders were enough to make an exchange section fail."""
    book = OrderBook("p", self_trade_action=SelfTradeAction.CANCEL_TAKER)
    for i, price in enumerate(("99", "98", "97")):
        book.place_order(_limit(f"bid{i}", "maker", OrderSide.BUY, price, "1"))
    for name in ("s1", "s2"):
        book.place_order(Order(id=name, owner=f"stopper-{name}", side=OrderSide.SELL,
                               order_type=OrderType.STOP_LOSS, price=D(0), amount=D(1),
                               stop_price=D("99.5")))
    book.place_order(_limit("ask", "seller", OrderSide.SELL, "99", "0.5"))   # trades at 99
    assert not book._stop_orders                        # both triggered, no exception
    assert book.cached_digest() == book.state_digest()
