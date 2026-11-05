"""
The native order book (native/qrdx-native/src/book.rs) is the Python one (qrdx/exchange/orderbook.py).

Both books get the same random operations — limit, market and stop orders in every time in force,
hidden and iceberg orders, one price in several spellings, budgets of makers, the protocol's own
orders, cancels by the owner and by others, reductions, fills by a plan, prices recorded from a
pool, new blocks, pauses — under each self-trade rule. After each: the same trades (ids, prices,
amounts, fees, sides), the order as it ended, the same error, the same budget used, the same top
of the book, every level's queue order by order, the same totals, and the same digest.
"""

import random
from decimal import Decimal as D

import pytest

N = pytest.importorskip("qrdx_native")

from qrdx.exchange import undo  # noqa: E402
from qrdx.exchange.orderbook import (  # noqa: E402
    MatchBudget,
    Order,
    OrderBook,
    OrderSide,
    OrderType,
    SelfTradeAction,
)

OWNERS = [f"0xPQ{i:064x}" for i in range(1, 6)]
SPELLINGS = {D("1.00"): ["1", "1.0", "1.00", "10E-1"], D("1.05"): ["1.05", "1.050"]}


def _order_dict(o):
    return {
        "id": o.id, "owner": o.owner, "side": o.side.value, "order_type": o.order_type.value,
        "price": str(o.price), "amount": str(o.amount), "filled": str(o.filled),
        "status": o.status.value, "timestamp": o.timestamp,
        "stop_price": None if o.stop_price is None else str(o.stop_price), "nonce": o.nonce,
        "expire_time": o.expire_time, "tif": o.tif, "hidden": o.hidden,
        "display_size": str(o.display_size), "shown": str(o.shown),
    }


def _trade_dict(t):
    return {
        "id": t.id, "maker_order_id": t.maker_order_id, "taker_order_id": t.taker_order_id,
        "price": str(t.price), "amount": str(t.amount), "maker_fee": str(t.maker_fee),
        "taker_fee": str(t.taker_fee), "buyer": t.buyer, "seller": t.seller,
        "sequence": t.sequence,
    }


def _py_order(d):
    return Order(
        id=d["id"], owner=d["owner"], side=OrderSide(d["side"]),
        order_type=OrderType(d["order_type"]), price=D(d["price"]), amount=D(d["amount"]),
        timestamp=d["timestamp"],
        stop_price=None if d["stop_price"] is None else D(d["stop_price"]), nonce=d["nonce"],
        expire_time=d["expire_time"], tif=d["tif"], hidden=d["hidden"],
        display_size=D(d["display_size"]),
    )


def _price(rng):
    if rng.random() < 0.25:
        value = rng.choice(list(SPELLINGS))
        return rng.choice(SPELLINGS[value])
    return str(D(rng.randint(90, 112)) / D(100))


def _new_order(rng, i, now):
    kind = rng.choices(["limit", "market", "stop_loss"], [0.75, 0.15, 0.1])[0]
    tif = rng.choices(["gtc", "ioc", "fok", "alo", "day"], [0.6, 0.12, 0.1, 0.15, 0.03])[0]
    if kind != "limit" and tif == "alo" and rng.random() < 0.7:
        tif = "gtc"
    amount = str(D(rng.randint(1, 4000)) / D(100))
    hidden = kind == "limit" and rng.random() < 0.08
    display = "0"
    if kind == "limit" and not hidden and rng.random() < 0.12:
        display = str(D(rng.randint(1, 1500)) / D(100))
    return {
        "id": f"o{i}", "owner": rng.choice(OWNERS), "side": rng.choice(["buy", "sell"]),
        "order_type": kind, "price": _price(rng) if kind != "market" else "0",
        "amount": amount, "timestamp": 1.0,
        "stop_price": _price(rng) if kind == "stop_loss" else None,
        "nonce": rng.choice([0, 0, rng.randint(1, 50)]),
        "expire_time": rng.choice([0.0, 0.0, 0.0, now + rng.choice([-5.0, 30.0, 300.0])]),
        "tif": tif, "hidden": hidden, "display_size": display,
    }


def _both(py, nb, call_py, call_native):
    """Run an operation on both books (Python's inside an undo scope, as an operation's is);
    (result or error) of each."""
    try:
        with undo.atomic():
            a = ("ok", call_py())
    except ValueError as e:
        a = ("error", str(e))
    try:
        b = ("ok", call_native())
    except ValueError as e:
        b = ("error", str(e))
    return a, b


def _compare_books(py, nb):
    assert nb.best(True) == (None if py.best_bid is None else str(py.best_bid))
    assert nb.best(False) == (None if py.best_ask is None else str(py.best_ask))
    for bids in (True, False):
        prices = py.level_prices(bids)
        assert nb.level_prices(bids) == [str(p) for p in prices]
        levels = py._bids if bids else py._asks
        for p in prices:
            assert nb.level_orders(bids, str(p)) == [_order_dict(o) for o in levels[p].orders]
    seq, trades, volume, last = nb.totals()
    assert (seq, trades, volume, last) == (
        py._trade_sequence, py.total_trades, str(py.total_volume),
        None if py.last_price is None else str(py.last_price))
    assert nb.state_digest() == py.state_digest() == py.cached_digest()


@pytest.mark.parametrize("stp", ["cancel_taker", "cancel_maker", "cancel_both", "reject"])
@pytest.mark.parametrize("seed", range(6))
def test_random_operations_run_as_python_runs_them(stp, seed):
    rng = random.Random(f"{stp}-{seed}")
    cfg = dict(pool_id="0xtok:QRDX", max_depth=12, maker_fee_rate=D("0.0002"),
               taker_fee_rate=D("0.0005"), self_trade_action=SelfTradeAction(stp),
               max_orders_per_address=40)
    py = OrderBook(**cfg)
    nb = N.NativeBook("0xtok:QRDX", 12, "0.0002", "0.0005", stp, str(py.min_order_size), 40)
    now = 1_700_000_000.0
    height = 1
    ops = 0
    for i in range(700):
        k = rng.random()
        if k < 0.55:
            d = _new_order(rng, i, now)
            protocol = rng.random() < 0.1
            makers = rng.choice([None, None, None, 1, 2, 5])
            box = {}

            def place_py(d=d, protocol=protocol, makers=makers):
                o = _py_order(d)
                budget = None if makers is None else MatchBudget(makers)
                trades = py.place_order(o, protocol=protocol, budget=budget)
                used = None if budget is None else (budget.visited, budget.exhausted)
                return [_trade_dict(t) for t in trades], _order_dict(o), used

            a, b = _both(py, nb, place_py,
                         lambda d=d, protocol=protocol, makers=makers: nb.place_order(
                             d, protocol, makers))
            if a[0] == "ok":
                b = ("ok", (list(b[1][0]), b[1][1], b[1][2])) if b[0] == "ok" else b
            assert a == b, f"op {i}: place {d}"
            box.clear()
        elif k < 0.7:
            resting = list(py._orders) + list(py._stop_orders)
            oid = rng.choice(resting) if resting and rng.random() < 0.9 else f"o{rng.randint(0, i)}"
            order = py.get_order(oid)
            caller = rng.choice([order.owner if order else "", rng.choice(OWNERS), ""])
            a, b = _both(py, nb,
                         lambda: (lambda o: None if o is None else _order_dict(o))(
                             py.cancel_order(oid, caller)),
                         lambda: nb.cancel_order(oid, caller))
            assert a == b, f"op {i}: cancel {oid} by {caller}"
        elif k < 0.78 and py._orders:
            oid = rng.choice(list(py._orders))
            o = py._orders[oid]
            amount = rng.choice([o.amount - D("0.01"), o.filled + D("0.01"), o.amount,
                                 o.amount / 2, D("0.001")])
            caller = rng.choice([o.owner, o.owner, rng.choice(OWNERS)])
            a, b = _both(py, nb, lambda: _order_dict(py.reduce_order(oid, amount, caller)),
                         lambda: nb.reduce_order(oid, str(amount), caller))
            assert a == b, f"op {i}: reduce {oid} to {amount}"
        elif k < 0.86 and py._orders:
            oid = rng.choice(list(py._orders))
            o = py._orders[oid]
            amount = rng.choice([o.remaining, o.remaining / 3, D("0.01"), o.remaining + 1, D(0)])
            a, b = _both(py, nb, lambda: _order_dict(py.fill_resting(oid, amount)),
                         lambda: nb.fill_resting(oid, str(amount)))
            assert a == b, f"op {i}: fill {oid} by {amount}"
        elif k < 0.9:
            price = _price(rng)
            py.record_price(D(price))
            nb.record_price(price)
        elif k < 0.97:
            height += 1
            now += rng.choice([1.0, 60.0, 200.0])
            py.enter_block(height, now)
            nb.enter_block(height, now)
        elif rng.random() < 0.3:
            py.pause(), nb.pause()
        if py.is_paused and rng.random() < 0.5:
            py.unpause(), nb.unpause()
        _compare_books(py, nb)
        ops += 1
    assert py.total_trades > 20, "the run traded"


def test_a_copy_is_independent_of_its_book():
    nb = N.NativeBook("p", 50, "0", "0", "cancel_taker", "0.00000001", 200)
    nb.place_order({"id": "a", "owner": "0xPQa", "side": "sell", "order_type": "limit",
                    "price": "1", "amount": "5", "timestamp": 1.0}, True, None)
    twin = nb.copy()
    nb.place_order({"id": "b", "owner": "0xPQb", "side": "buy", "order_type": "limit",
                    "price": "1", "amount": "5", "timestamp": 1.0}, True, None)
    assert nb.level_prices(False) == [] and twin.level_prices(False) == ["1"]
    assert twin.state_digest() != nb.state_digest()


def test_a_failed_placement_leaves_the_book_as_it_was():
    nb = N.NativeBook("p", 50, "0", "0", "cancel_taker", "0.00000001", 200)
    nb.place_order({"id": "a", "owner": "0xPQa", "side": "sell", "order_type": "limit",
                    "price": "1", "amount": "2", "timestamp": 1.0}, True, None)
    before = nb.state_digest()
    with pytest.raises(ValueError, match="fill-or-kill"):
        nb.place_order({"id": "b", "owner": "0xPQb", "side": "buy", "order_type": "limit",
                        "price": "1", "amount": "5", "timestamp": 1.0, "tif": "fok"}, True, None)
    assert nb.state_digest() == before and nb.level_prices(False) == ["1"]
