"""
A spot book held natively (qrdx/exchange/native_book.py over native/qrdx-native/src/book.rs) is the
Python book (qrdx/exchange/orderbook.py), through the Python book's own interface.

Both get the same random operations — limit, market and stop orders in every time in force, hidden
and iceberg orders, one price in several spellings, budgets of makers, the protocol's own orders,
cancels by the owner and by others, reductions, fills by a plan, prices recorded from a pool, new
blocks, pauses — under each self-trade rule, some inside undo scopes made to fail, with deep copies
and pickles taken along the way. After each step: the same result (trades, the order as it ended,
the error, the makers its budget visited), every view (the best prices, each level's queue, the
resting and stop orders, the owners' counts and nonces, the history, the levels as displayed), the
same digest incremental and in full, the same level tree, and every ``Order`` object handed out
earlier showing what the Python book's object shows.
"""

import copy
import pickle
import random
from decimal import Decimal as D

import pytest

pytest.importorskip("qrdx_native")

from qrdx.exchange import commitment, native_book, undo  # noqa: E402
from qrdx.exchange.native_book import NativeSpotBook  # noqa: E402
from qrdx.exchange.orderbook import (  # noqa: E402
    MatchBudget,
    Order,
    OrderBook,
    OrderSide,
    OrderType,
    SelfTradeAction,
)
from qrdx.snapshot import safe_loads  # noqa: E402
from qrdx.crypto import smt  # noqa: E402

OWNERS = [f"0xPQ{i:064x}" for i in range(1, 6)]
SPELLINGS = {D("1.00"): ["1", "1.0", "1.00", "10E-1"], D("1.05"): ["1.05", "1.050"]}


def _od(o):
    return None if o is None else (
        o.id, o.owner, o.side.value, o.order_type.value, str(o.price), str(o.amount),
        str(o.filled), o.status.value, o.timestamp,
        None if o.stop_price is None else str(o.stop_price), o.nonce, o.expire_time, o.tif,
        o.hidden, str(o.display_size), str(o.shown))


def _td(t):
    return (t.id, t.maker_order_id, t.taker_order_id, str(t.price), str(t.amount),
            str(t.maker_fee), str(t.taker_fee), t.buyer, t.seller, t.sequence)


def _price(rng):
    if rng.random() < 0.25:
        return rng.choice(SPELLINGS[rng.choice(list(SPELLINGS))])
    return str(D(rng.randint(90, 112)) / D(100))


def _new_order(rng, i, now):
    kind = rng.choices(["limit", "market", "stop_loss"], [0.75, 0.15, 0.1])[0]
    tif = rng.choices(["gtc", "ioc", "fok", "alo", "day"], [0.6, 0.12, 0.1, 0.15, 0.03])[0]
    if kind != "limit" and tif == "alo" and rng.random() < 0.7:
        tif = "gtc"
    hidden = kind == "limit" and rng.random() < 0.08
    display = "0"
    if kind == "limit" and not hidden and rng.random() < 0.12:
        display = str(D(rng.randint(1, 1500)) / D(100))
    return Order(
        id=f"o{i}", owner=rng.choice(OWNERS), side=OrderSide(rng.choice(["buy", "sell"])),
        order_type=OrderType(kind), price=D(_price(rng) if kind != "market" else "0"),
        amount=D(rng.randint(1, 4000)) / D(100), timestamp=1.0,
        stop_price=D(_price(rng)) if kind == "stop_loss" else None,
        nonce=rng.choice([0, 0, rng.randint(1, 50)]),
        expire_time=rng.choice([0.0, 0.0, 0.0, now + rng.choice([-5.0, 30.0, 300.0])]),
        tif=tif, hidden=hidden, display_size=D(display))


def _views(book):
    out = [book.best_bid, book.best_ask, book.level_prices(True), book.level_prices(False),
           list(book.iter_levels(True)), list(book.iter_levels(False)), book.get_bids(3),
           book.get_asks(3), book.last_price, str(book.total_volume), book.total_trades,
           book._trade_sequence, book.is_paused, book.has_expiring, book.header(),
           sorted(dict(book._nonces().peek_items()).items()),
           [_td(t) for t in book.get_recent_trades(20)], len(book._orders), len(book._bids),
           len(book._asks)]
    for bids in (True, False):
        side = book._bids if bids else book._asks
        for p in book.level_prices(bids):
            level = side[p]
            out.append((str(level.price), [_od(o) for o in level.orders],
                        str(level.total_amount), str(level.visible_amount),
                        [(o.id, str(a)) for o, a in OrderBook.fill_queue(level)]))
    out.append(sorted(_od(book._orders[i]) for i in book._orders))
    out.append([_od(book._stop_orders[i]) for i in book._stop_orders])
    out.append([(w, book._owner_order_count.get(w)) for w in OWNERS])
    return out


def _check(py, nb):
    assert _views(nb) == _views(py)
    assert nb.cached_digest() == py.cached_digest() == py.state_digest() == nb.state_digest()
    assert smt.m_root(nb.level_tree) == smt.m_root(py.level_tree)


def _run(book, op):
    """``op`` on ``book`` inside an undo scope, as an exchange operation runs it: (outcome)."""
    try:
        with undo.atomic():
            return ("ok", op(book))
    except ValueError as e:
        return ("error", str(e))


@pytest.mark.parametrize("stp", ["cancel_taker", "cancel_maker", "cancel_both", "reject"])
@pytest.mark.parametrize("seed", range(5))
def test_random_operations_run_as_python_runs_them(stp, seed, monkeypatch):
    monkeypatch.setattr(native_book, "available", lambda: True)  # (whatever QRDX_NATIVE_BOOK)
    monkeypatch.setattr(commitment, "_TREES", seed % 2 == 0)  # (proof trees on and off)
    rng = random.Random(f"{stp}-{seed}")
    cfg = dict(pool_id="0xtok:QRDX", max_depth=12, self_trade_action=SelfTradeAction(stp),
               max_orders_per_address=40)
    py, nb = OrderBook(**cfg), NativeSpotBook(**cfg)
    held = []  # (the Python book's order object, the native one's) handed out earlier
    now, height = 1_700_000_000.0, 1
    for i in range(500):
        k = rng.random()
        failed = False
        if k < 0.5:
            d = _new_order(rng, i, now)
            protocol = rng.random() < 0.1
            makers = rng.choice([None, None, None, 1, 2, 5])
            orders = (copy.copy(d), copy.copy(d))

            def place(book, which):
                o = orders[which]
                budget = None if makers is None else MatchBudget(makers)
                try:
                    trades = book.place_order(o, protocol=protocol, budget=budget)
                except ValueError as e:
                    return ("refused", str(e), budget and budget.visited)
                return ([_td(t) for t in trades], _od(o),
                        budget and (budget.visited, budget.left, budget.exhausted))

            a, b = _run(py, lambda bk: place(bk, 0)), _run(nb, lambda bk: place(bk, 1))
            assert a == b, f"op {i}: place {_od(d)}"
            failed = a[0] == "error" or a[1][0] == "refused"
            if not failed and rng.random() < 0.3:
                held.append(orders)
        elif k < 0.62:
            ids = list(py._orders) + list(py._stop_orders)
            oid = rng.choice(ids) if ids and rng.random() < 0.9 else f"o{rng.randint(0, i)}"
            o = py.get_order(oid)
            caller = rng.choice([o.owner if o else "", rng.choice(OWNERS), ""])
            a = _run(py, lambda bk: _od(bk.cancel_order(oid, caller)))
            b = _run(nb, lambda bk: _od(bk.cancel_order(oid, caller)))
            assert a == b, f"op {i}: cancel {oid}"
            failed = a[0] == "error"
        elif k < 0.7 and py._orders:
            oid = rng.choice(list(py._orders))
            o = py._orders[oid]
            amount = rng.choice([o.amount - D("0.01"), o.filled + D("0.01"), o.amount, D("0.001")])
            caller = rng.choice([o.owner, o.owner, rng.choice(OWNERS)])
            a = _run(py, lambda bk: _od(bk.reduce_order(oid, amount, caller)))
            b = _run(nb, lambda bk: _od(bk.reduce_order(oid, amount, caller)))
            assert a == b, f"op {i}: reduce {oid}"
            failed = a[0] == "error"
        elif k < 0.78 and py._orders:
            oid = rng.choice(list(py._orders))
            o = py._orders[oid]
            amount = rng.choice([o.remaining, o.remaining / 3, D("0.01"), o.remaining + 1, D(0)])
            if rng.random() < 0.5:  # (an order handed out first, then filled: it shows it)
                held.append((py.get_order(oid), nb.get_order(oid)))
            a = _run(py, lambda bk: _od(bk.fill_resting(oid, amount)))
            b = _run(nb, lambda bk: _od(bk.fill_resting(oid, amount)))
            assert a == b, f"op {i}: fill {oid}"
            failed = a[0] == "error"
        elif k < 0.82:
            price = D(_price(rng))
            py.record_price(price), nb.record_price(price)
        elif k < 0.88:
            height += 1
            now += rng.choice([1.0, 60.0, 200.0])
            py.enter_block(height, now), nb.enter_block(height, now)
        elif k < 0.91:
            # a scope that fails after changing the book: both books as they were
            d = _new_order(rng, 10_000 + i, now)
            for book, o in ((py, copy.copy(d)), (nb, copy.copy(d))):
                with pytest.raises(RuntimeError):
                    with undo.atomic():
                        try:
                            book.place_order(o, protocol=True)
                        except ValueError:
                            pass
                        raise RuntimeError("the operation fails later")
            held = []  # (handed out before a rollback: see NativeSpotBook._keep)
        elif k < 0.94:
            py, nb = copy.deepcopy(py), copy.deepcopy(nb)
            held = []  # (a copy's orders are its own objects)
        elif k < 0.96:
            blob, way = pickle.dumps(nb), rng.random()
            if way < 0.4:
                py = safe_loads(pickle.dumps(py))
            elif way < 0.7:  # (the reference from now on: the native book, loaded without them)
                with monkeypatch.context() as m:
                    m.setattr(native_book, "available", lambda: False)
                    py = safe_loads(blob)
                assert type(py) is OrderBook
            nb = safe_loads(blob)
            if way >= 0.7:  # (the native book from now on: the Python book, made native)
                py = safe_loads(pickle.dumps(py))
                nb = native_book.as_spot_book(copy.deepcopy(py))
            assert type(nb) is NativeSpotBook
            held = []
        elif rng.random() < 0.3:
            py.pause(), nb.pause()
        if py.is_paused and rng.random() < 0.5:
            py.unpause(), nb.unpause()
        if failed:
            held = []
        _check(py, nb)
        # Every order handed out shows what the book did to it — as long as no operation
        # failed since: a failed one restores copies of the levels it touched in a Python book
        # (detaching the orders handed out there), where a native book detaches them all on a
        # rollback. No caller holds an order across a failure (native_book.py, "Undo").
        for a, b in held[-30:]:
            assert _od(a) == _od(b), "an order handed out shows what the book did to it"
    assert py.total_trades > 20, "the run traded"


def test_a_native_book_runs_no_maker_guard():
    nb = NativeSpotBook(pool_id="p")
    nb.maker_guard = None
    with pytest.raises(TypeError):
        nb.maker_guard = lambda maker, amount: True


@pytest.mark.parametrize("way", ["pickled", "to_python", "to_native"])
def test_the_per_block_limit_holds_across_a_pickle_and_a_conversion(way, monkeypatch):
    """An owner's orders in the block count toward its limit (50) as the Python book counts them,
    and the count survives a pickle, a load without native books and a conversion to native."""
    monkeypatch.setattr(native_book, "available", lambda: True)
    cfg = dict(pool_id="p", max_orders_per_address=1000)
    py, nb = OrderBook(**cfg), NativeSpotBook(**cfg)
    py.enter_block(1, 1.0), nb.enter_block(1, 1.0)
    results = []
    for i in range(55):
        if i == 30:
            blob = pickle.dumps(nb)
            if way == "pickled":
                py, nb = safe_loads(pickle.dumps(py)), safe_loads(blob)
            elif way == "to_python":
                with monkeypatch.context() as m:
                    m.setattr(native_book, "available", lambda: False)
                    py = safe_loads(blob)
            else:
                nb = native_book.as_spot_book(copy.deepcopy(py))
        out = []
        for book in (py, nb):
            o = Order(id=f"o{i}", owner=OWNERS[0], side=OrderSide.SELL, order_type=OrderType.LIMIT,
                      price=D(1) + D(i) / D(1000), amount=D(1), timestamp=1.0)
            try:
                book.place_order(o)
                out.append("ok")
            except ValueError as e:
                out.append(str(e))
        assert out[0] == out[1], f"order {i}"
        results.append(out[0])
        _check(py, nb)
    assert results.count("ok") == 50 and results[-1].startswith("Rate limit")
    py.enter_block(2, 2.0), nb.enter_block(2, 2.0)  # (a new block: a new count)
    _check(py, nb)
