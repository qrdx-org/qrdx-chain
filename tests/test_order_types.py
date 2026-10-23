"""
Order types: time in force (good-till-cancelled, immediate-or-cancel, fill-or-kill, post-only)
and orders that show less than they hold (hidden, iceberg) — qrdx/exchange/orderbook.py.

Priority within a price level has two tiers: every displayed quantity in time order (an
iceberg's current slice), then every hidden one (an iceberg's reserve, a hidden order). An
iceberg whose slice is used up shows its next one from the back of the level. Depth, best
bid/ask and the mark price read displayed quantities only; matching reaches everything. The
router quotes in the same priority, so a quote is still exactly what executes.
"""

import copy
import random
from decimal import Decimal as D

import pytest

from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction, undo
from qrdx.exchange.orderbook import (
    Order,
    OrderBook,
    OrderSide,
    OrderStatus,
    OrderType,
    SelfTradeAction,
)
from qrdx.exchange.router import UnifiedRouter
from qrdx.exchange.transactions import EXCHANGE_GAS_COSTS, EXCHANGE_GAS_PER_MAKER

BUY, SELL = OrderSide.BUY, OrderSide.SELL


def _o(oid, owner, side, amount, price, *, tif="gtc", hidden=False, display=0, kind=None):
    return Order(
        id=oid,
        owner=owner,
        side=side,
        order_type=kind or OrderType.LIMIT,
        price=D(price),
        amount=D(amount),
        nonce=0,
        timestamp=0.0,
        tif=tif,
        hidden=hidden,
        display_size=D(display),
    )


def _book():
    return OrderBook(
        pool_id="AAA:BBB",
        self_trade_action=SelfTradeAction.CANCEL_TAKER,
        max_orders_per_address=10_000,
    )


def _fills(trades):
    return [(t.maker_order_id, t.amount) for t in trades]


# ── priority ────────────────────────────────────────────────────────────────


def test_displayed_quantity_fills_before_hidden_quantity_and_icebergs_refresh_at_the_back():
    book = _book()
    book.place_order(_o("plain", "a", SELL, "1", "100"))
    book.place_order(_o("hidden", "b", SELL, "5", "100", hidden=True))
    book.place_order(_o("ice", "c", SELL, "10", "100", display="2"))
    book.place_order(_o("late", "d", SELL, "1", "100"))
    assert book.get_asks(5) == [(D(100), D(4))]  # 1 + a slice of 2 + 1

    # Displayed first, in time order — the hidden order placed earlier waits.
    trades = book.place_order(_o("t1", "x", BUY, "4", "100"))
    assert _fills(trades) == [("plain", D(1)), ("ice", D(2)), ("late", D(1))]
    ice = book.get_order("ice")
    assert ice.shown == D(2) and ice.remaining == D(8)  # a new slice…
    assert [o.id for o in book._asks[D(100)].orders] == ["hidden", "ice"]  # …from the back

    # Then the new slice, then hidden quantities in time order (the iceberg's reserve after
    # the hidden order: its refresh put it behind).
    trades = book.place_order(_o("t2", "x", BUY, "10", "100"))
    assert _fills(trades) == [("ice", D(2)), ("hidden", D(5)), ("ice", D(3))]
    assert book.get_order("ice").remaining == D(3) and book.get_order("ice").shown == D(2)
    assert book.get_asks(5) == [(D(100), D(2))]


def test_hidden_orders_are_matched_but_never_shown():
    book = _book()
    book.place_order(_o("h", "a", SELL, "5", "99", hidden=True))
    book.place_order(_o("p", "b", SELL, "1", "101"))
    assert book.best_ask == D(101) and book.get_asks(5) == [(D(101), D(1))]
    assert book.ask_depth == 1
    trades = book.place_order(_o("t", "x", BUY, "2", "101"))
    assert _fills(trades) == [("h", D(2))]  # the better hidden price first
    assert book.get_order("h").remaining == D(3)


def test_the_book_view_shows_displayed_quantities_and_the_owner_sees_everything():
    from qrdx.exchange import views

    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    book = _book()
    m._order_books["AAA:BBB"] = book
    book.place_order(_o("h", "0xPQa", SELL, "5", "100", hidden=True))
    book.place_order(_o("i", "0xPQb", SELL, "10", "100", display="2"))
    book.place_order(_o("p", "0xPQc", SELL, "1", "100"))
    l3 = views._levels(book._asks, False, 10, True, lambda o: o.owner)
    assert l3[0]["amount"] == "3" and [o["order_id"] for o in l3[0]["orders"]] == ["i", "p"]
    ice_row = l3[0]["orders"][0]
    assert ice_row["remaining"] == "2" and "amount" not in ice_row  # its size is held back
    own = views.spot_open_orders(m, "0xPQb")
    assert own[0]["remaining"] == "10" and own[0]["display_size"] == "2"
    assert views.spot_open_orders(m, "0xPQa")[0]["hidden"] is True
    ExchangeStateManager.reset_instance()


# ── time in force ───────────────────────────────────────────────────────────


def test_post_only_rests_when_it_would_not_match_and_changes_nothing_when_it_would():
    book = _book()
    book.place_order(_o("h", "a", SELL, "1", "100", hidden=True))  # crossing, but hidden
    before, nonces = book.state_digest(), dict(book._owner_nonces)
    counts = dict(book._block_order_count)
    with pytest.raises(ValueError, match="post-only"):
        book.place_order(_o("alo", "x", BUY, "1", "100", tif="alo"))
    assert book.state_digest() == before and dict(book._owner_nonces) == nonces
    assert dict(book._block_order_count) == counts  # not even the rate limit counted
    assert book.place_order(_o("alo2", "x", BUY, "1", "99.5", tif="alo")) == []
    assert book.get_order("alo2").is_active


def test_fill_or_kill_fills_whole_or_leaves_the_book_as_it_was_wherever_it_is_placed_from():
    book = _book()
    for i in range(3):
        book.place_order(_o(f"a{i}", f"m{i}", SELL, "1", 100 + i))
    before = book.state_digest()
    assert undo.active() is None  # no caller scope to rely on
    with pytest.raises(ValueError, match="fill-or-kill"):
        book.place_order(_o("fok", "x", BUY, "4", "105", tif="fok"))
    assert book.state_digest() == before and book.get_order("a0").filled == 0
    trades = book.place_order(_o("fok2", "x", BUY, "3", "105", tif="fok"))
    assert sum(t.amount for t in trades) == 3 and book.get_order("fok2") is None


def test_immediate_or_cancel_never_rests():
    book = _book()
    book.place_order(_o("a", "m", SELL, "1", "100"))
    taker = _o("ioc", "x", BUY, "3", "100", tif="ioc")
    assert sum(t.amount for t in book.place_order(taker)) == 1
    assert book.get_order("ioc") is None and taker.status == OrderStatus.FILLED
    assert book.best_bid is None


@pytest.mark.parametrize(
    "order, error",
    [
        (_o("x", "x", BUY, "1", "1", tif="day"), "time in force"),
        (_o("x", "x", BUY, "1", "0", tif="alo", kind=OrderType.MARKET), "post-only"),
        (_o("x", "x", BUY, "1", "1", tif="ioc", hidden=True), "resting limit"),
        (_o("x", "x", BUY, "5", "1", hidden=True, display="1"), "hidden or an iceberg"),
        (_o("x", "x", BUY, "5", "1", display="5"), "display size"),
    ],
)
def test_order_options_that_make_no_sense_are_refused(order, error):
    with pytest.raises(ValueError, match=error):
        _book().place_order(order)


def test_hidden_and_iceberg_fields_are_part_of_the_books_commitment():
    digests = set()
    for kw in ({}, {"hidden": True}, {"display": "1"}, {"display": "2"}):
        book = _book()
        book.place_order(_o("a", "m", SELL, "5", "100", **kw))
        digests.add(book.state_digest())
        assert book.cached_digest() == book.state_digest()
    assert len(digests) == 4


# ── random books: invariants, the router's quotes, undo ─────────────────────


def _random_order(rng, n, owners):
    side = rng.choice([BUY, SELL])
    kind = rng.random()
    kw = {}
    if kind < 0.2:
        kw["hidden"] = True
    elif kind < 0.4:
        kw["display"] = str(rng.randint(1, 3))
    tif = rng.choice(["gtc"] * 5 + ["ioc", "fok", "alo"])
    if tif in ("ioc", "fok"):
        kw = {}
    amount = rng.randint(1, 9) if not kw.get("display") else rng.randint(int(kw["display"]) + 1, 12)
    return _o(
        f"o{n}", rng.choice(owners), side, str(amount), str(rng.randint(95, 105)), tif=tif, **kw
    )


def _random_ops(rng, book, start, count, owners):
    n = start
    for _ in range(count):
        n += 1
        if rng.random() < 0.2 and book._orders:
            oid = rng.choice(sorted(book._orders))
            book.cancel_order(oid, caller=book._orders[oid].owner)
            continue
        try:
            book.place_order(_random_order(rng, n, owners))
        except ValueError:
            pass
        _check_invariants(book)
    return n


def _check_invariants(book):
    for levels in (book._bids, book._asks):
        for price, level in levels.items():
            assert level.visible_amount <= level.total_amount
            for o in level.orders:
                if o.is_iceberg and o.is_active:
                    assert D(0) < o.shown <= o.display_size and o.visible <= o.remaining
                assert o.tif in ("gtc", "alo")  # nothing else ever rests


@pytest.mark.parametrize("seed", range(25))
def test_the_routers_quote_is_exactly_what_executes_with_hidden_and_iceberg_orders(seed):
    rng = random.Random(seed)
    book = _book()
    _random_ops(rng, book, 0, 80, [f"0xPQ{i}" for i in range(6)])
    router = UnifiedRouter()
    router.register_order_book("AAA:BBB", book)
    for k in range(10):
        selling = rng.random() < 0.5
        token_in, token_out = ("AAA", "BBB") if selling else ("BBB", "AAA")
        amount = D(rng.randint(1, 40)) if selling else D(rng.randint(50, 4000))
        route = router.clob_route(token_in, token_out, amount, sender=f"taker{k}")
        if route is None:
            continue
        result = router.apply_route(route, f"taker{k}")  # raises if the fill differs
        got = sum((t.amount if not selling else t.amount * t.price) for t in result.trades)
        assert got == route.amount_out
        _check_invariants(book)


@pytest.mark.parametrize("seed", range(15))
def test_a_book_with_hidden_and_iceberg_orders_rolls_back_exactly(seed):
    rng = random.Random(seed)
    owners = [f"0xPQ{i}" for i in range(5)]
    book = _book()
    n = _random_ops(rng, book, 0, 60, owners)
    book.cached_digest()
    twin = copy.deepcopy(book)
    before = book.state_digest()
    with pytest.raises(KeyError):
        with undo.atomic():
            _random_ops(rng, book, n, 40, owners)
            raise KeyError()
    assert book.state_digest() == before == book.cached_digest()
    rng_a, rng_b = random.Random(seed + 1), random.Random(seed + 1)
    _random_ops(rng_a, book, 1000, 40, owners)
    _random_ops(rng_b, twin, 1000, 40, owners)
    assert book.state_digest() == twin.state_digest()


# ── through the operations ──────────────────────────────────────────────────

MID = "BTC-QRDX-PERP"


@pytest.fixture
def perps():
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.begin_block(1, 1_700_000_000.0)
    ch = m.clearinghouse
    ch.create_market("BTC")
    ch.set_oracle_price(MID, D(100))
    for o in ("maker", "taker", "other"):
        ch.deposit(o, D(10**6))
    yield m
    ExchangeStateManager.reset_instance()


def _perp(m, sender, nonce, **params):
    params = {"market_id": MID, **{k: v for k, v in params.items()}}
    return m.process_transaction(
        ExchangeTransaction(
            op_type=ExchangeOpType.PERP_ORDER,
            sender=sender,
            nonce=nonce,
            gas_limit=10**6,
            params=params,
        )
    )


def test_a_perp_fill_or_kill_that_cannot_fill_changes_nothing_and_pays_for_its_visits(perps):
    m, ch = perps, perps.clearinghouse
    for i in range(5):
        assert _perp(m, "maker", i, side="sell", size="1", price=str(100 + i)).success
    before, root = ch.canonical(), ch.commitment()
    r = _perp(m, "taker", 0, side="buy", size="6", price="110", tif="fok")
    assert not r.success and "fill-or-kill" in r.error
    assert r.gas_used == EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_ORDER] + 5 * EXCHANGE_GAS_PER_MAKER
    assert ch.canonical() == before and ch.commitment() == root
    r = _perp(m, "taker", 1, side="buy", size="5", price="110", tif="fok")
    assert r.success and not r.data["resting"] and len(r.data["fills"]) == 5
    assert ch.accounts["taker"].positions[MID].size == D(5)


def test_perp_post_only_hidden_and_iceberg_orders(perps):
    m, ch = perps, perps.clearinghouse
    assert _perp(m, "maker", 0, side="sell", size="3", price="101", hidden=True).success
    assert _perp(m, "maker", 1, side="sell", size="4", price="102", display_size="1").success
    book = ch.markets[MID].book
    assert book.get_asks(5) == [(D(102), D(1))]
    r = _perp(m, "other", 0, side="buy", size="1", price="101", tif="alo")
    assert not r.success and "post-only" in r.error  # the hidden ask is there
    r = _perp(m, "taker", 0, side="buy", size="5", price="102")
    assert r.success and sum(D(f["amount"]) for f in r.data["fills"]) == 5
    assert ch.accounts["taker"].positions[MID].size == D(5)
    assert ch.accounts["maker"].positions[MID].size == D(-5)
    r = _perp(m, "other", 1, side="buy", size="1", price="101", hidden="false")
    assert not r.success and "true or false" in r.error


def test_an_unknown_time_in_force_is_refused_not_treated_as_good_till_cancelled(perps):
    r = _perp(perps, "maker", 0, side="sell", size="1", price="100", tif="day")
    assert not r.success and "time in force" in r.error
    assert not perps.clearinghouse.markets[MID].orders


def test_a_spot_ioc_remainder_is_not_escrowed_and_a_hidden_order_escrows_whole(no_trading_fees):
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager()
    m.enforce_orderbook_settlement = True
    pair = "TKA:TKB"
    m._order_books[pair] = OrderBook(pool_id=pair)
    m.begin_block(1, 0.0)
    escrow = m.orderbook_escrow_address(pair)
    for who in ("0xPQm", "0xPQt", escrow):
        m.set_available_token_balance(who, "TKA", D(100))
        m.set_available_token_balance(who, "TKB", D(10_000))

    def place(sender, nonce, **params):
        return m.process_transaction(
            ExchangeTransaction(
                op_type=ExchangeOpType.PLACE_ORDER,
                sender=sender,
                nonce=nonce,
                gas_limit=10**6,
                params={"pair": pair, "order_type": "limit", **params},
            )
        )

    assert place("0xPQm", 0, side="sell", price="5", amount="10", hidden=True).success
    assert m.token_balance_deltas()[(escrow, "TKA")] == D(10)
    r = place("0xPQt", 0, side="buy", price="5", amount="12", tif="ioc")
    assert r.success and r.data["filled"] == "10"
    d = m.token_balance_deltas()
    assert d[("0xPQt", "TKB")] == D(-50) and d.get((escrow, "TKB"), 0) == 0  # none held back
    assert d[("0xPQt", "TKA")] == D(10)


def _perp_ops(rng, ch, start, count, owners):
    from qrdx.exchange.clearinghouse import ClearinghouseError

    n = start
    for _ in range(count):
        n += 1
        owner = rng.choice(owners)
        r = rng.random()
        try:
            if r < 0.15:
                mine = [
                    oid for oid, meta in ch.markets[MID].orders.peek_items() if meta.owner == owner
                ]
                if mine:
                    ch.cancel_order(owner, MID, rng.choice(sorted(mine)))
            elif r < 0.2:
                ch.set_oracle_price(MID, D(rng.randint(90, 110)))
            else:
                tif = rng.choice(["gtc"] * 4 + ["ioc", "fok", "alo"])
                kw = {}
                if tif in ("gtc", "alo") and rng.random() < 0.4:
                    kw = {"hidden": True} if rng.random() < 0.5 else {"display_size": D(1)}
                ch.place_order(
                    owner,
                    MID,
                    f"p{n}",
                    rng.choice(["buy", "sell"]),
                    D(rng.randint(2, 9)),
                    D(rng.randint(95, 105)),
                    n,
                    tif=tif,
                    **kw,
                )
        except (ClearinghouseError, ValueError):
            pass
        _check_invariants(ch.markets[MID].book)
    return n


@pytest.mark.parametrize("seed", range(12))
def test_a_clearinghouse_with_every_order_type_rolls_back_exactly(seed, perps):
    ch = perps.clearinghouse
    owners = ["maker", "taker", "other"]
    rng = random.Random(seed)
    n = _perp_ops(rng, ch, 0, 60, owners)
    twin = copy.deepcopy(ch)
    before, root = ch.canonical(), ch.commitment()
    with pytest.raises(KeyError):
        with undo.atomic():
            _perp_ops(rng, ch, n, 40, owners)
            raise KeyError()
    assert ch.canonical() == before and ch.commitment() == root
    ch.verify_commitment()
    rng_a, rng_b = random.Random(seed + 3), random.Random(seed + 3)
    _perp_ops(rng_a, ch, 5000, 40, owners)
    _perp_ops(rng_b, twin, 5000, 40, owners)
    assert ch.canonical() == twin.canonical() and ch.identity_gap() == 0
