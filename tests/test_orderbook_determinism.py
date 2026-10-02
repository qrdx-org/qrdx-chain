"""
The order book as consensus state (docs/KNOWN_ISSUES.md, "Spot exchange: …").

* The state root used to commit a book only as (trades, volume, bid levels, ask levels): two
  nodes could hold different resting orders — owners, sizes, time priority — under one root.
* Every book kept its whole trade history in memory, and each order deep-copied it (the
  all-or-nothing wrapper), so a long-running node grew without bound and slowed with every
  trade. The history is now bounded and display-only; the stop trigger reads ``last_price``.
* Expiry was judged by the wall clock; it is now the block time ``new_block`` is given.
* Matching ran in the caller's Decimal context; it is now pinned.
"""
from decimal import Decimal, localcontext

import pytest

from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import orderbook as OB
from qrdx.exchange.orderbook import Order, OrderBook, OrderSide, OrderType, SelfTradeAction
from qrdx.exchange.router import UnifiedRouter

D = Decimal
ALICE, BOB, CAROL = ("0xPQ" + c * 64 for c in "abc")
T0, T1 = "0x" + "11" * 20, "0x" + "22" * 20


def _order(oid, owner, side, price, amount, nonce=0, **kw):
    return Order(id=oid, owner=owner, side=side, order_type=OrderType.LIMIT, price=D(price),
                 amount=D(amount), nonce=nonce, **kw)


def _book():
    return OrderBook(pool_id=f"{T0}:{T1}", self_trade_action=SelfTradeAction.CANCEL_TAKER)


def test_the_digest_commits_owners_sizes_and_time_priority():
    """Same totals, same level counts — the old commitment could not tell these apart."""
    a, b, c = _book(), _book(), _book()
    a.place_order(_order("1", ALICE, OrderSide.BUY, "1", "5"))
    a.place_order(_order("2", BOB, OrderSide.BUY, "1", "7"))
    b.place_order(_order("2", BOB, OrderSide.BUY, "1", "7"))         # same orders, other priority
    b.place_order(_order("1", ALICE, OrderSide.BUY, "1", "5"))
    c.place_order(_order("1", CAROL, OrderSide.BUY, "1", "5"))       # another owner
    c.place_order(_order("2", BOB, OrderSide.BUY, "1", "7"))
    old = lambda bk: (bk.total_trades, bk.total_volume, bk.bid_depth, bk.ask_depth)
    assert old(a) == old(b) == old(c)
    assert len({a.state_digest(), b.state_digest(), c.state_digest()}) == 3
    d = _book()
    d.place_order(_order("1", ALICE, OrderSide.BUY, "1", "5"))
    d.place_order(_order("2", BOB, OrderSide.BUY, "1", "7"))
    assert d.state_digest() == a.state_digest()


def test_the_exchange_root_commits_the_book():
    ExchangeStateManager.reset_instance()
    try:
        m = ExchangeStateManager.get_instance()
        book = OrderBook(pool_id=f"{T0}:{T1}", self_trade_action=SelfTradeAction.CANCEL_TAKER)
        m._order_books[book.pool_id] = book
        before = m.compute_state_root()
        book.place_order(_order("1", ALICE, OrderSide.BUY, "1", "5"))
        mid = m.compute_state_root()
        book._orders["1"].amount = D(6)                    # a node whose order differs
        assert len({before, mid, m.compute_state_root()}) == 3
    finally:
        ExchangeStateManager.reset_instance()


def test_trade_history_is_bounded_and_the_stop_trigger_survives_it(monkeypatch):
    monkeypatch.setattr(OB, "MAX_RECENT_TRADES", 10)
    book = _book()
    for i in range(25):
        book.place_order(_order(f"a{i}", ALICE, OrderSide.SELL, "2", "1"))
        book.place_order(_order(f"b{i}", BOB, OrderSide.BUY, "2", "1"))
    assert book.total_trades == 25 and len(book._trades) == 10
    assert book.last_price == D(2)
    assert [t.sequence for t in book.get_recent_trades(3)] == [23, 24, 25]
    # a sell stop at 2 triggers off the last price even though the history has wrapped
    book.place_order(_order("s", CAROL, OrderSide.BUY, "1.5", "1"))
    stop = Order(id="stop", owner=BOB, side=OrderSide.SELL, order_type=OrderType.STOP_LOSS,
                 price=D(0), amount=D(1), stop_price=D(2))
    book.place_order(stop)
    book.place_order(_order("a-last", ALICE, OrderSide.SELL, "1.5", "0.5"))  # trades at 1.5
    assert "stop" not in book._stop_orders


def test_snapshot_restores_the_book_without_deep_copying_history():
    book = _book()
    for i in range(5):
        book.place_order(_order(f"a{i}", ALICE, OrderSide.SELL, "2", "1"))
        book.place_order(_order(f"b{i}", BOB, OrderSide.BUY, "2", "1"))
    book.place_order(_order("rest", ALICE, OrderSide.SELL, "3", "4"))
    digest, history = book.state_digest(), list(book._trades)
    snap = book.snapshot()
    assert snap[1][0] is history[0]                         # shared, not copied
    book.place_order(_order("x", BOB, OrderSide.BUY, "3", "2"))
    assert book.state_digest() != digest
    book.restore(snap)
    assert book.state_digest() == digest and list(book._trades) == history


def test_expiry_is_judged_by_block_time_not_the_wall_clock(monkeypatch):
    book = _book()
    book.new_block(1_000.0)
    book.place_order(_order("e", ALICE, OrderSide.BUY, "1", "5", expire_time=1_100.0))
    monkeypatch.setattr(OB.time, "time", lambda: 9e12)     # the wall clock says "long expired"
    book.new_block(1_050.0)
    assert "e" in book._orders
    book.new_block(1_101.0)
    assert "e" not in book._orders
    with pytest.raises(ValueError, match="expired"):
        book.place_order(_order("late", ALICE, OrderSide.BUY, "1", "5", expire_time=1_100.0))


def test_matching_does_not_depend_on_the_callers_precision():
    def run():
        book = _book()
        book.place_order(_order("m", ALICE, OrderSide.SELL, "2.123456789012345678",
                                "123456.123456789012345678"))
        book.place_order(_order("t", BOB, OrderSide.BUY, "2.123456789012345678",
                                "100000.000000000000000001"))
        router = UnifiedRouter()
        router.register_order_book(book.pool_id, book)
        route = router.clob_route(T1, T0, D("1000.123456789012345678"), CAROL)
        return book.state_digest(), book.total_volume, route.amount_out, route.amount_in
    reference = run()
    with localcontext() as ctx:
        ctx.prec = 12
        assert run() == reference


def test_a_failed_book_operation_leaves_the_book_and_history_unchanged():
    ExchangeStateManager.reset_instance()
    try:
        m = ExchangeStateManager.get_instance()
        m.enforce_spot_settlement = m.enforce_orderbook_settlement = True
        for who in (ALICE, BOB):
            m.set_available_balance(who, D(10_000_000))
            for t in (T0, T1):
                m.set_available_token_balance(who, t, D(1_000_000))
        m.begin_block(1, 1_700_000_000.0)
        nonces = {ALICE: 0, BOB: 0}

        def tx(who, op, params):
            nonces[who] += 1
            return ExchangeTransaction(op_type=op, sender=who, nonce=nonces[who] - 1,
                                       params=params, gas_limit=10_000_000, gas_price=D("1"))

        assert m.process_transaction(tx(ALICE, ExchangeOpType.CREATE_POOL, {
            "token0": T0, "token1": T1, "fee_tier": 3000, "pool_type": "STANDARD",
            "initial_price": "1", "stake_amount": "10000"})).success
        pair = f"{T0}:{T1}"
        escrow = m.orderbook_escrow_address(pair)
        m.set_available_token_balance(escrow, T0, D(0))
        m.set_available_token_balance(escrow, T1, D(0))
        assert m.process_transaction(tx(ALICE, ExchangeOpType.PLACE_ORDER, {
            "pair": pair, "side": "buy", "order_type": "limit", "price": "1",
            "amount": "10"})).success
        book = m._order_books[pair]
        m.set_available_token_balance(escrow, T1, D(0))    # as if the escrow were drained
        digest, history = book.state_digest(), list(book._trades)
        r = m.process_transaction(tx(BOB, ExchangeOpType.PLACE_ORDER, {
            "pair": pair, "side": "sell", "order_type": "limit", "price": "1", "amount": "4"}))
        assert not r.success and "cannot cover" in r.error
        assert m._order_books[pair].state_digest() == digest
        assert list(m._order_books[pair]._trades) == history
    finally:
        ExchangeStateManager.reset_instance()
