"""
Matching is paid for by the order that does it (qrdx/exchange/orderbook.py ``MatchBudget``,
docs/BLOCK_LIMITS.md).

An order used to sweep any number of resting orders for its operation's base gas — 1,600
makers in one PERP_ORDER took ~38 ms, every node, for 60,000 gas. Each resting order an order
visits (filled, skipped or cancelled) now costs EXCHANGE_GAS_PER_MAKER on top of the base, and
an order visits no more than its gas limit pays for. When it runs out the order stops; its
remainder is cancelled, never rested — it could still cross the book.
"""
from decimal import Decimal as D

from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange.clearinghouse import Clearinghouse
from qrdx.exchange.orderbook import (
    MatchBudget,
    Order,
    OrderBook,
    OrderSide,
    OrderStatus,
    OrderType,
)
from qrdx.exchange.transactions import EXCHANGE_GAS_COSTS, EXCHANGE_GAS_PER_MAKER, match_budget

M = "BTC-QRDX-PERP"


def _order(oid, owner, side, amount, price, nonce=0):
    return Order(id=oid, owner=owner, side=side, order_type=OrderType.LIMIT,
                 price=D(price), amount=D(amount), nonce=nonce, timestamp=0.0)


def _book_with_asks(n):
    book = OrderBook(pool_id="A:B", max_orders_per_address=10_000)
    for i in range(n):
        book.place_order(_order(f"ask{i}", f"m{i}", OrderSide.SELL, "1", 100 + i % 7))
    return book


def test_an_order_visits_no_more_resting_orders_than_its_budget_pays_for():
    book = _book_with_asks(1000)
    budget = MatchBudget(50)
    taker = _order("t", "taker", OrderSide.BUY, "1000", "200")
    trades = book.place_order(taker, budget=budget)
    assert budget.visited == 50 and budget.exhausted and len(trades) == 50
    # Out of budget: the remainder is cancelled, not rested across the asks it did not reach.
    assert taker.status == OrderStatus.FILLED and book.get_order("t") is None
    assert book.best_bid is None and book.best_ask is not None


def test_an_order_that_finishes_within_its_budget_rests_as_before():
    book = _book_with_asks(3)
    budget = MatchBudget(10)
    taker = _order("t", "taker", OrderSide.BUY, "5", "200")
    book.place_order(taker, budget=budget)
    assert budget.visited == 3 and not budget.exhausted
    assert book.get_order("t") is not None and taker.remaining == D(2)


def test_skipped_makers_cost_a_visit_too():
    """Self-trade prevention skipping the taker's own orders is matching work like a fill."""
    from qrdx.exchange.orderbook import SelfTradeAction

    book = OrderBook(pool_id="A:B", self_trade_action=SelfTradeAction.REJECT,
                     max_orders_per_address=1000)
    for i in range(5):
        book.place_order(_order(f"own{i}", "taker", OrderSide.SELL, "1", "100", nonce=i))
    budget = MatchBudget(3)
    book.place_order(_order("t", "taker", OrderSide.BUY, "1", "100", nonce=9), budget=budget)
    assert budget.visited == 3 and budget.exhausted


def test_a_budget_of_nothing_fills_nothing_and_rests_nothing():
    book = _book_with_asks(2)
    taker = _order("t", "taker", OrderSide.BUY, "1", "200")
    assert book.place_order(taker, budget=MatchBudget(0)) == []
    assert taker.status == OrderStatus.CANCELLED and book.get_order("t") is None


def test_the_gas_limit_sets_the_budget():
    base = EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_ORDER]
    assert match_budget(ExchangeOpType.PERP_ORDER, base) == 0
    assert match_budget(ExchangeOpType.PERP_ORDER, base + 3 * EXCHANGE_GAS_PER_MAKER + 1) == 3
    assert match_budget(ExchangeOpType.PERP_ORDER, None) is None


# ── through the operations ──────────────────────────────────────────────────

def _perps(makers):
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.begin_block(1, 1_700_000_000.0)
    ch = mgr.clearinghouse
    ch.create_market("BTC")
    ch.set_oracle_price(M, D(30000))
    for i in range(makers):
        ch.deposit(f"0xPQm{i}", D(1_000_000))
        ch.place_order(f"0xPQm{i}", M, f"o{i}", "sell", D("0.01"), D(30000 + i % 5), 0)
    ch.deposit("0xPQtaker", D(10_000_000))
    return mgr, ch


def _perp_order(gas_limit, size="10"):
    return ExchangeTransaction(op_type=ExchangeOpType.PERP_ORDER, sender="0xPQtaker", nonce=0,
                               params={"market_id": M, "side": "buy", "size": size,
                                       "price": "31000"},
                               gas_limit=gas_limit, gas_price=10 ** 9)


def test_a_perp_order_pays_for_each_maker_and_stops_where_its_gas_does():
    mgr, ch = _perps(40)
    base = EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_ORDER]
    r = mgr.process_transaction(_perp_order(base + 12 * EXCHANGE_GAS_PER_MAKER))
    assert r.success and len(r.data["fills"]) == 12
    assert r.gas_used == base + 12 * EXCHANGE_GAS_PER_MAKER
    assert not r.data["resting"]                       # the remainder did not rest
    assert ch.accounts["0xPQtaker"].positions[M].size == D("0.12")
    assert ch.net_size(M) == 0 and ch.identity_gap() == 0
    ExchangeStateManager.reset_instance()


def test_a_perp_order_with_gas_to_spare_rests_its_remainder_and_pays_only_what_it_used():
    mgr, ch = _perps(3)
    base = EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_ORDER]
    r = mgr.process_transaction(_perp_order(base + 100 * EXCHANGE_GAS_PER_MAKER, size="1"))
    assert r.success and len(r.data["fills"]) == 3 and r.data["resting"]
    assert r.gas_used == base + 3 * EXCHANGE_GAS_PER_MAKER
    ExchangeStateManager.reset_instance()


def test_the_worst_sweep_a_block_can_carry_is_bounded():
    """However deep the book, an order's work is what its gas paid for: a block's exchange gas
    limit bounds the matching in it."""
    import time

    from qrdx import constants

    mgr, ch = _perps(1500)
    t = time.perf_counter()
    r = mgr.process_transaction(_perp_order(constants.BLOCK_EXCHANGE_GAS_LIMIT, size="100"))
    elapsed = time.perf_counter() - t
    visits = (constants.BLOCK_EXCHANGE_GAS_LIMIT
              - EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_ORDER]) // EXCHANGE_GAS_PER_MAKER
    assert r.success and len(r.data["fills"]) == min(1500, visits)
    assert elapsed < 1.0
    ExchangeStateManager.reset_instance()
