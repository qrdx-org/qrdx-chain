"""
Undo scopes (qrdx/exchange/undo.py): all or nothing at the cost of what an operation touched.

An exchange operation that fails part-way must change nothing. Spot orders used to get that by
deep-copying their whole book before matching (every resting order, every time), and nothing
wider than one book — a batch, a modify, an order that must fill whole — could be atomic at all.
Inside an undo scope each piece of state records what it was the first time the scope touches
it, and a failure puts back exactly that. These tests run random operations in a scope, roll
back, and require the state to be what it was — field for field, with the order index pointing
at the very orders its price levels hold — and to behave identically afterwards.
"""
import copy
import random
from decimal import Decimal as D

import pytest

from qrdx.exchange import undo
from qrdx.exchange.clearinghouse import Clearinghouse, ClearinghouseError
from qrdx.exchange.orderbook import (
    Order,
    OrderBook,
    OrderSide,
    OrderType,
    SelfTradeAction,
)

OWNERS = [f"0xPQ{i}" for i in range(5)]


class Boom(Exception):
    pass


def _order(rng, n, owner=None, kind=None):
    side = rng.choice([OrderSide.BUY, OrderSide.SELL])
    kind = kind or rng.choice([OrderType.LIMIT] * 6 + [OrderType.MARKET, OrderType.STOP_LOSS])
    price = D(rng.randint(95, 105))
    return Order(id=f"o{n}", owner=owner or rng.choice(OWNERS), side=side, order_type=kind,
                 price=price if kind != OrderType.MARKET else D(0),
                 amount=D(rng.randint(1, 5)), nonce=0, timestamp=0.0,
                 stop_price=price if kind == OrderType.STOP_LOSS else None)


def _book_state(book):
    """Everything consensus-relevant about a book, and the order index's identity with the
    levels' orders."""
    levels = {}
    for tag, side in (("b", book._bids), ("a", book._asks)):
        for price, level in side.items():
            levels[(tag, price)] = [(o.id, o.owner, o.side, o.price, o.amount, o.filled, o.status)
                                    for o in level.orders]
            for o in level.orders:
                if o.is_active:
                    assert book._orders.get(o.id) is o, f"index does not hold level order {o.id}"
    return {
        "levels": levels,
        "orders": sorted((oid, o.filled, o.status) for oid, o in book._orders.items()),
        # In insertion order: stop orders trigger in the order they were placed.
        "stops": [(oid, o.stop_price, o.status) for oid, o in book._stop_orders.items()],
        "counts": dict(book._owner_order_count),
        "stop_counts": dict(book._owner_stop_count),
        "block_counts": dict(book._block_order_count),
        "nonces": dict(book._owner_nonces),
        "scalars": (book._trade_sequence, book.last_price, book.total_volume, book.total_trades),
        "trades": [t.id for t in book._trades],
        "digest": book.state_digest(),
    }


def _random_ops(rng, book, start, count):
    n = start
    for _ in range(count):
        n += 1
        if rng.random() < 0.25 and book._orders:
            oid = rng.choice(sorted(book._orders))
            book.cancel_order(oid, caller=book._orders[oid].owner)
        else:
            try:
                book.place_order(_order(rng, n))
            except ValueError:
                pass
    return n


@pytest.mark.parametrize("seed", range(20))
@pytest.mark.parametrize("stp", [SelfTradeAction.CANCEL_TAKER, SelfTradeAction.CANCEL_MAKER,
                                 SelfTradeAction.REJECT])
def test_a_book_rolled_back_is_the_book_it_was(seed, stp):
    rng = random.Random(seed)
    book = OrderBook(pool_id="A:B", self_trade_action=stp)
    book.new_block(1000.0)
    n = _random_ops(rng, book, 0, 40)
    book.cached_digest()                                   # a digest cached before the scope
    twin = copy.deepcopy(book)
    before = _book_state(book)
    with pytest.raises(Boom):
        with undo.atomic():
            _random_ops(rng, book, n, 30)
            raise Boom()
    assert _book_state(book) == before
    assert book.cached_digest() == book.state_digest() == twin.state_digest()
    # …and it behaves exactly like the book that never ran the scope.
    rng_a, rng_b = random.Random(seed + 99), random.Random(seed + 99)
    _random_ops(rng_a, book, 1000, 30)
    _random_ops(rng_b, twin, 1000, 30)
    assert _book_state(book) == _book_state(twin)


def test_a_scope_that_succeeds_keeps_its_changes_and_an_outer_scope_can_still_undo_them():
    rng = random.Random(7)
    book = OrderBook(pool_id="A:B", self_trade_action=SelfTradeAction.CANCEL_TAKER)
    _random_ops(rng, book, 0, 30)
    before = _book_state(book)
    with pytest.raises(Boom):
        with undo.atomic():
            with undo.atomic():                            # succeeds…
                _random_ops(rng, book, 100, 20)
            middle = _book_state(book)
            assert middle != before
            with pytest.raises(Boom):
                with undo.atomic():                        # …this one fails: back to middle
                    _random_ops(rng, book, 200, 20)
                    raise Boom()
            assert _book_state(book) == middle
            raise Boom()                                   # the outer fails: back to before
    assert _book_state(book) == before


def test_outside_a_scope_nothing_is_recorded():
    book = OrderBook(pool_id="A:B")
    assert undo.active() is None
    book.place_order(_order(random.Random(1), 1, kind=OrderType.LIMIT))
    assert undo.active() is None


# ── the clearinghouse ───────────────────────────────────────────────────────

def _house():
    ch = Clearinghouse()
    for base in ("BTC", "ETH"):
        ch.create_market(base)
        ch.set_oracle_price(f"{base}-QRDX-PERP", D(100))
    for o in OWNERS:
        ch.deposit(o, D(100_000))
    return ch


def _perp_ops(rng, ch, start, count):
    n = start
    for _ in range(count):
        n += 1
        mid = rng.choice(sorted(ch.markets))
        owner = rng.choice(OWNERS)
        r = rng.random()
        try:
            if r < 0.15:
                orders = [oid for oid, meta in ch.markets[mid].orders.peek_items()
                          if meta.owner == owner]
                if orders:
                    ch.cancel_order(owner, mid, rng.choice(sorted(orders)))
            elif r < 0.2:
                ch.set_oracle_price(mid, D(rng.randint(80, 120)))
            elif r < 0.25:
                ch.tick(D(1000 + n))
            elif r < 0.3:
                ch.withdraw(owner, D(rng.randint(1, 100)))
            else:
                ch.place_order(owner, mid, f"p{n}", rng.choice(["buy", "sell"]),
                               D(rng.randint(1, 20)), D(rng.randint(90, 110)), n,
                               ioc=rng.random() < 0.2)
        except (ClearinghouseError, ValueError):
            pass
    return n


@pytest.mark.parametrize("seed", range(15))
def test_a_clearinghouse_rolled_back_is_the_clearinghouse_it_was(seed):
    rng = random.Random(seed)
    ch = _house()
    n = _perp_ops(rng, ch, 0, 60)
    ch.commitment()
    twin = copy.deepcopy(ch)
    before, root = ch.canonical(), ch.commitment()
    with pytest.raises(Boom):
        with undo.atomic():
            _perp_ops(rng, ch, n, 40)
            raise Boom()
    assert ch.canonical() == before
    assert ch.commitment() == root
    ch.verify_commitment()
    assert ch.identity_gap() == 0
    rng_a, rng_b = random.Random(seed + 7), random.Random(seed + 7)
    _perp_ops(rng_a, ch, 5000, 40)
    _perp_ops(rng_b, twin, 5000, 40)
    assert ch.canonical() == twin.canonical() and ch.commitment() == twin.commitment()


# ── the manager: a spot order that fails part-way changes nothing ────────────

def test_a_failed_spot_settlement_leaves_the_book_and_the_ledgers_as_they_were(monkeypatch):
    from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
    from qrdx.exchange import block_processor as BP

    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    BP.apply_enforcement(m)
    m.begin_block(1, 1_700_000_000.0)
    book = OrderBook(pool_id="AAA:QRDX", self_trade_action=SelfTradeAction.CANCEL_TAKER)
    m._order_books["AAA:QRDX"] = book
    m.router.register_order_book("AAA:QRDX", book)
    rng = random.Random(3)
    _random_ops(rng, book, 0, 20)
    before, ledgers = _book_state(book), dict(m._token_balance_deltas)
    escrow = m.orderbook_escrow_address("AAA:QRDX")
    for o in OWNERS + [escrow]:
        m.set_available_token_balance(o, "AAA", D(10 ** 6))
        m.set_available_balance(o, D(10 ** 6))
    calls = {"n": 0}
    real = m._settle_token_move

    def fail_late(*a, **k):                                 # the second move fails
        calls["n"] += 1
        if calls["n"] == 2:
            raise ValueError("cannot cover")
        return real(*a, **k)

    monkeypatch.setattr(m, "_settle_token_move", fail_late)
    tx = ExchangeTransaction(op_type=ExchangeOpType.PLACE_ORDER, sender=OWNERS[0], nonce=0,
                             params={"pair": "AAA:QRDX", "side": "buy", "order_type": "limit",
                                     "price": "200", "amount": "50"}, gas_limit=10 ** 6)
    r = m.process_transaction(tx)
    assert not r.success and "cannot cover" in r.error
    assert _book_state(book) == before and dict(m._token_balance_deltas) == ledgers
    ExchangeStateManager.reset_instance()


def test_a_perp_order_that_cannot_rest_changes_nothing():
    """It used to keep the makers' fills in the book without applying the trades: the order
    matched, then could not rest its remainder (the account already rested the most a book
    allows), and the failure left a maker without its order and without a position."""
    from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
    from qrdx.exchange.orderbook import MAX_ORDERS_PER_ADDRESS

    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.begin_block(1, 1_700_000_000.0)
    ch = m.clearinghouse
    ch.create_market("BTC")
    mid = "BTC-QRDX-PERP"
    ch.set_oracle_price(mid, D(100))
    for o in ("maker", "taker"):
        ch.deposit(o, D(10 ** 9))
    ch.place_order("maker", mid, "ask1", "sell", D(1), D(100), 0)
    for i in range(MAX_ORDERS_PER_ADDRESS):
        if i % 40 == 0:
            m.begin_block(2 + i, 1_700_000_000.0 + i)
        ch.place_order("taker", mid, f"bid{i}", "buy", D("0.01"), D(50), 0)
    m.begin_block(999, 1_700_001_000.0)
    before, root = ch.canonical(), ch.commitment()
    r = m.process_transaction(ExchangeTransaction(
        op_type=ExchangeOpType.PERP_ORDER, sender="taker", nonce=0, gas_limit=10 ** 6,
        params={"market_id": mid, "side": "buy", "size": "2", "price": "101"}))
    assert not r.success and "Max orders" in r.error
    assert ch.canonical() == before and ch.commitment() == root
    assert ch.markets[mid].book.get_order("ask1").filled == 0
    assert m.get_nonce("taker") == 1                       # it still consumed its nonce
    ExchangeStateManager.reset_instance()
