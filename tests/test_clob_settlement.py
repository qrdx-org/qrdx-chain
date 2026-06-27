"""
Phase E — CLOB order-book settlement (escrow-on-place / settle-on-match / refund-on-cancel).

Gated by ExchangeStateManager.enforce_orderbook_settlement (observe-first, default off →
behaviour-neutral). When on, a placed LIMIT order escrows its funds into a per-book escrow
holder, matched trades move real base/quote token balances maker↔taker (maker side from
escrow, taker side live), and cancel refunds the resting remainder. These pin conservation
(no token created/destroyed) + the affordability/market guards.
"""

from decimal import Decimal
from types import SimpleNamespace

import pytest

from qrdx.exchange.state_manager import ExchangeStateManager
from qrdx.exchange.orderbook import OrderBook, OrderSide

PAIR = "TKA:TKB"   # base:quote
BASE, QUOTE = "TKA", "TKB"


def _mgr():
    mgr = ExchangeStateManager()
    mgr.enforce_orderbook_settlement = True
    mgr._order_books[PAIR] = OrderBook(pool_id=PAIR)
    mgr.begin_block(1, 0.0)
    return mgr


def _order_tx(sender, side, price, amount, oid, order_type="limit"):
    return SimpleNamespace(
        sender=sender, nonce=0, tx_hash=lambda _o=oid: _o,
        params={"pair": PAIR, "side": side, "order_type": order_type,
                "price": str(price), "amount": str(amount)})


def _escrow(mgr):
    return mgr.orderbook_escrow_address(PAIR)


def _assert_conserves(mgr):
    sums = {}
    for (holder, token), d in mgr.token_balance_deltas().items():
        sums[token] = sums.get(token, Decimal(0)) + d
    for token, s in sums.items():
        assert s == Decimal(0), f"{token} not conserved: net {s}"


def test_place_sell_escrows_base():
    mgr = _mgr()
    mgr.set_available_token_balance("0xPQm", BASE, Decimal("100"))
    res = mgr._op_place_order(_order_tx("0xPQm", "sell", 5, 10, "m" * 16))
    assert res.success
    d = mgr.token_balance_deltas()
    assert d[("0xPQm", BASE)] == Decimal("-10")
    assert d[(_escrow(mgr), BASE)] == Decimal("10")
    _assert_conserves(mgr)


def test_full_match_settles_and_conserves():
    mgr = _mgr()
    mgr.set_available_token_balance("0xPQm", BASE, Decimal("100"))
    mgr.set_available_token_balance("0xPQt", QUOTE, Decimal("100000"))
    mgr._op_place_order(_order_tx("0xPQm", "sell", 5, 10, "m" * 16))   # rests, escrows 10 base
    mgr._op_place_order(_order_tx("0xPQt", "buy", 5, 10, "t" * 16))    # matches fully @ 5
    d = mgr.token_balance_deltas()
    esc = _escrow(mgr)
    assert d[("0xPQt", BASE)] == Decimal("10")          # buyer gets base
    assert d[(esc, BASE)] == Decimal("0")               # escrow released (+10 then -10)
    assert d[("0xPQm", BASE)] == Decimal("-10")         # seller gave base
    assert d[("0xPQt", QUOTE)] == Decimal("-50")        # buyer paid 10*5
    assert d[("0xPQm", QUOTE)] == Decimal("50")         # seller received 50
    _assert_conserves(mgr)


def test_taker_keeps_price_improvement():
    mgr = _mgr()
    mgr.set_available_token_balance("0xPQm", BASE, Decimal("100"))
    mgr.set_available_token_balance("0xPQt", QUOTE, Decimal("100000"))
    mgr._op_place_order(_order_tx("0xPQm", "sell", 5, 10, "m" * 16))   # ask @ 5
    mgr._op_place_order(_order_tx("0xPQt", "buy", 6, 10, "t" * 16))    # bid @ 6 → fills @ 5
    d = mgr.token_balance_deltas()
    assert d[("0xPQt", QUOTE)] == Decimal("-50")        # pays maker's 5, not its 6
    _assert_conserves(mgr)


def test_unmatched_buy_escrows_quote():
    mgr = _mgr()
    mgr.set_available_token_balance("0xPQt", QUOTE, Decimal("100000"))
    mgr._op_place_order(_order_tx("0xPQt", "buy", 5, 10, "t" * 16))    # no asks → rests
    d = mgr.token_balance_deltas()
    assert d[("0xPQt", QUOTE)] == Decimal("-50")        # escrow 10*5
    assert d[(_escrow(mgr), QUOTE)] == Decimal("50")
    _assert_conserves(mgr)


def test_cancel_refunds_escrow():
    mgr = _mgr()
    mgr.set_available_token_balance("0xPQt", QUOTE, Decimal("100000"))
    mgr._op_place_order(_order_tx("0xPQt", "buy", 5, 10, "t" * 16))    # escrow 50 quote
    cancel = SimpleNamespace(sender="0xPQt", nonce=1,
                             params={"order_id": "t" * 16, "pair": PAIR})
    res = mgr._op_cancel_order(cancel)
    assert res.success
    d = mgr.token_balance_deltas()
    assert d[("0xPQt", QUOTE)] == Decimal("0")          # escrow(50) then refund(50)
    assert d[(_escrow(mgr), QUOTE)] == Decimal("0")
    _assert_conserves(mgr)


def test_enforce_rejects_unaffordable_limit():
    mgr = _mgr()
    mgr.set_available_token_balance("0xPQt", QUOTE, Decimal("10"))     # needs 50
    res = mgr._op_place_order(_order_tx("0xPQt", "buy", 5, 10, "t" * 16))
    assert not res.success and "insufficient" in res.error
    assert mgr.token_balance_deltas() == {}              # no match, no settlement


def test_enforce_rejects_market_order():
    mgr = _mgr()
    mgr.set_available_token_balance("0xPQt", QUOTE, Decimal("100000"))
    res = mgr._op_place_order(_order_tx("0xPQt", "buy", 0, 10, "t" * 16, order_type="market"))
    assert not res.success and "LIMIT" in res.error


def test_observe_off_is_behaviour_neutral():
    mgr = ExchangeStateManager()  # enforce_orderbook_settlement defaults False
    mgr._order_books[PAIR] = OrderBook(pool_id=PAIR)
    mgr.begin_block(1, 0.0)
    res = mgr._op_place_order(_order_tx("0xPQt", "buy", 5, 10, "t" * 16))
    assert res.success
    assert mgr.token_balance_deltas() == {}             # matches as before, moves no value
