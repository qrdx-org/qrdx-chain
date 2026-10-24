"""
Margin reserved by resting perp orders (docs/PERPS_CLEARINGHOUSE.md, Phase 1).

An order that would only close the position reserves nothing: per market, the position's size
is closing capacity, used by the orders on the closing side in the order they would fill. A
resting take-profit used to reserve margin as if it opened a position, unless flagged
reduce-only.

What the static rule assumed can stop being true when the position changes, so:
  * after any position change, the account's reduce-only orders that would now open are
    cancelled, and so are opening orders it can no longer carry (least likely to fill first);
  * at match time, a maker whose fill would open exposure is cancelled instead if it is
    reduce-only, or if neither its reservation nor the free margin covers that exposure
    (Hyperliquid's reduceOnlyCanceled / marginCanceled).
Placing an order checks both worst cases: a full fill now, and resting whole.
"""
from decimal import Decimal
from types import SimpleNamespace

import pytest

from qrdx import constants
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange.clearinghouse import Clearinghouse, ClearinghouseError

pytestmark = pytest.mark.usefixtures("open_listing")  # lists markets with CREATE_MARKET

D = Decimal
BTC = "BTC-QRDX-PERP"


def _ch():
    ch = Clearinghouse()
    ch.create_market("BTC")
    ch.set_oracle_price(BTC, D(30000))
    for who in ("bob", "carol"):
        ch.deposit(who, D(10_000_000))
    return ch


def _alice_long(ch, deposit):
    """Alice goes long 1 at 30,000 (10x: 3,000 margin, 15 taker fee)."""
    ch.deposit("alice", D(deposit))
    ch.place_order("bob", BTC, "s0", "sell", D(1), D(30000), 0)
    ch.place_order("alice", BTC, "b0", "buy", D(1), D(30000), 0)
    assert ch.accounts["alice"].positions[BTC].size == 1


def _cancelled(ch):
    return [(c["order_id"], c["owner"], c["reason"]) for c in ch.last_cancelled]


# ── what a resting order reserves ─────────────────────────────────────────

def test_a_take_profit_reserves_nothing():
    ch = _ch()
    _alice_long(ch, 3500)
    free = ch.withdrawable("alice")
    ch.place_order("alice", BTC, "tp", "sell", D(1), D(33000), 0)
    assert ch.open_order_margin("alice") == 0          # it used to reserve 3,300
    assert ch.withdrawable("alice") == free


def test_a_second_closing_order_behind_the_first_reserves_as_opening():
    ch = _ch()
    _alice_long(ch, 3500)
    ch.place_order("alice", BTC, "tp", "sell", D(1), D(33000), 0)
    with pytest.raises(ClearinghouseError, match="insufficient margin"):
        ch.place_order("alice", BTC, "tp2", "sell", D(1), D(34000), 0)   # would open: 3,400
    ch.deposit("alice", D(5000))
    ch.place_order("alice", BTC, "tp2", "sell", D(1), D(34000), 0)
    assert ch.open_order_margin("alice") == D(3400)


def test_an_order_ahead_of_a_take_profit_reserves_for_the_one_it_displaces():
    """A sell below the take-profit fills first, so the take-profit is the one that opens."""
    ch = _ch()
    _alice_long(ch, 3500)
    ch.place_order("alice", BTC, "tp", "sell", D(1), D(33000), 0)
    with pytest.raises(ClearinghouseError, match="insufficient margin"):
        ch.place_order("alice", BTC, "near", "sell", D(1), D(32000), 0)
    ch.deposit("alice", D(5000))
    ch.place_order("alice", BTC, "near", "sell", D(1), D(32000), 0)
    assert ch.open_order_margin("alice") == D(3300)    # the take-profit's


def test_a_resting_order_far_from_mark_reserves_at_its_price():
    """The fill check alone valued a sell far above mark at the gap: it rested against almost
    no collateral, at hundreds of times the maximum leverage."""
    ch = _ch()
    ch.deposit("alice", D(100))
    with pytest.raises(ClearinghouseError, match="insufficient margin"):
        ch.place_order("alice", BTC, "far", "sell", D(1), D(60000), 0)
    ch.deposit("alice", D(6000))
    ch.place_order("alice", BTC, "far", "sell", D(1), D(60000), 0)
    assert ch.open_order_margin("alice") == D(6000)


# ── a position change re-checks the account's orders ─────────────────────

def test_closing_the_position_cancels_a_take_profit_it_cannot_carry():
    ch = _ch()
    _alice_long(ch, 3100)                               # collateral 3,085
    ch.place_order("alice", BTC, "tp", "sell", D(1), D(33000), 0)
    ch.place_order("carol", BTC, "bid", "buy", D(1), D(30000), 0)
    ch.place_order("alice", BTC, "close", "sell", D(1), D(30000), 0, ioc=True)
    assert BTC not in ch.accounts["alice"].positions
    assert _cancelled(ch) == [("tp", "alice", "margin")]    # opening 3,300 of 3,070 equity
    assert ch.markets[BTC].book.get_order("tp") is None or not ch.markets[BTC].book.get_order(
        "tp").is_active
    assert "tp" not in ch.markets[BTC].orders


def test_closing_the_position_keeps_a_take_profit_it_can_carry():
    ch = _ch()
    _alice_long(ch, 10_000)
    ch.place_order("alice", BTC, "tp", "sell", D(1), D(33000), 0)
    ch.place_order("carol", BTC, "bid", "buy", D(1), D(30000), 0)
    ch.place_order("alice", BTC, "close", "sell", D(1), D(30000), 0, ioc=True)
    assert ch.last_cancelled == []
    assert ch.open_order_margin("alice") == D(3300)    # now an opening order, reserved


def test_a_reduce_only_order_is_cancelled_once_it_would_open():
    ch = _ch()
    _alice_long(ch, 10_000)
    ch.place_order("alice", BTC, "ro", "sell", D(1), D(33000), 0, reduce_only=True)
    ch.place_order("carol", BTC, "bid", "buy", D(1), D(30000), 0)
    ch.place_order("alice", BTC, "close", "sell", D(1), D(30000), 0, ioc=True)
    assert _cancelled(ch) == [("ro", "alice", "reduce_only")]


def test_a_maker_reduce_only_order_never_fills_as_an_opening():
    """Alice's sell below her reduce-only one fills first and closes her long; the same sweep
    then reaches the reduce-only order, which would open a short: it is cancelled, unfilled."""
    ch = _ch()
    _alice_long(ch, 10_000)
    ch.place_order("alice", BTC, "ro", "sell", D(1), D(31000), 0, reduce_only=True)
    ch.place_order("alice", BTC, "tp", "sell", D(1), D(30500), 0)
    fills = ch.place_order("carol", BTC, "sweep", "buy", D(2), D(31000), 0)
    assert [(f["seller"], f["price"]) for f in fills] == [("alice", "30500")]
    assert ("ro", "alice", "reduce_only") in _cancelled(ch)
    assert BTC not in ch.accounts["alice"].positions
    assert ch.identity_gap() == 0 and ch.net_size(BTC) == 0


def test_a_maker_opening_without_reserved_margin_is_cancelled_at_match_time():
    """Two sells at one price: the reservation assumed the lower id closes, time priority
    fills the older one first. The other then opens with no margin reserved for it and none
    free, so it is cancelled rather than filled."""
    ch = _ch()
    _alice_long(ch, 6200)
    ch.place_order("alice", BTC, "z-first", "sell", D(1), D(31000), 0)
    ch.place_order("alice", BTC, "a-second", "sell", D(1), D(31000), 0)   # takes the capacity
    assert ch.open_order_margin("alice") == D(3100)    # reserved for z-first
    ch.withdraw("alice", ch.withdrawable("alice"))     # no free margin left
    fills = ch.place_order("carol", BTC, "sweep", "buy", D(2), D(31000), 0)
    assert [f["amount"] for f in fills] == ["1"]       # z-first closed the long …
    assert ("a-second", "alice", "margin") in _cancelled(ch)   # … a-second could not open
    assert BTC not in ch.accounts["alice"].positions
    assert ch.identity_gap() == 0 and ch.net_size(BTC) == 0


# ── through the state manager: the receipt reports the cancellations ─────

def test_the_order_receipt_lists_the_orders_it_cancelled(monkeypatch):
    rep, alice, carol = "0xPQrep", "0xPQaaa", "0xPQccc"
    monkeypatch.setattr(constants, "ORACLE_REPORTERS", (rep,))
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    try:
        mgr.begin_block(1, 1_700_000_000.0)
        assert mgr._op_create_market(SimpleNamespace(params={"base_token": "BTC"})).success

        def tx(op, sender, params):
            return mgr.process_transaction(ExchangeTransaction(
                op_type=op, sender=sender, nonce=mgr._nonces.get(sender, 0), params=params,
                gas_limit=2_000_000, gas_price=10**9))

        def order(sender, side, size, price, **extra):
            return tx(ExchangeOpType.PERP_ORDER, sender, {
                "market_id": BTC, "side": side, "size": str(size), "price": str(price), **extra})

        assert tx(ExchangeOpType.UPDATE_ORACLE, rep, {"pair": "BTC:QRDX", "price": "30000"}).success
        for who, amount in ((alice, "3100"), (carol, "10000000")):
            assert tx(ExchangeOpType.PERP_DEPOSIT, who, {"amount": amount}).success
        assert order(carol, "sell", 1, 30000).success
        assert order(alice, "buy", 1, 30000).success
        placed = order(alice, "sell", 1, 33000)
        assert placed.success and "cancelled" not in placed.data
        assert order(carol, "buy", 1, 30000).success
        closed = order(alice, "sell", 1, 30000, tif="ioc")
        assert closed.success
        assert [(c["owner"], c["reason"]) for c in closed.data["cancelled"]] == [(alice, "margin")]
    finally:
        ExchangeStateManager.reset_instance()
