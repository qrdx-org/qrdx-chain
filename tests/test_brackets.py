"""
Take-profit / stop-loss attached to an order, and one-cancels-the-other (docs/TRADING_FEATURES.md
§3).

Perps: ``PERP_ORDER`` with ``tp`` / ``sl`` places reduce-only triggers sized to the order, in a
group — the first to fire cancels the other; they go with the order if it is cancelled unfilled,
and once it is done and the position is gone.

Spot: ``PLACE_ORDER`` (a buy) with ``tp`` / ``sl`` places one sell trigger (a one-cancels-the-other
with both) that starts empty: each fill of the order puts the base it bought into the trigger's
escrow, so it protects exactly what was bought, wherever and whenever the order fills. A
standalone ``oco`` order is the same over base already held.
"""
from decimal import Decimal as D

import pytest

from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from test_trading_ops import BASE, MID, PAIR, QUOTE, T0, Spot, _house, _price


# ── perps ───────────────────────────────────────────────────────────────────

@pytest.fixture
def mgr():
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.begin_block(1, float(T0))
    m.clearinghouse.create_market("BTC")
    m.clearinghouse.set_oracle_price(MID, D(100), now=T0)
    for o in ("maker", "taker", "other"):
        m.clearinghouse.deposit(o, D(100_000))
    yield m
    ExchangeStateManager.reset_instance()


def _perp(m, who, **params):
    return m.process_transaction(ExchangeTransaction(
        op_type=ExchangeOpType.PERP_ORDER, sender=who, nonce=m.get_nonce(who),
        params={"market_id": MID, **params}, gas_limit=10 ** 6))


def test_a_perp_orders_tp_and_sl_one_cancelling_the_other(mgr):
    ch = mgr.clearinghouse
    ch.place_order("maker", MID, "ask", "sell", D(2), D(100), 0)
    r = _perp(mgr, "taker", side="buy", size="2", price="100",
              tp={"trigger_price": "110"}, sl={"trigger_price": "95"})
    assert r.success, r.error
    assert sorted(r.data["attached"]) == sorted([f"{r.data['order_id']}.tp",
                                                 f"{r.data['order_id']}.sl"])
    t = ch.markets[MID].triggers[f"{r.data['order_id']}.sl"]
    assert t.reduce_only and t.side == "sell" and t.size == 2
    ch.place_order("other", MID, "bid", "buy", D(5), D(94), 0)
    events = _price(ch, 94, T0 + 1)
    kinds = sorted((e["type"], e.get("reason", "")) for e in events if "trigger" in e["type"])
    assert kinds == [("trigger_cancelled", "oco"), ("trigger_fired", "")]
    assert not ch.markets[MID].triggers and MID not in ch.accounts["taker"].positions


def test_an_unfilled_orders_tp_sl_go_with_it(mgr):
    ch = mgr.clearinghouse
    r = _perp(mgr, "taker", side="buy", size="1", price="99", sl={"trigger_price": "90"})
    assert r.success and r.data["resting"] and r.data["attached"]
    mgr.process_transaction(ExchangeTransaction(
        op_type=ExchangeOpType.PERP_CANCEL, sender="taker", nonce=mgr.get_nonce("taker"),
        params={"market_id": MID, "order_id": r.data["order_id"]}, gas_limit=10 ** 6))
    assert not ch.markets[MID].triggers
    r = _perp(mgr, "taker", side="buy", size="1", price="99", tif="ioc", sl={"trigger_price": "90"})
    assert r.success and "attached" not in r.data and not ch.markets[MID].triggers


def test_a_tp_sl_the_mark_has_already_reached_refuses_the_whole_order(mgr):
    ch = mgr.clearinghouse
    ch.place_order("maker", MID, "ask", "sell", D(1), D(100), 0)
    before = ch.commitment()
    r = _perp(mgr, "taker", side="buy", size="1", price="100", tp={"trigger_price": "99"})
    assert not r.success and "already reached" in r.error and ch.commitment() == before


def test_attached_tp_sl_go_once_the_order_is_done_and_the_position_is_gone(mgr):
    ch = mgr.clearinghouse
    ch.place_order("maker", MID, "ask", "sell", D(1), D(100), 0)
    r = _perp(mgr, "taker", side="buy", size="1", price="100", sl={"trigger_price": "90"})
    assert r.data["attached"]
    ch.place_order("other", MID, "bid", "buy", D(1), D(100), 0)
    ch.place_order("taker", MID, "close", "sell", D(1), D(100), 0, reduce_only=True)
    assert MID not in ch.accounts["taker"].positions and not ch.markets[MID].triggers


# ── spot ────────────────────────────────────────────────────────────────────

def _bracket(s, oid):
    return s.m.trading.spot_triggers.peek(f"{oid}.b")


def test_a_spot_brackets_escrow_holds_exactly_what_its_order_bought(no_trading_fees):
    s = Spot()
    assert s.order("0xPQb", "sell", "5", 3).success
    r = s.order("0xPQa", "buy", "5", 10, tp={"trigger_price": "6"}, sl={"trigger_price": "4"})
    assert r.success, r.error
    oid = r.data["order_id"]
    b = _bracket(s, oid)
    assert b.kind == "oco" and b.amount == 3 and b.escrowed == 3          # bought as taker
    assert s.held("0xPQa", BASE) == 0 and s.held(s.escrow, BASE) == 3      # …into escrow
    assert s.order("0xPQc", "sell", "5", 4).success                        # filled as maker
    assert _bracket(s, oid).amount == 7 and s.held(s.escrow, BASE) == 7
    # The rest of the order cancelled: the bracket stays (it holds what was bought).
    assert s.tx("0xPQa", ExchangeOpType.CANCEL_ORDER, {"pair": PAIR, "order_id": oid}).success
    assert _bracket(s, oid).amount == 7
    assert s.order("0xPQc", "sell", "3.9", 1).success and s.order("0xPQd", "buy", "3.9", 1).success
    events = s.block()                                                     # last price 3.9 ≤ 4
    fired = [e for e in events if e["type"] == "spot_trigger_fired"]
    assert fired and fired[0]["kind"] == "sl" and _bracket(s, oid) is None
    s.conserved()


def test_a_spot_bracket_with_fees_holds_the_base_after_the_fee():
    s = Spot()
    s.order("0xPQb", "sell", "5", 10)
    r = s.order("0xPQa", "buy", "5", 10, sl={"trigger_price": "4"})
    from qrdx.exchange import clearinghouse as CH
    fee = D(10) * CH.TAKER_FEE_RATE
    assert _bracket(s, r.data["order_id"]).amount == 10 - fee


def test_a_spot_brackets_order_cancelled_before_it_bought_takes_it_along(no_trading_fees):
    s = Spot()
    r = s.order("0xPQa", "buy", "5", 10, tp={"trigger_price": "6"})
    oid = r.data["order_id"]
    assert _bracket(s, oid).amount == 0
    assert s.tx("0xPQa", ExchangeOpType.CANCEL_ORDER, {"pair": PAIR, "order_id": oid}).success
    assert _bracket(s, oid) is None


def test_a_spot_brackets_order_modified_keeps_its_bracket(no_trading_fees):
    s = Spot()
    r = s.order("0xPQa", "buy", "5", 10, sl={"trigger_price": "4"})
    oid = r.data["order_id"]
    m = s.tx("0xPQa", ExchangeOpType.MODIFY_ORDER, {"pair": PAIR, "order_id": oid, "price": "5.5"})
    assert m.success and m.data["order_id"] != oid
    assert _bracket(s, oid).parent == m.data["order_id"]
    s.order("0xPQb", "sell", "5.5", 2)
    assert _bracket(s, oid).amount == 2


def test_a_spot_oco_fires_the_first_leg_reached(no_trading_fees):
    s = Spot()
    s.order("0xPQb", "buy", "6", 10)                       # a bid to take profit into
    r = s.trigger("0xPQa", "sell", "oco", 4, 5, tp_price="6")
    assert r.success, r.error
    assert s.held("0xPQa", BASE) == -5
    s.order("0xPQc", "sell", "6", 1)                       # trades at 6: the take-profit leg
    events = s.block()
    fired = [e for e in events if e["type"] == "spot_trigger_fired"]
    assert fired[0]["kind"] == "tp" and not s.m.trading.spot_triggers
    assert s.held("0xPQa", QUOTE) == 5 * 6
    s.conserved()


@pytest.mark.parametrize("params, error", [
    ({"side": "sell", "tp": {"trigger_price": "6"}}, "buy"),
    ({"side": "buy", "tp": "6"}, "trigger_price"),
    ({"side": "buy", "tp": {"trigger_price": "-1"}}, "positive"),
])
def test_attached_tp_sl_that_make_no_sense_are_refused(params, error, no_trading_fees):
    s = Spot()
    side = params.pop("side")
    r = s.order("0xPQa", side, "5", 1, **params)
    assert not r.success and error in r.error and not s.m.trading.spot_triggers
