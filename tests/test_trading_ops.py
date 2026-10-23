"""
Trading operations beyond a single order (docs/TRADING_FEATURES.md):

* trigger orders — stops and take-profits, market or limit, standalone or attached to a
  position (its TP/SL) — judged on the mark price and fired in the block's tick;
* changing an order in one step (PERP_MODIFY, MODIFY_ORDER) — a smaller size keeps the order's
  place in the queue;
* CANCEL_ALL — every order and trigger, spot and perps, or one market's;
* BATCH — several trading operations, all or nothing.

Everything here is consensus state: it is committed, it rolls back exactly with an undo scope,
and the tick fires triggers within fixed per-block limits.
"""
import copy
import random
from decimal import Decimal as D

import pytest

from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction, undo
from qrdx.exchange import clearinghouse as CH
from qrdx.exchange.clearinghouse import Clearinghouse, ClearinghouseError
from qrdx.exchange.journal import ExchangeJournal
from qrdx.exchange.orderbook import OrderBook
from qrdx.exchange.transactions import (
    EXCHANGE_GAS_COSTS,
    EXCHANGE_GAS_PER_CANCEL,
    EXCHANGE_GAS_PER_MAKER,
)

MID = "BTC-QRDX-PERP"
T0 = 1_700_000_000


def _house(owners=("maker", "taker", "other")):
    ch = Clearinghouse()
    ch.create_market("BTC")
    ch.set_oracle_price(MID, D(100), now=T0)
    for o in owners:
        ch.deposit(o, D(100_000))
    return ch


def _price(ch, p, now):
    ch.set_oracle_price(MID, D(p), now=now)
    return ch.tick(D(now))


def _long(ch, owner="taker", size="5"):
    """``owner`` long ``size`` at 100 against maker; leaves the book empty."""
    ch.place_order("maker", MID, f"ask-{owner}", "sell", D(size), D(100), 0)
    ch.place_order(owner, MID, f"buy-{owner}", "buy", D(size), D(100), 0)
    return ch.accounts[owner].positions[MID]


# ── triggers ────────────────────────────────────────────────────────────────

def test_a_positions_stop_loss_closes_it_and_its_take_profit_goes_with_it():
    ch = _house()
    _long(ch)
    ch.place_trigger("taker", MID, "sl", "sell", "sl", D(95), position=True)
    ch.place_trigger("taker", MID, "tp", "sell", "tp", D(110), position=True)
    ch.place_order("other", MID, "bid", "buy", D(10), D(94), 0)
    assert _price(ch, 97, T0 + 1) == [] and set(ch.markets[MID].triggers) == {"sl", "tp"}
    events = _price(ch, 94, T0 + 2)
    fired = [e for e in events if e["type"] == "trigger_fired"]
    assert [e["trigger_id"] for e in fired] == ["sl"] and fired[0]["size"] == "5"
    assert MID not in ch.accounts["taker"].positions
    gone = [e for e in events if e["type"] == "trigger_cancelled"]
    assert [(e["trigger_id"], e["reason"]) for e in gone] == [("tp", "position_closed")]
    assert not ch.markets[MID].triggers
    ch.verify_commitment()
    assert ch.identity_gap() == 0 and ch.net_size(MID) == 0


def test_a_position_trigger_closes_the_position_as_it_is_when_it_fires():
    ch = _house()
    _long(ch, size="2")
    ch.place_trigger("taker", MID, "tp", "sell", "tp", D(105), position=True)
    _long(ch, size="3")                                   # the position grew to 5
    ch.place_order("other", MID, "bid", "buy", D(10), D(104), 0)
    events = _price(ch, 105, T0 + 1)
    assert [e["size"] for e in events if e["type"] == "trigger_fired"] == ["5"]
    assert MID not in ch.accounts["taker"].positions


def test_a_buy_stop_opens_a_position_when_the_mark_rises_to_it():
    ch = _house()
    ch.place_trigger("taker", MID, "stop", "buy", "sl", D(103), size=D(2))
    ch.place_order("maker", MID, "ask", "sell", D(5), D(104), 0)
    assert _price(ch, 102, T0 + 1) == []
    events = _price(ch, 103, T0 + 2)
    fired = [e for e in events if e["type"] == "trigger_fired"][0]
    assert fired["price"] == str((D(103) * D("1.1")).quantize(D("1e-18")))  # 10 % through mark
    assert ch.accounts["taker"].positions[MID].size == D(2)


def test_a_limit_trigger_rests_what_it_does_not_fill():
    ch = _house()
    ch.place_trigger("taker", MID, "tpl", "buy", "tp", D(95), size=D(3), limit_price=D(94))
    _price(ch, 95, T0 + 1)
    resting = ch.markets[MID].book.get_order("tpl")
    assert resting is not None and resting.price == D(94) and "tpl" in ch.markets[MID].orders


@pytest.mark.parametrize("side, kind, price", [("sell", "sl", 101), ("sell", "tp", 99),
                                               ("buy", "sl", 99), ("buy", "tp", 101)])
def test_a_trigger_the_mark_has_already_reached_is_refused(side, kind, price):
    ch = _house()
    with pytest.raises(ClearinghouseError, match="already reached"):
        ch.place_trigger("taker", MID, "t", side, kind, D(price), size=D(1))


def test_trigger_options_that_make_no_sense_are_refused():
    ch = _house()
    with pytest.raises(ClearinghouseError, match="no position"):
        ch.place_trigger("taker", MID, "t", "sell", "sl", D(90), position=True)
    _long(ch)
    with pytest.raises(ClearinghouseError, match="no size"):
        ch.place_trigger("taker", MID, "t", "sell", "sl", D(90), size=D(1), position=True)
    with pytest.raises(ClearinghouseError, match="max_makers"):
        ch.place_trigger("taker", MID, "t", "sell", "sl", D(90), size=D(1), max_makers=101)
    with pytest.raises(ClearinghouseError, match="gtc or ioc"):
        ch.place_trigger("taker", MID, "t", "sell", "sl", D(90), size=D(1), tif="fok")
    for i in range(CH.TRIGGERS_PER_ACCOUNT):
        ch.place_trigger("taker", MID, f"t{i}", "sell", "sl", D(90), size=D(1))
    with pytest.raises(ClearinghouseError, match="at most"):
        ch.place_trigger("taker", MID, "one-more", "sell", "sl", D(90), size=D(1))


def test_a_stale_oracle_holds_back_triggers_that_add_exposure_but_not_those_that_reduce_it():
    from qrdx import constants

    ch = _house()
    _long(ch)
    ch.place_trigger("taker", MID, "sl", "sell", "sl", D(95), position=True)
    ch.place_trigger("other", MID, "entry", "sell", "sl", D(95), size=D(1))
    ch.place_order("maker", MID, "bid", "buy", D(10), D(90), 0)
    ch.set_oracle_price(MID, D(94), now=T0 + 1)
    events = ch.tick(D(T0 + 2 + constants.PERP_ORACLE_STALE_SECONDS))
    assert [e["trigger_id"] for e in events if e["type"] == "trigger_fired"] == ["sl"]
    assert set(ch.markets[MID].triggers) == {"entry"}


def test_a_block_fires_a_bounded_number_of_triggers_risk_reducing_ones_first():
    owners = [f"o{i}" for i in range(3)]
    ch = _house(owners + ["maker"])
    n = 0
    for owner in owners:                                  # 3 × 25 that add exposure…
        for _ in range(25):
            n += 1
            ch.place_trigger(owner, MID, f"open{n}", "sell", "sl", D(95), size=D("0.01"),
                             max_makers=1)
    for owner in owners:                                  # …and 3 reduce-only ones, placed last
        ch.place_trigger(owner, MID, f"reduce-{owner}", "sell", "sl", D(95), size=D(1),
                         reduce_only=True, max_makers=1)
    ch.place_order("maker", MID, "bid", "buy", D(1000), D(90), 0)
    events = _price(ch, 94, T0 + 1)
    acted = [e for e in events if e["type"].startswith("trigger_")]
    assert len(acted) == CH.TRIGGER_FIRES_PER_BLOCK
    assert [e["trigger_id"] for e in acted[:3]] == [f"reduce-{o}" for o in owners]
    assert len(ch.markets[MID].triggers) == 78 - CH.TRIGGER_FIRES_PER_BLOCK
    _price(ch, 94, T0 + 2)
    assert not ch.markets[MID].triggers


def test_the_blocks_matching_budget_bounds_the_triggers_it_fires():
    ch = _house()
    per = CH.TRIGGER_MAX_MAKERS
    for i in range(CH.TRIGGER_MAKERS_PER_BLOCK // per + 3):
        ch.place_trigger("taker", MID, f"t{i}", "sell", "sl", D(95), size=D("0.01"),
                         max_makers=per)
    events = _price(ch, 94, T0 + 1)
    assert len([e for e in events if e["type"].startswith("trigger_")]) == (
        CH.TRIGGER_MAKERS_PER_BLOCK // per)


def test_a_liquidation_cancels_the_accounts_triggers():
    ch = Clearinghouse()
    ch.create_market("BTC")
    ch.set_oracle_price(MID, D(100), now=T0)
    ch.deposit("maker", D(100_000))
    ch.deposit("taker", D(60))                            # ~8x on a long of 5 at 100
    _long(ch)
    ch.place_trigger("taker", MID, "far", "sell", "sl", D(50), position=True)
    ch.place_order("maker", MID, "bid", "buy", D(10), D(90), 0)
    events = _price(ch, 89, T0 + 1)
    assert any(e["type"] == "liquidation" for e in events)
    assert "far" not in ch.markets[MID].triggers


def test_a_fired_trigger_that_fails_changes_nothing_but_is_gone():
    ch = _house()
    ch.deposit("poor", D(1))
    ch.place_trigger("poor", MID, "big", "buy", "sl", D(101), size=D(100))
    ch.place_order("maker", MID, "ask", "sell", D(200), D(102), 0)
    before = (ch.accounts["poor"].collateral, ch.markets[MID].book.state_digest())
    events = _price(ch, 101, T0 + 1)
    cancelled = [e for e in events if e["type"] == "trigger_cancelled"]
    assert cancelled and "margin" in cancelled[0]["reason"]
    assert (ch.accounts["poor"].collateral, ch.markets[MID].book.state_digest()) == before
    assert "big" not in ch.markets[MID].triggers
    ch.verify_commitment()


def test_triggers_are_committed():
    ch = _house()
    root = ch.commitment()
    ch.place_trigger("taker", MID, "t", "sell", "sl", D(90), size=D(1))
    with_trigger = ch.commitment()
    assert with_trigger != root
    ch.cancel_order("taker", MID, "t")
    assert ch.commitment() not in (with_trigger,)          # the sequence counter moved on
    ch.verify_commitment()
    twin = copy.deepcopy(ch)
    assert twin.commitment() == ch.commitment() and twin.canonical() == ch.canonical()


# ── modify, cancel-all ──────────────────────────────────────────────────────

def test_a_smaller_size_at_the_same_price_keeps_the_orders_place():
    ch = _house()
    ch.place_order("maker", MID, "first", "sell", D(5), D(101), 0)
    ch.place_order("other", MID, "second", "sell", D(5), D(101), 0)
    out = ch.modify_order("maker", MID, "first", "new", size=D(2))
    assert out["order_id"] == "first"
    level = ch.markets[MID].book._asks[D(101)]
    assert [o.id for o in level.orders] == ["first", "second"] and level.orders[0].remaining == 2
    fills = ch.place_order("taker", MID, "t", "buy", D(3), D(101), 0)
    assert [(f["maker"], f["amount"]) for f in fills] == [("maker", "2"), ("other", "1")]
    ch.verify_commitment()


def test_any_other_change_replaces_the_order_and_may_match():
    ch = _house()
    ch.place_order("maker", MID, "ask", "sell", D(5), D(105), 0)
    ch.place_order("taker", MID, "bid", "buy", D(5), D(99), 0)
    out = ch.modify_order("taker", MID, "bid", "bid2", price=D(105))
    assert out["order_id"] == "bid2" and len(out["fills"]) == 1 and not out["resting"]
    assert ch.markets[MID].book.get_order("bid") is None
    assert ch.accounts["taker"].positions[MID].size == 5


def test_a_trigger_is_modified_in_place_and_queues_again():
    ch = _house()
    ch.place_trigger("taker", MID, "t", "sell", "sl", D(90), size=D(1))
    seq = ch.markets[MID].triggers["t"].seq
    ch.modify_order("taker", MID, "t", "unused", trigger_price=D(95), size=D(2))
    t = ch.markets[MID].triggers["t"]
    assert (t.trigger_price, t.size) == (D(95), D(2)) and t.seq > seq
    with pytest.raises(ClearinghouseError, match="already reached"):
        ch.modify_order("taker", MID, "t", "unused", trigger_price=D(101))


def test_cancel_all_cancels_every_order_and_trigger_of_the_account_only():
    ch = _house()
    for i in range(3):
        ch.place_order("taker", MID, f"b{i}", "buy", D(1), D(90 + i), 0)
    ch.place_trigger("taker", MID, "t", "sell", "sl", D(90), size=D(1))
    ch.place_order("other", MID, "keep", "buy", D(1), D(80), 0)
    assert ch.cancel_all("taker") == 4
    assert set(ch.markets[MID].orders) == {"keep"} and not ch.markets[MID].triggers


# ── through the operations ──────────────────────────────────────────────────

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


def _tx(m, sender, op, params, gas=10 ** 6):
    nonce = m.get_nonce(sender)
    return m.process_transaction(ExchangeTransaction(
        op_type=op, sender=sender, nonce=nonce, params=params, gas_limit=gas))


def test_a_trigger_prepays_its_matching(mgr):
    r = _tx(mgr, "taker", ExchangeOpType.PERP_TRIGGER, {
        "market_id": MID, "side": "sell", "kind": "sl", "trigger_price": "90", "size": "1",
        "max_makers": 7})
    assert r.success
    assert r.gas_used == EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_TRIGGER] + 7 * EXCHANGE_GAS_PER_MAKER
    assert mgr.clearinghouse.markets[MID].triggers[r.data["order_id"]].max_makers == 7
    r = _tx(mgr, "taker", ExchangeOpType.PERP_TRIGGER, {
        "market_id": MID, "side": "sell", "kind": "sl", "trigger_price": "90", "size": "1",
        "max_makers": 50}, gas=100_000)
    assert not r.success and "does not cover" in r.error


def test_cancel_all_pays_for_what_it_cancels_and_cancels_nothing_when_it_cannot(mgr):
    for i in range(4):
        assert _tx(mgr, "taker", ExchangeOpType.PERP_ORDER, {
            "market_id": MID, "side": "buy", "size": "1", "price": str(90 + i)}).success
    before = mgr.clearinghouse.commitment()
    need = EXCHANGE_GAS_COSTS[ExchangeOpType.CANCEL_ALL] + 4 * EXCHANGE_GAS_PER_CANCEL
    r = _tx(mgr, "taker", ExchangeOpType.CANCEL_ALL, {}, gas=need - 1)
    assert not r.success and mgr.clearinghouse.commitment() == before
    r = _tx(mgr, "taker", ExchangeOpType.CANCEL_ALL, {}, gas=need)
    assert r.success and r.data["cancelled"] == 4 and r.gas_used == need
    assert not mgr.clearinghouse.markets[MID].orders


def test_a_batch_is_all_or_nothing(mgr):
    ch = mgr.clearinghouse
    ok = {"op": "PERP_ORDER", "params": {"market_id": MID, "side": "buy", "size": "1",
                                         "price": "95"}}
    same = {"op": "PERP_ORDER", "params": {"market_id": MID, "side": "buy", "size": "1",
                                           "price": "95"}}
    trig = {"op": "PERP_TRIGGER", "params": {"market_id": MID, "side": "sell", "kind": "sl",
                                             "trigger_price": "90", "size": "1"}}
    bad = {"op": "PERP_ORDER", "params": {"market_id": MID, "side": "buy", "size": "1e9",
                                          "price": "95"}}
    before = ch.commitment()
    r = _tx(mgr, "taker", ExchangeOpType.BATCH, {"actions": [ok, same, trig, bad]})
    assert not r.success and r.error.startswith("action 3 (PERP_ORDER)")
    assert ch.commitment() == before and mgr.get_nonce("taker") == 1
    r = _tx(mgr, "taker", ExchangeOpType.BATCH, {"actions": [ok, same, trig]})
    assert r.success, r.error
    ids = [a["order_id"] for a in r.data["results"]]
    assert len(set(ids)) == 3                              # identical actions, distinct ids
    assert set(ch.markets[MID].orders) == set(ids[:2]) and set(ch.markets[MID].triggers) == {ids[2]}
    expected = (EXCHANGE_GAS_COSTS[ExchangeOpType.BATCH]
                + 2 * EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_ORDER]
                + EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_TRIGGER]
                + 20 * EXCHANGE_GAS_PER_MAKER)             # the trigger's default prepaid matching
    assert r.gas_used == expected


@pytest.mark.parametrize("actions, error", [
    ([], "1 to"),
    ([{"op": "BATCH", "params": {"actions": []}}], "cannot be batched"),
    ([{"op": "TOKEN_MINT", "params": {}}], "cannot be batched"),
    ([{"op": "NOPE", "params": {}}], "unknown operation"),
    ([{"op": "PERP_ORDER", "params": {"market_id": MID}}], "missing param"),
])
def test_a_malformed_batch_is_refused_before_it_runs(actions, error):
    tx = ExchangeTransaction(op_type=ExchangeOpType.BATCH, sender="x", nonce=0,
                             params={"actions": actions})
    with pytest.raises(ValueError, match=error):
        tx.validate_basic()


def test_a_batch_runs_out_of_gas_as_a_whole(mgr):
    action = {"op": "PERP_ORDER", "params": {"market_id": MID, "side": "buy", "size": "1",
                                             "price": "95"}}
    gas = EXCHANGE_GAS_COSTS[ExchangeOpType.BATCH] + EXCHANGE_GAS_COSTS[ExchangeOpType.PERP_ORDER]
    r = _tx(mgr, "taker", ExchangeOpType.BATCH, {"actions": [action, action]}, gas=gas)
    assert not r.success and "out of gas" in r.error and not mgr.clearinghouse.markets[MID].orders


def test_spot_modify_moves_exactly_the_escrow_the_change_needs():
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager()
    m.enforce_orderbook_settlement = True
    pair = "TKA:TKB"
    m._order_books[pair] = OrderBook(pool_id=pair)
    m.begin_block(1, 0.0)
    escrow = m.orderbook_escrow_address(pair)
    for who in ("0xPQm", escrow):
        m.set_available_token_balance(who, "TKA", D(100))
        m.set_available_token_balance(who, "TKB", D(10_000))

    def tx(op, params):
        return m.process_transaction(ExchangeTransaction(
            op_type=op, sender="0xPQm", nonce=m.get_nonce("0xPQm"), gas_limit=10 ** 6,
            params={"pair": pair, **params}))

    r = tx(ExchangeOpType.PLACE_ORDER, {"side": "buy", "order_type": "limit", "price": "5",
                                        "amount": "10"})
    oid = r.data["order_id"]
    assert m.token_balance_deltas()[(escrow, "TKB")] == D(50)
    assert tx(ExchangeOpType.MODIFY_ORDER, {"order_id": oid, "amount": "4"}).success
    assert m.token_balance_deltas()[(escrow, "TKB")] == D(20)       # 6 × 5 handed back
    assert m._order_books[pair].get_order(oid).remaining == 4
    r = tx(ExchangeOpType.MODIFY_ORDER, {"order_id": oid, "price": "6"})
    assert r.success and r.data["order_id"] != oid
    assert m.token_balance_deltas()[(escrow, "TKB")] == D(24)       # 4 × 6, the old 20 back
    assert m.token_balance_deltas()[("0xPQm", "TKB")] == D(-24)
    r = tx(ExchangeOpType.CANCEL_ALL, {})
    assert r.success and r.data["cancelled"] == 1
    assert m.token_balance_deltas()[(escrow, "TKB")] == 0
    ExchangeStateManager.reset_instance()


def test_the_journal_records_what_batches_and_triggers_traded():
    j = ExchangeJournal()

    class Tx:
        op_type = ExchangeOpType.BATCH
        sender, nonce, gas_price = "taker", 0, 1

        def tx_hash(self):
            return "h"

    class R:
        success, error, gas_used = True, "", 1
        data = {"results": [{"op": "PERP_ORDER", "order_id": "o", "fills": [
            {"market": MID, "price": "100", "amount": "1", "buyer": "taker", "seller": "maker",
             "maker": "maker", "realized": {}}]}]}

    fired = {"type": "trigger_fired", "market": MID, "trigger_id": "t", "owner": "taker",
             "fills": [{"market": MID, "price": "99", "amount": "2", "buyer": "x",
                        "seller": "taker", "maker": "x", "realized": {}}]}
    j.record_block(5, 1.0, [Tx()], [R()], [fired])
    kinds = [e["type"] for e in j.events]
    assert kinds == ["fill", "trigger_fired", "fill"]
    assert [t["amount"] for t in j.market.trades_of("taker", 10)] == ["1", "2"]


# ── random operations roll back exactly ─────────────────────────────────────

def _ops(rng, ch, start, count, owners):
    n = start
    for _ in range(count):
        n += 1
        owner = rng.choice(owners)
        r = rng.random()
        try:
            if r < 0.15:
                ch.set_oracle_price(MID, D(rng.randint(92, 108)), now=T0 + n)
                ch.tick(D(T0 + n))
            elif r < 0.35:
                kind, side = rng.choice(["sl", "tp"]), rng.choice(["buy", "sell"])
                pos = rng.random() < 0.3
                ch.place_trigger(owner, MID, f"t{n}", side, kind, D(rng.randint(90, 110)),
                                 size=D(0) if pos else D(rng.randint(1, 4)),
                                 limit_price=D(rng.choice([0, rng.randint(90, 110)])),
                                 reduce_only=rng.random() < 0.3, position=pos,
                                 max_makers=rng.randint(1, 5))
            elif r < 0.45:
                mine = sorted(set(ch.markets[MID].orders) | set(ch.markets[MID].triggers))
                if mine:
                    oid = rng.choice(mine)
                    ch.modify_order(owner, MID, oid, f"m{n}",
                                    size=D(rng.randint(1, 4)) if rng.random() < 0.7 else None,
                                    **({"price": D(rng.randint(95, 105))}
                                       if oid in ch.markets[MID].orders and rng.random() < 0.5
                                       else {}))
            elif r < 0.5:
                ch.cancel_all(owner)
            else:
                ch.place_order(owner, MID, f"p{n}", rng.choice(["buy", "sell"]),
                               D(rng.randint(1, 6)), D(rng.randint(95, 105)), n,
                               tif=rng.choice(["gtc", "gtc", "ioc", "alo"]))
        except (ClearinghouseError, ValueError):
            pass
    return n


@pytest.mark.parametrize("seed", range(20))
def test_triggers_modifies_and_cancels_roll_back_exactly(seed):
    owners = ["a", "b", "c", "d"]
    ch = _house(owners)
    rng = random.Random(seed)
    n = _ops(rng, ch, 0, 80, owners)
    twin = copy.deepcopy(ch)
    before, root = ch.canonical(), ch.commitment()
    with pytest.raises(KeyError):
        with undo.atomic():
            _ops(rng, ch, n, 60, owners)
            raise KeyError()
    assert ch.canonical() == before and ch.commitment() == root
    ch.verify_commitment()
    rng_a, rng_b = random.Random(seed + 5), random.Random(seed + 5)
    _ops(rng_a, ch, 5000, 60, owners)
    _ops(rng_b, twin, 5000, 60, owners)
    assert ch.canonical() == twin.canonical() and ch.commitment() == twin.commitment()
    ch.verify_commitment()
    assert ch.identity_gap() == 0 and ch.net_size(MID) == 0


# ── spot triggers ───────────────────────────────────────────────────────────

PAIR, BASE, QUOTE = "TKA:TKB", "TKA", "TKB"


class Spot:
    """A manager with one enforced spot book, run block by block as the node runs it."""

    def __init__(self):
        from qrdx.exchange.orderbook import SelfTradeAction

        ExchangeStateManager.reset_instance()
        self.m = m = ExchangeStateManager.get_instance()
        m.enforce_orderbook_settlement = m.enforce_spot_settlement = True
        book = OrderBook(pool_id=PAIR, self_trade_action=SelfTradeAction.CANCEL_TAKER)
        m._order_books[PAIR] = book
        m.router.register_order_book(PAIR, book)
        self.book, self.escrow, self.height = book, m.orderbook_escrow_address(PAIR), 0
        self.ledger = {}  # (holder, token) → balance, as the flushes would leave it
        self.block()

    def block(self):
        from qrdx.exchange.block_processor import _execute_block_boundary_duties

        if self.height:
            events = []
            _execute_block_boundary_duties(self.m, self.height, float(T0 + self.height))
            events = self.m._block_tick_events
            for key, d in self.m.token_balance_deltas().items():
                self.ledger[key] = self.ledger.get(key, 0) + d
        self.height += 1
        self.m.begin_block(self.height, float(T0 + self.height))
        for who in ("0xPQa", "0xPQb", "0xPQc", "0xPQd", self.escrow):
            for tok in (BASE, QUOTE):
                start = 0 if who == self.escrow else 10_000
                self.m.set_available_token_balance(who, tok, start + self.ledger.get((who, tok), 0))
        return events if self.height > 1 else []

    def tx(self, sender, op, params, gas=10 ** 6):
        return self.m.process_transaction(ExchangeTransaction(
            op_type=op, sender=sender, nonce=self.m.get_nonce(sender), gas_limit=gas,
            params=params))

    def order(self, sender, side, price, amount, **kw):
        return self.tx(sender, ExchangeOpType.PLACE_ORDER, {
            "pair": PAIR, "side": side, "order_type": "limit", "price": str(price),
            "amount": str(amount), **kw})

    def trigger(self, sender, side, kind, trigger_price, amount, **kw):
        return self.tx(sender, ExchangeOpType.PLACE_ORDER, {
            "pair": PAIR, "side": side, "order_type": kind, "trigger_price": str(trigger_price),
            "amount": str(amount), **kw})

    def held(self, who, tok):
        return self.ledger.get((who, tok), 0) + self.m.token_balance_deltas().get((who, tok), 0)

    def conserved(self):
        for tok in (BASE, QUOTE):
            assert sum(v for (h, t), v in self.ledger.items() if t == tok) == 0


def test_a_spot_sell_stop_escrows_its_base_and_fires_on_the_last_price(no_trading_fees):
    s = Spot()
    assert s.order("0xPQb", "buy", 95, 10).success                 # a bid to sell into
    r = s.trigger("0xPQa", "sell", "stop_loss", 96, 4)
    assert r.success and r.data["trigger"]
    assert s.held("0xPQa", BASE) == -4 and s.held(s.escrow, BASE) == 4
    assert s.block() == []                                         # no trade yet: no price
    assert s.order("0xPQc", "sell", 95, 1).success                 # a trade at 95 ≤ 96
    events = s.block()
    fired = [e for e in events if e["type"] == "spot_trigger_fired"]
    assert len(fired) == 1 and sum(D(f["amount"]) for f in fired[0]["fills"]) == 4
    assert s.held("0xPQa", QUOTE) == 4 * 95 and s.held(s.escrow, BASE) == 0
    assert s.held("0xPQb", BASE) == 5 and s.book.get_order(r.data["order_id"]) is None
    assert not s.m.trading.spot_triggers
    s.conserved()


def test_a_spot_buy_stop_limit_rests_what_it_does_not_fill_with_exactly_its_escrow(no_trading_fees):
    s = Spot()
    assert s.order("0xPQb", "sell", "105", 1).success
    assert s.order("0xPQb", "sell", "105.5", 2).success
    r = s.trigger("0xPQa", "buy", "stop_loss", 105, 5, price="106")
    oid = r.data["order_id"]
    assert s.held("0xPQa", QUOTE) == -530                          # 5 × its limit
    assert s.order("0xPQc", "buy", "105", 1).success              # last price 105: reached
    events = s.block()
    assert [e["type"] for e in events] == ["spot_trigger_fired"] and events[0]["resting"]
    resting = s.book.get_order(oid)
    assert resting.remaining == 3 and resting.price == 106
    # Paid 2 × 105.5; 3 × 106 stays escrowed for the resting rest; the 1 left over came back.
    assert s.held("0xPQa", QUOTE) == -(211 + 318) and s.held("0xPQa", BASE) == 2
    assert s.tx("0xPQa", ExchangeOpType.CANCEL_ORDER, {"pair": PAIR, "order_id": oid}).success
    s.block()
    assert s.held("0xPQa", QUOTE) == -211
    s.conserved()


def test_a_spot_market_trigger_goes_no_further_than_its_slippage_bound():
    s = Spot()
    assert s.order("0xPQb", "sell", "109", 1).success
    assert s.order("0xPQb", "sell", "111", 5).success              # beyond 100 × 1.1
    r = s.trigger("0xPQa", "buy", "stop_loss", 100, 3)
    assert s.held("0xPQa", QUOTE) == -330                          # 3 × 110
    assert s.order("0xPQc", "sell", "100", 1).success and s.order("0xPQd", "buy", "100", 1).success
    events = s.block()
    assert sum(D(f["amount"]) for f in events[0]["fills"]) == 1 and not events[0]["resting"]
    assert s.held("0xPQa", QUOTE) == -109 and s.book.get_order(r.data["order_id"]) is None
    s.conserved()


def test_spot_triggers_cancel_with_a_full_refund_and_are_refused_once_reached():
    s = Spot()
    assert s.order("0xPQb", "buy", 95, 1).success and s.order("0xPQc", "sell", 95, 1).success
    r = s.trigger("0xPQa", "sell", "stop_loss", 96, 1)
    assert not r.success and "already reached" in r.error
    ids = [s.trigger("0xPQa", "sell", "stop_loss", 90, 1).data["order_id"] for _ in range(2)]
    s.trigger("0xPQa", "buy", "take_profit", 90, 1, price="91")
    assert s.tx("0xPQa", ExchangeOpType.CANCEL_ORDER, {"order_id": ids[0]}).success
    r = s.tx("0xPQa", ExchangeOpType.CANCEL_ALL, {"scope": "spot"})
    assert r.success and r.data["cancelled"] == 2 and not s.m.trading.spot_triggers
    s.block()
    assert s.held("0xPQa", BASE) == 0 and s.held("0xPQa", QUOTE) == 0
    s.conserved()


def test_a_paused_token_holds_spot_triggers_back():
    s = Spot()

    class Paused:
        paused, symbol = True, "TKA"

    s.order("0xPQb", "buy", 95, 5)
    s.trigger("0xPQa", "sell", "stop_loss", 96, 1)
    s.order("0xPQc", "sell", 95, 1)
    real = s.m.tokens.get
    s.m.tokens.get = lambda tok: Paused() if tok == BASE else real(tok)
    assert s.block() == [] and len(s.m.trading.spot_triggers) == 1
    s.m.tokens.get = real
    assert [e["type"] for e in s.block()] == ["spot_trigger_fired"]


def test_spot_triggers_are_committed_and_roll_back_with_a_failed_batch():
    s = Spot()
    root = s.m.compute_state_root()
    bad = {"op": "PLACE_ORDER", "params": {"pair": PAIR, "side": "buy", "order_type": "limit",
                                           "price": "1", "amount": "1e12"}}
    trig = {"op": "PLACE_ORDER", "params": {"pair": PAIR, "side": "sell",
                                            "order_type": "stop_loss", "trigger_price": "90",
                                            "amount": "1"}}
    r = s.tx("0xPQa", ExchangeOpType.BATCH, {"actions": [trig, bad]})
    assert not r.success and not s.m.trading.spot_triggers and not s.m.trading.touched
    assert s.held("0xPQa", BASE) == 0
    assert s.tx("0xPQa", ExchangeOpType.BATCH, {"actions": [trig]}).success
    assert s.m.compute_state_root() != root
    s.m.verify_commitments()
    twin = copy.deepcopy(s.m.trading)
    assert twin.commitment() == s.m.trading.commitment()


# ── swaps: multi-hop, and matching paid per resting order ────────────────────

def _two_books():
    """Books TKA:TKB and TKB:TKC, each with asks from a maker; the taker holds TKA."""
    from qrdx.exchange.orderbook import SelfTradeAction

    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.enforce_orderbook_settlement = m.enforce_spot_settlement = True
    m.begin_block(1, float(T0))
    for pair in ("TKA:TKB", "TKB:TKC"):
        book = OrderBook(pool_id=pair, self_trade_action=SelfTradeAction.CANCEL_TAKER)
        m._order_books[pair] = book
        m.router.register_order_book(pair, book)
        escrow = m.orderbook_escrow_address(pair)
        for tok in pair.split(":"):
            m.set_available_token_balance(escrow, tok, D(0))
    for who in ("0xPQm", "0xPQt"):
        for tok in ("TKA", "TKB", "TKC"):
            m.set_available_token_balance(who, tok, D(10_000) if who == "0xPQm" else D(0))
    m.set_available_token_balance("0xPQt", "TKA", D(100))

    def place(pair, side, price, amount, n):
        r = m.process_transaction(ExchangeTransaction(
            op_type=ExchangeOpType.PLACE_ORDER, sender="0xPQm", nonce=m.get_nonce("0xPQm"),
            gas_limit=10 ** 6, params={"pair": pair, "side": side, "order_type": "limit",
                                       "price": str(price), "amount": str(amount)}))
        assert r.success, r.error

    # TKA→TKB: sell TKA into bids on TKA:TKB (2 TKB per TKA); TKB→TKC: buy TKC from asks on
    # TKB:TKC (TKB is the base there: sell TKB into its bids at 0.5 TKC per TKB).
    for i in range(5):
        place("TKA:TKB", "buy", 2, 10, i)
        place("TKB:TKC", "buy", "0.5", 20, i)
    return m


def _swap(m, gas=10 ** 6, **params):
    return m.process_transaction(ExchangeTransaction(
        op_type=ExchangeOpType.SWAP, sender="0xPQt", nonce=m.get_nonce("0xPQt"), gas_limit=gas,
        params=params))


def test_a_multi_hop_swap_spends_exactly_what_each_hop_bought(no_trading_fees):
    m = _two_books()
    r = _swap(m, path=["TKA", "TKB", "TKC"], amount_in="15", min_amount_out="15")
    assert r.success, r.error
    assert D(r.data["amount_out"]) == 15
    assert [D(h["amount_out"]) for h in r.data["hops"]] == [30, 15]
    d = m.token_balance_deltas()
    assert d[("0xPQt", "TKA")] == -15 and d.get(("0xPQt", "TKB"), 0) == 0
    assert d[("0xPQt", "TKC")] == 15
    # 2 hops; 2 makers on the first (10 + 5), 2 on the second (20 + 10).
    assert r.gas_used == 2 * EXCHANGE_GAS_COSTS[ExchangeOpType.SWAP] + 4 * EXCHANGE_GAS_PER_MAKER


def test_a_multi_hop_swap_short_of_its_minimum_changes_nothing():
    m = _two_books()
    before = (dict(m.token_balance_deltas()), m._order_books["TKA:TKB"].state_digest())
    r = _swap(m, path=["TKA", "TKB", "TKC"], amount_in="15", min_amount_out="16")
    assert not r.success and "Slippage" in r.error
    assert (dict(m.token_balance_deltas()), m._order_books["TKA:TKB"].state_digest()) == before


@pytest.mark.parametrize("path, error", [
    (["TKA"], "list of 2"), (["TKA", "TKB", "TKA"], "each token once"),
    (["TKA", "TKB", "TKC", "TKD", "TKE", "TKF"], "list of 2"),
])
def test_a_malformed_swap_path_is_refused(path, error):
    m = _two_books()
    r = _swap(m, path=path, amount_in="1")
    assert not r.success and error in r.error


def test_an_order_book_swap_visits_no_more_resting_orders_than_its_gas_pays_for(no_trading_fees):
    m = _two_books()
    base = EXCHANGE_GAS_COSTS[ExchangeOpType.SWAP]
    r = _swap(m, gas=base + 2 * EXCHANGE_GAS_PER_MAKER, token_in="TKA", token_out="TKB",
              amount_in="50")
    assert r.success and D(r.data["amount_in"]) == 20 and D(r.data["amount_out"]) == 40
    assert r.gas_used == base + 2 * EXCHANGE_GAS_PER_MAKER
    assert m.token_balance_deltas()[("0xPQt", "TKA")] == -20      # the rest stays with it


# ── TWAP ────────────────────────────────────────────────────────────────────

def _blocks(m, start, count, step=30, ledger=None):
    """Run ``count`` empty blocks ``step`` seconds apart from block time ``start``; return
    their tick events. ``ledger``: the token deltas of every block before each new one, added
    up (a block starts its own)."""
    from qrdx.exchange.block_processor import _execute_block_boundary_duties

    out = []
    for i in range(count):
        t = start + (i + 1) * step
        if ledger is not None:
            for key, d in m.token_balance_deltas().items():
                ledger[key] = ledger.get(key, 0) + d
        m.begin_block(1000 + t, float(t))
        _execute_block_boundary_duties(m, 1000 + t, float(t))
        out += m._block_tick_events
    return out


def _twap(m, sender, gas=10 ** 7, **params):
    return m.process_transaction(ExchangeTransaction(
        op_type=ExchangeOpType.TWAP_ORDER, sender=sender, nonce=m.get_nonce(sender),
        gas_limit=gas, params=params))


def test_a_perp_twap_works_its_size_in_slices_and_makes_up_what_a_slice_missed(mgr):
    from qrdx.exchange.block_processor import _execute_block_boundary_duties

    ch = mgr.clearinghouse
    r = _twap(mgr, "taker", market_id=MID, side="buy", size="6", duration=180, slices=6)
    assert r.success, r.error
    tid = r.data["twap_id"]
    from qrdx.exchange.trading import TWAP_SLICE_GAS
    assert r.gas_used == EXCHANGE_GAS_COSTS[ExchangeOpType.TWAP_ORDER] + 6 * (
        TWAP_SLICE_GAS + 5 * EXCHANGE_GAS_PER_MAKER)
    _execute_block_boundary_duties(mgr, 1, float(T0))          # slice 1: the book is empty
    first = [e for e in mgr._block_tick_events if e["type"] == "twap_slice"]
    assert first[0]["filled"] == "0"
    ch.place_order("maker", MID, "ask", "sell", D(10), D("100.5"), 0)
    events = _blocks(mgr, T0, 5)
    slices = [D(e["filled"]) for e in events if e["type"] == "twap_slice"]
    assert slices == [D("1.2")] * 5                            # 6 over the 5 slices left
    assert ch.accounts["taker"].positions[MID].size == 6
    assert [e["type"] for e in events][-1] == "twap_finished" and tid not in mgr.trading.twaps


def test_a_perp_twap_slice_stays_within_its_slippage(mgr):
    ch = mgr.clearinghouse
    ch.place_order("maker", MID, "far", "sell", D(10), D(104), 0)   # beyond 100 × 1.03
    r = _twap(mgr, "taker", market_id=MID, side="buy", size="2", duration=60, slices=2)
    events = _blocks(mgr, T0, 2)
    assert all(e["filled"] == "0" for e in events if e["type"] == "twap_slice")
    assert MID not in ch.accounts["taker"].positions
    assert r.data["twap_id"] not in mgr.trading.twaps


def test_a_reduce_only_twap_stops_when_the_position_is_gone(mgr):
    ch = mgr.clearinghouse
    _long(ch, size="1")
    ch.place_order("other", MID, "bid", "buy", D(10), D(99), 0)
    r = _twap(mgr, "taker", market_id=MID, side="sell", size="5", duration=150, slices=5,
              reduce_only=True)
    events = _blocks(mgr, T0, 3)
    assert MID not in ch.accounts["taker"].positions
    assert any(e["type"] == "twap_finished" for e in events)
    assert r.data["twap_id"] not in mgr.trading.twaps


def test_a_spot_twap_swaps_its_escrow_slice_by_slice_and_returns_what_is_left(no_trading_fees):
    m = _two_books()
    escrow = m.orderbook_escrow_address("TKA:TKB")
    r = _twap(m, "0xPQt", token_in="TKA", token_out="TKB", amount_in="40", duration=120,
              slices=4)
    assert r.success, r.error
    tid = r.data["twap_id"]
    d = m.token_balance_deltas()
    assert d[("0xPQt", "TKA")] == -40 and d[(escrow, "TKA")] == 40
    ledger = {}
    events = _blocks(m, T0 - 30, 2, ledger=ledger)            # two slices of 10 at 2
    assert [D(e["filled"]) for e in events if e["type"] == "twap_slice"] == [10, 10]
    assert m.process_transaction(ExchangeTransaction(
        op_type=ExchangeOpType.TWAP_CANCEL, sender="0xPQt", nonce=m.get_nonce("0xPQt"),
        gas_limit=10 ** 6, params={"twap_id": tid})).success
    for key, v in m.token_balance_deltas().items():
        ledger[key] = ledger.get(key, 0) + v
    assert ledger[("0xPQt", "TKB")] == 40
    assert ledger[("0xPQt", "TKA")] == -20 and ledger[(escrow, "TKA")] == 0  # 20 unspent back
    for tok in ("TKA", "TKB"):
        assert sum(v for (h, t), v in ledger.items() if t == tok) == 0


def test_twap_parameters_are_checked_and_the_slices_are_paid_for(mgr):
    base = dict(market_id=MID, side="buy", size="1")
    for params, error in [
        (dict(duration=30), "duration"),
        (dict(duration=600, slices=61), "slices"),
        (dict(duration=60, slices=3), "30 s apart"),
        (dict(duration=600, max_slippage="0.2"), "max_slippage"),
        (dict(duration=600, max_makers=21), "max_makers"),
        (dict(duration="600"), "whole number"),
    ]:
        r = _twap(mgr, "taker", **base, **params)
        assert not r.success and error in r.error, (params, r.error)
    r = _twap(mgr, "taker", gas=500_000, **base, duration=1800)    # 60 slices × 60,000
    assert not r.success and "needs" in r.error


def test_a_block_runs_a_bounded_number_of_twap_slices(mgr):
    from qrdx.exchange import trading as TR

    owners = [f"w{i}" for i in range(8)]
    for o in owners:
        mgr.clearinghouse.deposit(o, D(10_000))
        for _ in range(TR.TWAPS_PER_ACCOUNT):
            assert _twap(mgr, o, market_id=MID, side="buy", size="1", duration=600, slices=2,
                         max_makers=1).success
    events = _blocks(mgr, T0 - 30, 1)
    assert len([e for e in events if e["type"] == "twap_slice"]) == TR.TWAP_SLICES_PER_BLOCK
    events = _blocks(mgr, T0, 1)
    assert len([e for e in events if e["type"] == "twap_slice"]) == 80 - TR.TWAP_SLICES_PER_BLOCK


# ── everything at once, through the manager: undone exactly, and deterministic ──

def _manager_ops(rng, m, start, count, new_blocks=True):
    """Random trading operations and block ticks on a manager with a perp market (and new
    blocks — not inside an undo scope: a block's start is not an operation)."""
    from qrdx.exchange.block_processor import _execute_block_boundary_duties

    owners = ["a", "b", "c"]
    n = start
    for _ in range(count):
        n += 1
        who = rng.choice(owners)
        r = rng.random()
        side = rng.choice(["buy", "sell"])
        order = {"op": "PERP_ORDER", "params": {
            "market_id": MID, "side": side, "size": str(rng.randint(1, 4)),
            "price": str(rng.randint(95, 105)), "tif": rng.choice(["gtc", "ioc", "alo"])}}
        if r < 0.1:
            m.clearinghouse.set_oracle_price(MID, D(rng.randint(93, 107)),
                                             now=m._current_block_timestamp)
            _execute_block_boundary_duties(m, m._current_block_height,
                                           m._current_block_timestamp + rng.randint(0, 40))
            continue
        if r < 0.15:
            if new_blocks:
                m.begin_block(m._current_block_height + 1, m._current_block_timestamp + 30)
            continue
        if r < 0.35:
            op, params = ExchangeOpType.PERP_ORDER, order["params"]
        elif r < 0.45:
            op, params = ExchangeOpType.PERP_TRIGGER, {
                "market_id": MID, "side": side, "kind": rng.choice(["sl", "tp"]),
                "trigger_price": str(rng.randint(90, 110)), "size": str(rng.randint(1, 3)),
                "max_makers": rng.randint(1, 4)}
        elif r < 0.55:
            op, params = ExchangeOpType.TWAP_ORDER, {
                "market_id": MID, "side": side, "size": str(rng.randint(1, 5)),
                "duration": rng.choice([60, 90, 120]), "max_makers": rng.randint(1, 3)}
        elif r < 0.65:
            ids = sorted(set(m.clearinghouse.markets[MID].orders)
                         | set(m.clearinghouse.markets[MID].triggers))
            if not ids:
                continue
            op, params = ExchangeOpType.PERP_MODIFY, {
                "market_id": MID, "order_id": rng.choice(ids), "size": str(rng.randint(1, 3))}
        elif r < 0.72:
            twaps = m.trading.twaps_of(who)
            if not twaps:
                continue
            op, params = ExchangeOpType.TWAP_CANCEL, {"twap_id": rng.choice(twaps)}
        elif r < 0.78:
            op, params = ExchangeOpType.CANCEL_ALL, {"scope": rng.choice(["all", "perps"])}
        else:
            acts = [order] * rng.randint(1, 3)
            if rng.random() < 0.3:
                acts.append({"op": "PERP_ORDER", "params": {"market_id": MID, "side": "buy",
                                                            "size": "1e9", "price": "100"}})
            op, params = ExchangeOpType.BATCH, {"actions": acts}
        m.process_transaction(ExchangeTransaction(
            op_type=op, sender=who, nonce=m.get_nonce(who), params=params, gas_limit=10 ** 7))
    return n


def _fresh_manager():
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager()
    m.begin_block(1, float(T0))
    m.clearinghouse.create_market("BTC")
    m.clearinghouse.set_oracle_price(MID, D(100), now=T0)
    for o in ("a", "b", "c"):
        m.clearinghouse.deposit(o, D(100_000))
    return m


@pytest.mark.parametrize("seed", range(12))
def test_every_trading_operation_rolls_back_exactly_and_replays_identically(seed):
    a, b = _fresh_manager(), _fresh_manager()
    _manager_ops(random.Random(seed), a, 0, 120)
    _manager_ops(random.Random(seed), b, 0, 120)
    assert a.compute_state_root() == b.compute_state_root()       # same operations, same state
    rng = random.Random(seed + 100)
    root = a.compute_state_root()
    with pytest.raises(KeyError):
        with undo.atomic():
            _manager_ops(rng, a, 1000, 80, new_blocks=False)
            raise KeyError()
    assert a.compute_state_root() == root
    a.verify_commitments()
    _manager_ops(random.Random(seed + 7), a, 2000, 80)
    _manager_ops(random.Random(seed + 7), b, 2000, 80)
    assert a.compute_state_root() == b.compute_state_root()
    a.verify_commitments()
    assert a.clearinghouse.identity_gap() == 0


# ── fees: tiers by volume, maker rebates, referrals ─────────────────────────

def _fill(ch, maker, taker, size, price=100, n=[0]):
    n[0] += 1
    ch.place_order(maker, MID, f"f{n[0]}m", "sell", D(size), D(price), 0)
    return ch.place_order(taker, MID, f"f{n[0]}t", "buy", D(size), D(price), 0)


def test_rates_follow_the_accounts_volume_over_the_last_fourteen_days():
    ch = _house(("maker", "taker"))
    ch.deposit("maker", D(10 ** 12))
    ch.deposit("taker", D(10 ** 12))
    ch.new_block(T0)
    assert ch.fee_rates("taker") == (CH.TAKER_FEE_RATE, CH.MAKER_FEE_RATE)
    fills = _fill(ch, "maker", "taker", 60_000)                  # 6M of notional each
    assert {o: D(f) for o, f in fills[0]["fees"].items()} == {
        "maker": D(6_000_000) * CH.MAKER_FEE_RATE, "taker": D(6_000_000) * CH.TAKER_FEE_RATE}
    assert ch.volume("taker") == 6_000_000
    assert ch.fee_rates("taker") == (D("0.00045"), D("0.00016"))
    fills = _fill(ch, "maker", "taker", 1)
    assert D(fills[0]["fees"]["taker"]) == D(100) * D("0.00045")
    ch.new_block(T0 + 14 * 86400)                                # the window moves on
    assert ch.volume("taker") == 0 and ch.fee_rates("taker")[0] == CH.TAKER_FEE_RATE
    assert ch.identity_gap() == 0
    ch.verify_commitment()


def test_a_maker_rebate_is_paid_out_of_the_takers_fee(no_staker_fees):
    ch = _house(("maker", "taker"))
    for o in ("maker", "taker"):
        ch.deposit(o, D(10 ** 13))
    ch.new_block(T0)
    ch.volumes["maker"] = ((int(T0) // 86400, D(8_000_000_000)),)   # top tier
    vault = ch.account(CH.VAULT).collateral
    fills = _fill(ch, "maker", "taker", 10)
    assert D(fills[0]["fees"]["maker"]) == D(1000) * D("-0.00002")   # a rebate
    assert ch.account(CH.VAULT).collateral - vault == D(1000) * (CH.TAKER_FEE_RATE - D("0.00002"))
    rebates = [-mk for _v, _t, mk in CH.FEE_TIERS if mk < 0]
    assert all(t >= max(rebates) for _v, t, _mk in CH.FEE_TIERS)  # every taker fee covers it
    assert ch.identity_gap() == 0


def test_a_referee_pays_less_and_its_referrer_shares_its_fees(mgr):
    ch = mgr.clearinghouse

    def op(sender, kind, code):
        return mgr.process_transaction(ExchangeTransaction(
            op_type=kind, sender=sender, nonce=mgr.get_nonce(sender), params={"code": code},
            gas_limit=10 ** 6))

    assert op("other", ExchangeOpType.REFERRAL_REGISTER, "friends").success
    assert not op("maker", ExchangeOpType.REFERRAL_REGISTER, "friends").success   # taken
    assert not op("other", ExchangeOpType.REFERRAL_JOIN, "friends").success       # itself
    assert op("taker", ExchangeOpType.REFERRAL_JOIN, "friends").data["referrer"] == "other"
    assert not op("taker", ExchangeOpType.REFERRAL_JOIN, "friends").success       # once
    before = {o: ch.accounts[o].collateral for o in ("other", CH.VAULT) if o in ch.accounts}
    fills = _fill(ch, "maker", "taker", 10)
    fee = (D(1000) * CH.TAKER_FEE_RATE * (1 - CH.REFEREE_DISCOUNT)).quantize(CH.FEE_QUANTUM)
    assert D(fills[0]["fees"]["taker"]) == fee
    reward = (fee * CH.REFERRER_SHARE).quantize(CH.FEE_QUANTUM)
    assert ch.accounts["other"].collateral - before["other"] == reward
    ch.volumes["maker"] = ((0, D(0)),)
    _fill(ch, "taker", "maker", 200)                             # 20,000 of volume
    r = op("maker", ExchangeOpType.REFERRAL_JOIN, "friends")
    assert not r.success and "before" in r.error                # too late to join
    assert ch.identity_gap() == 0


def test_the_views_show_triggers_twaps_fees_and_vaults(mgr):
    from qrdx.exchange import views

    _tx(mgr, "taker", ExchangeOpType.PERP_TRIGGER, {
        "market_id": MID, "side": "sell", "kind": "sl", "trigger_price": "90", "size": "1"})
    assert _tx(mgr, "taker", ExchangeOpType.TWAP_ORDER, {
        "market_id": MID, "side": "buy", "size": "2", "duration": 600}, gas=2_000_000).success
    r = _tx(mgr, "maker", ExchangeOpType.VAULT_CREATE, {"amount": "500", "name": "v"})
    acct = views.account(mgr, "taker")
    assert [t["kind"] for t in acct["triggers"]] == ["sl"] and len(acct["twaps"]) == 1
    assert acct["fees"]["taker"] == str(CH.TAKER_FEE_RATE) and acct["fees"]["volume"] == "0"
    vault = views.user_vault(mgr, r.data["vault"], holder="maker")
    assert vault["leader"] == "maker" and vault["holding"]["shares"] == "500"
    assert [v["vault"] for v in views.user_vaults(mgr, leader="maker")] == [r.data["vault"]]
    assert views.fee_schedule(mgr)["tiers"][0]["taker"] == str(CH.TAKER_FEE_RATE)


async def test_what_the_tick_settles_in_a_block_without_exchange_transactions_reaches_the_ledger(no_trading_fees):
    """A spot trigger fires in the tick of a block that carries no exchange transactions: its
    token moves must be flushed like a section's (every path ticks such a block through
    ``tick_and_flush``), or the ledger would disagree with the exchange's records."""
    from qrdx.exchange.block_processor import tick_and_flush

    class Ledger:
        def __init__(self):
            self.tokens, self.native = {}, {}

        async def apply_token_registry_op(self, op):
            pass

        async def apply_token_balance_delta(self, token, holder, delta):
            self.tokens[(holder, token)] = self.tokens.get((holder, token), 0) + delta

        async def apply_account_balance_delta(self, addr, delta):
            self.native[addr] = self.native.get(addr, 0) + delta
            return True

    s = Spot()
    s.order("0xPQb", "buy", 95, 10)
    s.trigger("0xPQa", "sell", "stop_loss", 96, 4)
    s.order("0xPQc", "sell", 95, 1)                               # the price reaches it…
    s.m.commit_block()
    ledger = Ledger()
    await tick_and_flush(ledger, s.height + 1, float(T0 + s.height + 1), s.m)  # …next block
    assert ledger.tokens[("0xPQa", QUOTE)] == 4 * 95
    assert ledger.tokens[(s.escrow, BASE)] == -4
    assert sum(v for (_h, t), v in ledger.tokens.items() if t == BASE) == 0
