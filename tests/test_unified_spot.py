"""
Unified spot liquidity (docs/UNIFIED_SPOT_LIQUIDITY.md): a pair's order book and pools are one
market. Each test names what went wrong before:

* a swap never went through a third token, even when A→QRDX→B paid twice what A→B did;
* a swap used one pool or the book, never several at once;
* a limit order only matched the book, and rested while a pool sold below its limit;
* a swap pushed a pool's price past resting orders without filling them;
* spot stops and take-profits never saw a pool's trades, nor a move that came back by the
  block's end.
"""
import random
from decimal import Decimal

import pytest

from qrdx import constants
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction, views

D = Decimal
ALICE, BOB, CAROL, DAVE = ("0xPQ" + c * 64 for c in "abcd")
A, B, USD = "0x" + "11" * 20, "0x" + "22" * 20, "0x" + "33" * 20  # sorted: A < B < USD < QRDX
T = 1_700_000_000


@pytest.fixture(autouse=True)
def _fee_free(no_trading_fees):
    """The exchange's spot fees off, so amounts are exact; the pools keep their own fees."""


_nonces = {}


def _tx(sender, op, gas_limit=10_000_000, **params):
    n = _nonces.get(sender, 0)
    _nonces[sender] = n + 1
    return ExchangeTransaction(op_type=op, sender=sender, nonce=n, params=params,
                               gas_limit=gas_limit, gas_price=10**9)


def _run(m, sender, op, **params):
    return m.process_transaction(_tx(sender, op, **params))


def _ok(m, sender, op, **params):
    r = _run(m, sender, op, **params)
    assert r.success, r.error
    return r


@pytest.fixture
def mgr():
    _nonces.clear()
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.enforce_spot_settlement = True
    m.enforce_orderbook_settlement = True
    for who in (ALICE, BOB, CAROL, DAVE):
        m.set_available_balance(who, D(100_000_000))
        for t in (A, B, USD):
            m.set_available_token_balance(who, t, D(100_000_000))
    m.begin_block(1, float(T))
    yield m
    ExchangeStateManager.reset_instance()


def _pool(m, t0, t1, price, tier=3000, liquidity="1000000", lo=-60000, hi=60000, add=True):
    """A pool of the canonical pair (t0 < t1) at ``price`` t1 per t0; its holder and the pair's
    book escrow start empty."""
    r = _ok(m, ALICE, ExchangeOpType.CREATE_POOL, token0=t0, token1=t1, fee_tier=tier,
            pool_type="STANDARD", initial_price=str(price), stake_amount="10000")
    pid = r.data["pool_id"]
    for who in (m.pool_holder_address(pid), m.orderbook_escrow_address(f"{t0}:{t1}")):
        for t in (t0, t1):
            if t == "QRDX":
                if m.available_balance(who) is None:
                    m.set_available_balance(who, D(0))
            elif m.available_token_balance(who, t) is None:
                m.set_available_token_balance(who, t, D(0))
    if add:
        _ok(m, ALICE, ExchangeOpType.ADD_LIQUIDITY, pool_id=pid, tick_lower=lo, tick_upper=hi,
            amount=liquidity)
    return pid


def _net(m, who, token):
    if token == "QRDX":
        return m.balance_deltas().get(who, D(0))
    return m.token_balance_deltas().get((who, token), D(0))


def _eff_buy(pool):
    """What a pool charges a buyer of its token0 at the margin, fee included."""
    return pool.state.price / (1 - pool.state.fee_tier.rate)


def _tick(m, seconds=1):
    """The block's tick, as every node runs it: crossed orders, then spot triggers."""
    now = D(int(m._block_clock()) + seconds)
    return m.uncross_spot_books(now) + m.fire_spot_triggers(now)


# ── 1. a swap takes the best path ──────────────────────────────────────────

def test_a_swap_goes_through_qrdx_when_that_pays_more(mgr):
    """The case the user described: A trades with B at 1, A with QRDX at 2 and QRDX with B at
    1 — so A→QRDX→B pays about twice what A→B does. A swap from A to B used to take A→B."""
    _pool(mgr, A, B, 1)
    _pool(mgr, A, "QRDX", 2)
    _pool(mgr, B, "QRDX", 1)
    direct = mgr.router.best_route(A, B, D(100), BOB).amount_out
    qrdx_before = _net(mgr, BOB, "QRDX")
    r = _ok(mgr, BOB, ExchangeOpType.SWAP, token_in=A, token_out=B, amount_in="100")
    assert r.data["path"] == [A, "QRDX", B]
    assert D(r.data["amount_out"]) > direct * D("1.9")
    assert _net(mgr, BOB, "QRDX") == qrdx_before         # the hub passes through
    assert _net(mgr, BOB, B) == D(r.data["amount_out"])


def test_the_settlement_asset_is_a_hub_too(mgr, monkeypatch):
    monkeypatch.setattr(constants, "PERP_COLLATERAL_TOKEN", USD)
    assert mgr.routing_hubs() == ["QRDX", USD]
    _pool(mgr, A, B, 1)
    _pool(mgr, A, USD, 3)
    _pool(mgr, B, USD, 1)
    r = _ok(mgr, BOB, ExchangeOpType.SWAP, token_in=A, token_out=B, amount_in="10")
    assert r.data["path"] == [A, USD, B]


def test_a_swap_named_to_a_pool_or_a_venue_stays_on_its_pair(mgr):
    direct = _pool(mgr, A, B, 1)
    _pool(mgr, A, "QRDX", 2)
    _pool(mgr, B, "QRDX", 1)
    for how in ({"pool_id": direct}, {"venue": "amm"}):
        r = _ok(mgr, BOB, ExchangeOpType.SWAP, token_in=A, token_out=B, amount_in="10", **how)
        assert "path" not in r.data and r.data["pool_id"] == direct
    r = _ok(mgr, BOB, ExchangeOpType.SWAP, path=[A, B], amount_in="10")
    assert "path" not in r.data


def test_a_two_hop_route_needs_gas_for_both_hops(mgr):
    _pool(mgr, A, B, 1)
    _pool(mgr, A, "QRDX", 2)
    _pool(mgr, B, "QRDX", 1)
    from qrdx.exchange.transactions import EXCHANGE_GAS_COSTS

    one_hop = EXCHANGE_GAS_COSTS[ExchangeOpType.SWAP]
    r = mgr.process_transaction(_tx(BOB, ExchangeOpType.SWAP, gas_limit=one_hop + 1000,
                                    token_in=A, token_out=B, amount_in="10"))
    assert r.success and "path" not in r.data                    # only the pair fits its gas


# ── 2. pools at the same price share the fill ──────────────────────────────

def test_a_swap_splits_between_pools_to_one_marginal_price(mgr):
    """Two pools of one pair: a swap used to put everything into whichever quoted best."""
    cheap = _pool(mgr, A, B, 1, tier=500, liquidity="200000")
    deep = _pool(mgr, A, B, 1, tier=3000, liquidity="2000000")
    alone = max(mgr.router.best_route(B, A, D(5000), BOB, pool_id=p).amount_out
                for p in (cheap, deep))
    r = _ok(mgr, BOB, ExchangeOpType.SWAP, token_in=B, token_out=A, amount_in="5000")
    assert {f["pool_id"] for f in r.data["fills"]} == {cheap, deep}
    assert D(r.data["amount_out"]) > alone
    pools = [mgr.pool_manager.get_pool(p) for p in (cheap, deep)]
    a, b = (_eff_buy(p) for p in pools)
    assert abs(a - b) / a < D("1e-9")                            # one marginal price


# ── 3. no swap trades through a resting order ──────────────────────────────

def test_a_swap_fills_a_resting_bid_before_pushing_the_pool_past_it(mgr):
    pid = _pool(mgr, A, B, 1, liquidity="100000")
    pair = f"{A}:{B}"
    _ok(mgr, CAROL, ExchangeOpType.PLACE_ORDER, pair=pair, side="buy", order_type="limit",
        price="0.99", amount="20")
    for how in ({}, {"pool_id": pid}, {"venue": "amm"}):
        before = _net(mgr, CAROL, A)
        r = _ok(mgr, BOB, ExchangeOpType.SWAP, token_in=A, token_out=B, amount_in="1000", **how)
        venues = {f["venue"] for f in r.data["fills"]}
        if before == 0:                                          # (the first swap fills her)
            assert venues == {"clob", "amm"} and _net(mgr, CAROL, A) == 20
        assert mgr.pool_manager.get_pool(pid).state.price < D("0.99")
    book = mgr._order_books[pair]
    assert not book._orders                                      # the bid filled, whole


# ── 4. a limit order takes from the pools first ────────────────────────────

def test_a_limit_buy_above_the_pool_buys_from_the_pool(mgr):
    """A buy at 1.10 rested on the book while the pool sold at 1.003: anyone could buy from
    the pool and sell to it at 1.10."""
    _pool(mgr, A, B, 1)
    pair = f"{A}:{B}"
    r = _ok(mgr, BOB, ExchangeOpType.PLACE_ORDER, pair=pair, side="buy", order_type="limit",
            price="1.10", amount="10")
    assert D(r.data["filled"]) == 10 and r.data["fills"][0]["venue"] == "amm"
    assert not mgr._order_books[pair]._orders                   # nothing rests
    paid = -_net(mgr, BOB, B)
    assert D("10.02") < paid < D("10.04")                        # ~1.003 each, not 1.10
    assert _net(mgr, BOB, A) == 10


def test_what_the_pools_cannot_fill_within_the_limit_rests(mgr):
    pid = _pool(mgr, A, B, 1, liquidity="10000")
    pair = f"{A}:{B}"
    r = _ok(mgr, BOB, ExchangeOpType.PLACE_ORDER, pair=pair, side="buy", order_type="limit",
            price="1.01", amount="500")
    filled = D(r.data["filled"])
    assert 0 < filled < 500
    pool = mgr.pool_manager.get_pool(pid)
    assert abs(_eff_buy(pool) - D("1.01")) < D("1e-12")         # the pool went to the limit …
    (order,) = mgr._order_books[pair]._orders.values()
    assert order.remaining == 500 - filled                       # … and the rest rests
    escrow = mgr.orderbook_escrow_address(pair)
    assert _net(mgr, escrow, B) == order.remaining * D("1.01")


def test_a_post_only_order_that_would_take_from_a_pool_is_refused(mgr):
    pid = _pool(mgr, A, B, 1)
    digest = mgr.pool_manager.get_pool(pid).state_digest()
    r = _run(mgr, BOB, ExchangeOpType.PLACE_ORDER, pair=f"{A}:{B}", side="buy",
             order_type="limit", price="1.10", amount="10", tif="alo")
    assert not r.success and "pool" in r.error
    assert mgr.pool_manager.get_pool(pid).state_digest() == digest


def test_fill_or_kill_counts_the_pools(mgr):
    pid = _pool(mgr, A, B, 1, liquidity="10000")
    pool = mgr.pool_manager.get_pool(pid)
    digest = pool.state_digest()
    r = _run(mgr, BOB, ExchangeOpType.PLACE_ORDER, pair=f"{A}:{B}", side="buy",
             order_type="limit", price="1.01", amount="500", tif="fok")
    assert not r.success                                          # the pool cannot fill it whole
    assert pool.state_digest() == digest and _net(mgr, BOB, A) == 0
    r = _ok(mgr, BOB, ExchangeOpType.PLACE_ORDER, pair=f"{A}:{B}", side="buy",
            order_type="limit", price="1.01", amount="5", tif="fok")
    assert D(r.data["filled"]) == 5


def test_an_attached_tp_sl_holds_what_a_pool_fill_bought(mgr):
    _pool(mgr, A, B, 1)
    pair = f"{A}:{B}"
    r = _ok(mgr, BOB, ExchangeOpType.PLACE_ORDER, pair=pair, side="buy", order_type="limit",
            price="1.10", amount="10", tp={"trigger_price": "1.5"}, sl={"trigger_price": "0.5"})
    bracket = mgr.trading.spot_triggers.peek(r.data["attached"])
    assert bracket.amount == 10 and _net(mgr, BOB, A) == 0       # in the bracket's escrow


# ── 5. resting orders fill when new liquidity crosses them ─────────────────

def test_a_resting_bid_fills_when_a_pool_opens_below_it(mgr):
    """A bid at 0.9 stayed unfilled while a pool sold at 0.5."""
    pid = _pool(mgr, A, B, "0.5", add=False)                     # no liquidity yet
    pair = f"{A}:{B}"
    r = _ok(mgr, CAROL, ExchangeOpType.PLACE_ORDER, pair=pair, side="buy", order_type="limit",
            price="0.9", amount="100")
    assert D(r.data["filled"]) == 0
    escrow = mgr.orderbook_escrow_address(pair)
    assert _net(mgr, escrow, B) == 90
    _ok(mgr, ALICE, ExchangeOpType.ADD_LIQUIDITY, pool_id=pid, tick_lower=-60000,
        tick_upper=60000, amount="1000000")
    (event,) = _tick(mgr)
    assert event["type"] == "spot_uncross" and D(event["amount"]) == 100
    assert not mgr._order_books[pair]._orders
    assert _net(mgr, CAROL, A) == 100
    paid = D(event["paid"])
    assert paid < 60 and -_net(mgr, CAROL, B) == paid            # the pool's price, not 0.9
    assert _net(mgr, escrow, B) == 0                             # the rest came back
    assert _tick(mgr) == []                                      # once


def test_a_resting_ask_fills_when_a_pool_opens_above_it(mgr):
    pid = _pool(mgr, A, B, "2", add=False)
    pair = f"{A}:{B}"
    _ok(mgr, CAROL, ExchangeOpType.PLACE_ORDER, pair=pair, side="sell", order_type="limit",
        price="1.5", amount="10")
    _ok(mgr, ALICE, ExchangeOpType.ADD_LIQUIDITY, pool_id=pid, tick_lower=-60000,
        tick_upper=60000, amount="1000000")
    (event,) = _tick(mgr)
    assert D(event["amount"]) == 10 and _net(mgr, CAROL, B) > 19   # ~2 each, not 1.5
    assert _net(mgr, CAROL, A) == -10


def test_more_crossed_orders_than_a_block_fills_wait_for_the_next(mgr):
    from qrdx.exchange.trading import SPOT_UNCROSS_ORDERS_PER_BLOCK as LIMIT

    pid = _pool(mgr, A, B, "0.5", add=False)
    pair = f"{A}:{B}"
    for i in range(LIMIT + 8):
        _ok(mgr, (CAROL, DAVE)[i % 2], ExchangeOpType.PLACE_ORDER, pair=pair, side="buy",
            order_type="limit", price="0.9", amount="1")
    _ok(mgr, ALICE, ExchangeOpType.ADD_LIQUIDITY, pool_id=pid, tick_lower=-60000,
        tick_upper=60000, amount="1000000")
    assert len(_tick(mgr)) == LIMIT
    assert pair in mgr.trading.uncross                           # (committed: it survives)
    mgr.begin_block(2, float(T + 1))
    assert len(_tick(mgr)) == 8
    assert not mgr._order_books[pair]._orders and pair not in mgr.trading.uncross


def test_a_trader_who_sells_past_its_own_bid_has_that_bid_filled_by_the_pool(mgr):
    """Self-trade prevention closes the book to a taker at its own order; the pools may still
    fill it, past that order. The order would then rest crossed — anyone could buy from the
    pool and sell to it — so the tick fills it from the pool instead."""
    pid = _pool(mgr, A, B, 1, liquidity="100000")
    pair = f"{A}:{B}"
    _ok(mgr, BOB, ExchangeOpType.PLACE_ORDER, pair=pair, side="buy", order_type="limit",
        price="0.99", amount="10")
    r = _ok(mgr, BOB, ExchangeOpType.SWAP, token_in=A, token_out=B, amount_in="2000")
    assert {f["venue"] for f in r.data["fills"]} == {"amm"}
    assert mgr.pool_manager.get_pool(pid).state.price < D("0.99")
    (event,) = _tick(mgr)
    assert event["owner"] == BOB and D(event["amount"]) == 10
    assert not mgr._order_books[pair]._orders


# ── 6. stops and take-profits see the pools ────────────────────────────────

def _stop(m, who, trigger, amount="10"):
    r = _ok(m, who, ExchangeOpType.PLACE_ORDER, pair=f"{A}:{B}", side="sell",
            order_type="stop_loss", trigger_price=str(trigger), amount=amount)
    return r.data["order_id"]


def test_a_stop_loss_fires_when_a_pool_trades_through_it(mgr):
    """The pair traded only in its pool, so the book's last price never moved and the stop
    never fired."""
    _pool(mgr, A, B, 1)
    tid = _stop(mgr, CAROL, "0.95")
    _ok(mgr, BOB, ExchangeOpType.SWAP, token_in=A, token_out=B, amount_in="80000")
    assert mgr.pair_price(f"{A}:{B}") < D("0.95")
    events = _tick(mgr)
    assert [e["trigger_id"] for e in events if e["type"] == "spot_trigger_fired"] == [tid]
    assert tid not in mgr.trading.spot_triggers
    assert _net(mgr, CAROL, B) > 8                               # sold, at the pool's price


def test_a_stop_reached_within_a_block_fires_though_the_price_came_back(mgr):
    _pool(mgr, A, B, 1)
    tid = _stop(mgr, CAROL, "0.95")
    r = _ok(mgr, BOB, ExchangeOpType.SWAP, token_in=A, token_out=B, amount_in="80000")
    _ok(mgr, BOB, ExchangeOpType.SWAP, token_in=B, token_out=A, amount_in=r.data["amount_out"])
    assert mgr.pair_price(f"{A}:{B}") > D("0.95")                # back by the block's end
    assert mgr.trading.spot_triggers.peek(tid).reached == "sl"
    assert any(e.get("trigger_id") == tid for e in _tick(mgr))


def test_a_move_before_a_stop_was_placed_does_not_fire_it(mgr):
    _pool(mgr, A, B, 1)
    r = _ok(mgr, BOB, ExchangeOpType.SWAP, token_in=A, token_out=B, amount_in="80000")
    _ok(mgr, BOB, ExchangeOpType.SWAP, token_in=B, token_out=A, amount_in=r.data["amount_out"])
    tid = _stop(mgr, CAROL, "0.95")
    assert _tick(mgr) == [] and tid in mgr.trading.spot_triggers


def test_a_stop_the_pool_price_is_already_past_is_refused(mgr):
    _pool(mgr, A, B, 1)                                          # never traded: the pool's price
    r = _run(mgr, CAROL, ExchangeOpType.PLACE_ORDER, pair=f"{A}:{B}", side="sell",
             order_type="stop_loss", trigger_price="1.05", amount="10")
    assert not r.success and "already reached" in r.error


def test_a_fired_stop_sells_into_the_pools(mgr):
    """A fired trigger used to place its order on the book only: with no bids it sold nothing."""
    _pool(mgr, A, B, 1)
    tid = _stop(mgr, CAROL, "0.95")
    _ok(mgr, BOB, ExchangeOpType.SWAP, token_in=A, token_out=B, amount_in="80000")
    (fired,) = [e for e in _tick(mgr) if e.get("trigger_id") == tid]
    assert {f["venue"] for f in fired["fills"]} == {"amm"} and not fired["resting"]


def test_a_stop_the_price_gapped_past_waits_and_sells_when_it_comes_back(mgr):
    """Seen live: one swap took the price from 0.50 to 0.34, past the stop's 10 % band, and the
    stop fired, filled nothing and was gone. It now waits, holding its escrow, and sells once
    the price is back within its band (the user's choice, 2026-10-27)."""
    _pool(mgr, A, B, 1)
    tid = _stop(mgr, CAROL, "0.95")                              # band: no less than 0.855
    r = _ok(mgr, BOB, ExchangeOpType.SWAP, token_in=A, token_out=B, amount_in="200000")
    assert mgr.pair_price(f"{A}:{B}") < D("0.85")
    (fired,) = [e for e in _tick(mgr) if e.get("trigger_id") == tid]
    assert fired["waiting"] and D(fired["filled"]) == 0
    t = mgr.trading.spot_triggers.peek(tid)
    assert t.waiting and t.amount == 10 and t.escrowed == 10
    assert _tick(mgr) == []                                       # still out of its band
    back = D(r.data["amount_out"]) * D("0.6")
    _ok(mgr, BOB, ExchangeOpType.SWAP, token_in=B, token_out=A, amount_in=str(back))
    assert mgr.pair_price(f"{A}:{B}") > D("0.855")
    (fired,) = [e for e in _tick(mgr) if e.get("trigger_id") == tid]
    assert D(fired["filled"]) == 10 and not fired["waiting"]
    assert tid not in mgr.trading.spot_triggers and _net(mgr, CAROL, B) > D("8.5")


# ── 7. all or nothing, and the quote ───────────────────────────────────────

def test_a_failed_two_hop_swap_puts_every_pool_back(mgr):
    """A swap that missed its min_amount_out after its first hop left that pool moved (the
    pool's snapshot was not part of the operation's undo)."""
    pools = [_pool(mgr, A, B, 1), _pool(mgr, A, "QRDX", 2), _pool(mgr, B, "QRDX", 1)]
    before = [mgr.pool_manager.get_pool(p).state_digest() for p in pools]
    deltas = (mgr.token_balance_deltas(), mgr.balance_deltas())
    r = _run(mgr, BOB, ExchangeOpType.SWAP, path=[A, "QRDX", B], amount_in="100",
             min_amount_out="1000")
    assert not r.success and "Slippage" in r.error
    assert [mgr.pool_manager.get_pool(p).state_digest() for p in pools] == before
    assert mgr.token_balance_deltas() == deltas[0]


def test_a_failed_batch_puts_its_swaps_pool_back(mgr):
    """Found on this change, on the code before it: a batch whose swap succeeded and whose next
    action failed was undone — every balance — except the pool, which kept the swap's price.
    Anyone could move a pool's price for free with a batch built to fail, then trade against
    it at the liquidity providers' expense."""
    pid = _pool(mgr, A, "QRDX", 2)
    pool = mgr.pool_manager.get_pool(pid)
    before = (pool.state.price, pool.state_digest(), mgr.balance_deltas(),
              mgr.token_balance_deltas())
    r = _run(mgr, BOB, ExchangeOpType.BATCH, actions=[
        {"op": "SWAP", "params": {"token_in": A, "token_out": "QRDX", "amount_in": "1000"}},
        {"op": "CANCEL_ORDER", "params": {"order_id": "none"}}])
    assert not r.success
    pool = mgr.pool_manager.get_pool(pid)
    assert (pool.state.price, pool.state_digest(), mgr.balance_deltas(),
            mgr.token_balance_deltas()) == before


def test_the_quote_shows_the_path_and_the_legs(mgr):
    _pool(mgr, A, B, 1)
    _pool(mgr, A, "QRDX", 2)
    _pool(mgr, B, "QRDX", 1)
    q = views.quote(mgr, A, B, "100", BOB)
    assert q["path"] == [A, "QRDX", B] and len(q["hops"]) == 2
    assert all(leg["venue"] == "amm" for hop in q["hops"] for leg in hop["legs"])
    r = _ok(mgr, BOB, ExchangeOpType.SWAP, token_in=A, token_out=B, amount_in="100")
    assert r.data["amount_out"] == q["amount_out"]               # the quote is what executes


# ── 8. invariants under random trading ─────────────────────────────────────

def _resting_escrow(m, pair):
    base, quote = pair.split(":")
    book = m._order_books[pair]
    held = {base: D(0), quote: D(0)}
    for o in book._orders.values():
        if o.side.value == "buy":
            held[quote] += o.remaining * o.price
        else:
            held[base] += o.remaining
    for t in m.trading.spot_triggers.peek_values() if hasattr(
            m.trading.spot_triggers, "peek_values") else []:
        if t.pair == pair:
            held[quote if t.side == "buy" else base] += t.escrowed
    return held


@pytest.mark.parametrize("seed", range(6))
def test_random_trading_keeps_escrow_whole_and_the_book_uncrossed(mgr, seed):
    rng = random.Random(seed)
    pair = f"{A}:{B}"
    pools = [_pool(mgr, A, B, 1, tier=t, liquidity=str(rng.randint(5_000, 500_000)))
             for t in rng.sample([500, 3000, 10000], 2)]
    escrow = mgr.orderbook_escrow_address(pair)
    who = [BOB, CAROL, DAVE]
    for _step in range(120):
        w = rng.choice(who)
        kind = rng.random()
        price = D(rng.randint(85, 115)) / 100
        if kind < 0.30:
            a, b = (A, B) if rng.random() < 0.5 else (B, A)
            r = _run(mgr, w, ExchangeOpType.SWAP, token_in=a, token_out=b,
                     amount_in=str(rng.randint(1, 3000)))
        elif kind < 0.65:
            r = _run(mgr, w, ExchangeOpType.PLACE_ORDER, pair=pair,
                     side=rng.choice(["buy", "sell"]), order_type="limit", price=str(price),
                     amount=str(rng.randint(1, 2000)))
        elif kind < 0.75:
            book = mgr._order_books[pair]
            mine = [o.id for o in book._orders.values() if o.owner == w]
            if mine:
                _ok(mgr, w, ExchangeOpType.CANCEL_ORDER, pair=pair, order_id=rng.choice(mine))
            continue
        elif kind < 0.83:  # a stop or a take-profit (refused if the price is already past it)
            r = _run(mgr, w, ExchangeOpType.PLACE_ORDER, pair=pair,
                     side=rng.choice(["buy", "sell"]),
                     order_type=rng.choice(["stop_loss", "take_profit"]),
                     trigger_price=str(price), amount=str(rng.randint(1, 500)))
        elif kind < 0.90:
            pid = rng.choice(pools)
            _ok(mgr, ALICE, ExchangeOpType.ADD_LIQUIDITY, pool_id=pid,
                tick_lower=rng.choice([-6000, -1200, 600]), tick_upper=rng.choice([1200, 6000]),
                amount=str(rng.randint(1000, 100000)))
            _tick(mgr)
        else:
            _tick(mgr)
            continue
        assert r.success or r.error, r
        # The escrow holds exactly what the resting orders and triggers lock.
        held = _resting_escrow(mgr, pair)
        assert _net(mgr, escrow, A) == held[A] and _net(mgr, escrow, B) == held[B]
    _tick(mgr)
    # No resting order is crossed with a pool (beyond rounding): bids at most the pools' asks
    # (fee included), asks at least their bids.
    book = mgr._order_books[pair]
    live = [mgr.pool_manager.get_pool(p) for p in pools]
    live = [p for p in live if p.state.liquidity > 0]
    if live and book.best_bid is not None:
        assert book.best_bid <= min(_eff_buy(p) for p in live) * (1 + D("1e-9"))
    if live and book.best_ask is not None:
        assert book.best_ask >= max(p.state.price * (1 - p.state.fee_tier.rate)
                                    for p in live) * (1 - D("1e-9"))
    # Every liquidity provider can still take everything out.
    for pid in pools:
        pool = mgr.pool_manager.get_pool(pid)
        for pos_id in list(pool.state.positions):
            _ok(mgr, ALICE, ExchangeOpType.REMOVE_LIQUIDITY, pool_id=pid, position_id=pos_id)
        holder = mgr.pool_holder_address(pid)
        assert _net(mgr, holder, A) >= 0 and _net(mgr, holder, B) >= 0
