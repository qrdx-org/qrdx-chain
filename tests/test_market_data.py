"""
Market data for interfaces — one shape for every market, spot pairs and perps:

* every trade is recorded when its block commits — spot order-book fills, AMM swaps and perps
  fills (liquidations too) — with the taker's side, the venue and the transaction;
* candles and 24-hour statistics by block time;
* the order book at level 2 (price levels with running totals) and level 3 (every resting
  order, in time priority), top of book, spread and mid;
* the surfaces: views, ``market_*`` JSON-RPC, and the ``orderbook`` / ``trades`` / ``tickers``
  stream channels.
"""
from decimal import Decimal

import pytest

from qrdx import constants
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import block_processor as BP
from qrdx.exchange import views
from qrdx.exchange.market_data import MAX_TRADES, MarketData
from qrdx.exchange.tokens import NATIVE_ASSET

D = Decimal
LP, TRADER, MAKER, MAKER2 = ("0xPQ" + c * 64 for c in "abcd")
T0 = 1_700_000_000 // 86400 * 86400
_nonces = {}


# ── the store ──────────────────────────────────────────────────────────────

def test_candles_bucket_trades_by_block_time():
    md = MarketData()
    for t, price, amount in ((T0 + 5, "10", "1"), (T0 + 30, "12", "2"), (T0 + 59, "9", "1"),
                             (T0 + 61, "11", "3")):
        md.record_trade("A:B", price=price, amount=amount, side="buy", block_height=1,
                        block_time=t, venue="clob")
    one = md.candles("A:B", "1m")
    assert [(c["time"], c["open"], c["high"], c["low"], c["close"], c["volume"], c["trades"])
            for c in one] == [(T0, "10", "12", "9", "9", "4", 3), (T0 + 60, "11", "11", "11", "11", "3", 1)]
    assert one[0]["quote_volume"] == "43"                       # 10 + 24 + 9
    (five,) = md.candles("A:B", "5m")
    assert (five["open"], five["close"], five["volume"], five["trades"]) == ("10", "11", "7", 4)
    assert md.candles("A:B", "1m", limit=1)[0]["time"] == T0 + 60
    assert md.candles("A:B", "1m", end=T0)[-1]["time"] == T0
    with pytest.raises(ValueError):
        md.candles("A:B", "2m")
    assert md.candles("X:Y") == []


def test_24h_stats_roll_with_block_time():
    md = MarketData()
    md.record_trade("A:B", price="100", amount="1", side="buy", block_height=1,
                    block_time=T0, venue="amm")
    md.record_trade("A:B", price="110", amount="2", side="sell", block_height=2,
                    block_time=T0 + 3600, venue="amm")
    s = md.stats_24h("A:B")
    assert (s["last_price"], s["open_24h"], s["high_24h"], s["low_24h"]) == ("110", "100", "110", "100")
    assert (s["change_24h"], s["change_pct_24h"], s["volume_24h"], s["quote_volume_24h"],
            s["trades_24h"]) == ("10", "10.00", "3", "320", 2)
    md.advance(T0 + 86400 + 120)              # a day of blocks later: the first trade has aged out
    s = md.stats_24h("A:B")
    assert (s["open_24h"], s["volume_24h"], s["trades_24h"]) == ("110", "2", 1)
    md.advance(T0 + 2 * 86400)
    s = md.stats_24h("A:B")
    assert s["last_price"] == "110" and s["volume_24h"] == "0" and s["open_24h"] is None


def test_the_trade_feed_is_sequenced_and_bounded():
    md = MarketData()
    for i in range(MAX_TRADES + 5):
        md.record_trade("A:B" if i % 2 else "C:D", price="1", amount="1", side="buy",
                        block_height=i, block_time=T0 + i, venue="clob",
                        maker=MAKER if i % 3 == 0 else None, taker=TRADER)
    assert md.seq == MAX_TRADES + 5
    assert [t["seq"] for t in md.since(md.seq - 3)] == [md.seq - 2, md.seq - 1, md.seq]
    assert md.since(md.seq) == []
    assert [t["seq"] for t in md.trades("A:B", limit=2, since=md.seq - 4)] == [md.seq - 3, md.seq - 1]
    assert len(md.markets["A:B"].trades) <= MAX_TRADES
    mine = md.trades_of(MAKER.upper().replace("0XPQ", "0xPQ"), limit=5)
    assert len(mine) == 5 and all(t["maker"] == MAKER for t in mine)
    assert md.record_trade("A:B", price="0", amount="1", side="buy", block_height=1,
                           block_time=T0, venue="clob") == {}


# ── spot: fills and swaps feed it, at commit ───────────────────────────────

def _tx(sender, op, **params):
    n = _nonces.get(sender, 0)
    _nonces[sender] = n + 1
    return ExchangeTransaction(op_type=op, sender=sender, nonce=n, params=params,
                               gas_limit=1_000_000)


@pytest.fixture
def spot():
    _nonces.clear()
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    BP.apply_enforcement(m)
    m.begin_block(1, float(T0 + 1))
    for who in (LP, TRADER, MAKER, MAKER2):
        m.set_available_balance(who, D(1_000_000))
    r = m.process_transaction(_tx(LP, ExchangeOpType.TOKEN_DEPLOY, name="Token", symbol="TOK",
                                  total_supply="1000000"))
    assert r.success, r.error
    tok = r.data["token_address"]
    m.set_available_token_balance(LP, tok, D(1_000_000))
    for who in (TRADER, MAKER, MAKER2):
        m.set_available_token_balance(who, tok, D(1000))
    r = m.process_transaction(_tx(LP, ExchangeOpType.CREATE_POOL, token0="QRDX", token1=tok,
                                  fee_tier=3000, pool_type="STANDARD", initial_price="2",
                                  stake_amount="10000"))
    assert r.success, r.error
    pid = r.data["pool_id"]
    holder = m.pool_holder_address(pid)
    escrow = m.orderbook_escrow_address(f"{tok}:{NATIVE_ASSET}")
    for who in (holder, escrow):
        m.set_available_balance(who, D(0))
        m.set_available_token_balance(who, tok, D(0))
    r = m.process_transaction(_tx(LP, ExchangeOpType.ADD_LIQUIDITY, pool_id=pid,
                                  tick_lower=-60000, tick_upper=60000, amount="100000"))
    assert r.success, r.error
    m.commit_block()
    yield m, tok, pid
    ExchangeStateManager.reset_instance()


def _run(m, sender, op, **params):
    r = m.process_transaction(_tx(sender, op, **params))
    assert r.success, r.error
    return r


def test_spot_trades_are_recorded_at_commit_with_side_venue_and_tx(spot):
    m, tok, pid = spot
    market = f"{tok}:{NATIVE_ASSET}"
    m.begin_block(2, float(T0 + 70))
    _run(m, MAKER, ExchangeOpType.PLACE_ORDER, pair=market, side="sell", order_type="limit",
         price="2.5", amount="10")
    fill = _run(m, TRADER, ExchangeOpType.PLACE_ORDER, pair=f"qrdx:{tok}", side="buy",
                order_type="limit", price="3", amount="4")
    swap = _run(m, TRADER, ExchangeOpType.SWAP, token_in=tok, token_out="QRDX", amount_in="5",
                venue="amm")
    assert fill.data["fills"][0]["maker"] == MAKER and fill.data["trades"] == 1
    assert views.market_trades(m, market)["trades"] == []        # nothing until the block commits
    m.commit_block()

    trades = views.market_trades(m, f"QRDX/{tok}")["trades"]     # either order, "/" too
    clob, amm = trades
    assert (clob["venue"], clob["side"], clob["price"], clob["amount"], clob["quote_amount"]) == \
        ("clob", "buy", "2.5", "4", "10.0")
    assert (clob["maker"], clob["taker"], clob["block_height"], clob["block_time"]) == \
        (MAKER, TRADER, 2, float(T0 + 70))
    assert clob["tx_hash"] == m._block_exchange_txs[1].tx_hash()
    assert (amm["venue"], amm["side"], amm["amount"], amm["pool_id"]) == ("amm", "sell", "5", pid)
    assert D(amm["price"]) == D(swap.data["amount_out"]) / 5 and D(amm["price"]) < 2
    assert amm["maker"] == m.pool_holder_address(pid)
    # an address's trades, maker or taker, every market
    assert [t["seq"] for t in views.address_trades(m, TRADER)] == [clob["seq"], amm["seq"]]
    assert [t["seq"] for t in views.address_trades(m, MAKER)] == [clob["seq"]]
    # newer than a sequence number
    assert views.market_trades(m, market, since=clob["seq"])["trades"] == [amm]


def test_the_order_book_at_level_2_and_3(spot):
    m, tok, _ = spot
    market = f"{tok}:{NATIVE_ASSET}"
    m.begin_block(2, float(T0 + 70))
    o1 = _run(m, MAKER, ExchangeOpType.PLACE_ORDER, pair=market, side="sell", order_type="limit",
              price="2.5", amount="10").data["order_id"]
    o2 = _run(m, MAKER2, ExchangeOpType.PLACE_ORDER, pair=market, side="sell", order_type="limit",
              price="2.5", amount="5").data["order_id"]
    _run(m, MAKER2, ExchangeOpType.PLACE_ORDER, pair=market, side="sell", order_type="limit",
         price="2.6", amount="1")
    _run(m, TRADER, ExchangeOpType.PLACE_ORDER, pair=market, side="buy", order_type="limit",
         price="2", amount="20")
    _run(m, TRADER, ExchangeOpType.PLACE_ORDER, pair=market, side="buy", order_type="limit",
         price="1.5", amount="10")
    m.commit_block()

    book = views.market_book(m, f"QRDX:{tok}")
    assert (book["market"], book["type"], book["base"], book["quote"], book["level"]) == \
        (market, "spot", tok, NATIVE_ASSET, 2)
    assert book["base_info"]["symbol"] == "TOK" and book["quote_info"]["symbol"] == "QRDX"
    assert [(r["price"], r["amount"], r["total"], r["orders"]) for r in book["asks"]] == \
        [("2.5", "15", "15", 2), ("2.6", "1", "16", 1)]
    assert [(r["price"], r["amount"], r["total"]) for r in book["bids"]] == \
        [("2", "20", "20"), ("1.5", "10", "30")]
    assert D(book["bids"][-1]["notional_total"]) == 55               # 40 + 15 QRDX
    assert (book["best_bid"], book["best_ask"], book["spread"], book["mid"], book["spread_bps"]) == \
        ("2", "2.5", "0.5", "2.25", "2222.22")
    assert book["block_height"] == 2 and len(book["amm"]) == 1
    assert D(book["amm"][0]["price"]) == 2                            # the pool, the other venue

    l3 = views.market_book(m, market, depth=1, level=3)
    assert len(l3["asks"]) == 1 and l3["level"] == 3
    assert [(o["order_id"], o["owner"], o["remaining"]) for o in l3["asks"][0]["orders"]] == \
        [(o1, MAKER, "10"), (o2, MAKER2, "5")]                        # time priority
    # an AMM-only pair is a market too, with an empty book
    assert views.resolve_market(m, f"{tok}:0x" + "99" * 20) is None


def test_tickers_and_candles_by_symbol(spot):
    m, tok, _ = spot
    market = f"{tok}:{NATIVE_ASSET}"
    for h, price in ((2, "2.5"), (3, "2.7")):
        m.begin_block(h, float(T0 + 60 * h))
        _run(m, MAKER, ExchangeOpType.PLACE_ORDER, pair=market, side="sell", order_type="limit",
             price=price, amount="1")
        _run(m, TRADER, ExchangeOpType.PLACE_ORDER, pair=market, side="buy", order_type="limit",
             price=price, amount="1")
        m.commit_block()
    t = views.market_ticker(m, "TOK/QRDX")                           # a unique symbol resolves
    assert t["market"] == market and t["last_price"] == "2.7" and t["trades_24h"] == 2
    assert (t["open_24h"], t["high_24h"], t["low_24h"], t["change_24h"]) == ("2.5", "2.7", "2.5", "0.2")
    assert D(t["amm_price"]) == 2 and t["pools"] == 1 and t["has_order_book"]
    assert [x["market"] for x in views.market_tickers(m)] == [market]
    assert views.market_tickers(m, "perp") == []
    c = views.market_candles(m, market, "1m")["candles"]
    assert [(x["time"], x["close"]) for x in c] == [(T0 + 120, "2.5"), (T0 + 180, "2.7")]


def test_a_taker_selling_into_a_bid(spot):
    m, tok, _ = spot
    market = f"{tok}:{NATIVE_ASSET}"
    m.begin_block(2, float(T0 + 90))
    _run(m, MAKER, ExchangeOpType.PLACE_ORDER, pair=market, side="buy", order_type="limit",
         price="1.9", amount="3")
    _run(m, TRADER, ExchangeOpType.PLACE_ORDER, pair=market, side="sell", order_type="limit",
         price="1.9", amount="2")
    m.commit_block()
    (trade,) = views.market_trades(m, market)["trades"]
    assert (trade["side"], trade["maker"], trade["taker"]) == ("sell", MAKER, TRADER)


# ── perps feed the same store ──────────────────────────────────────────────

def test_perps_fills_are_market_trades(monkeypatch):
    from test_perps_api import BTC, Key, _block, _market, _order
    rep = Key()
    monkeypatch.setattr(constants, "ORACLE_REPORTERS", (rep.addr,))
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    try:
        alice, bob = Key(), Key()
        _market(mgr, rep, alice, bob, deposit="10000")
        _block(mgr, 2, [_order(bob, "sell", 1, 30000), _order(alice, "buy", 1, 30000)])
        (trade,) = views.market_trades(mgr, BTC)["trades"]
        assert (trade["venue"], trade["side"], trade["price"], trade["amount"]) == \
            ("perp", "buy", "30000", "1")
        assert trade["taker"] == alice.addr and trade["block_height"] == 2
        t = views.market_ticker(mgr, BTC.lower())                     # perps ids, any casing
        assert t["type"] == "perp" and t["last_price"] == "30000" and t["mark_price"]
        book = views.market_book(mgr, BTC, level=3)
        assert book["type"] == "perp" and book["mark_price"] and book["bids"] == []
        assert [x["market"] for x in views.market_tickers(mgr)] == [BTC]
    finally:
        ExchangeStateManager.reset_instance()


# ── the surfaces ───────────────────────────────────────────────────────────

async def test_market_rpc_module(spot):
    from qrdx.rpc.modules.exchange import MarketModule
    from qrdx.rpc.server import RPCError
    m, tok, _ = spot
    market = f"{tok}:{NATIVE_ASSET}"
    m.begin_block(2, float(T0 + 70))
    _run(m, MAKER, ExchangeOpType.PLACE_ORDER, pair=market, side="sell", order_type="limit",
         price="2.5", amount="2")
    _run(m, TRADER, ExchangeOpType.PLACE_ORDER, pair=market, side="buy", order_type="limit",
         price="2.5", amount="1")
    m.commit_block()
    rpc = MarketModule()
    assert [t["market"] for t in await rpc.getMarkets()] == [market]
    assert (await rpc.getTicker(f"QRDX:{tok}"))["last_price"] == "2.5"
    assert (await rpc.getOrderBook(market, 10, 3))["asks"][0]["orders"][0]["owner"] == MAKER
    assert len((await rpc.getTrades(market))["trades"]) == 1
    assert (await rpc.getCandles(market, "1h"))["candles"][0]["volume"] == "1"
    with pytest.raises(RPCError):
        await rpc.getTicker("NOPE-PERP")
    with pytest.raises(RPCError):
        await rpc.getCandles(market, "7m")


def test_orderbook_trades_and_tickers_stream(spot):
    from qrdx.exchange.stream import PerpStreamPublisher, initial_snapshots
    from qrdx.node.observability import EventHub, canonical_channel, valid_channel
    m, tok, _ = spot
    market = f"{tok}:{NATIVE_ASSET}"
    assert valid_channel(f"orderbook:QRDX:{tok}") and not valid_channel("orderbook")
    assert canonical_channel(f"orderbook:qrdx:{tok.upper().replace('0X', '0x')}") == f"orderbook:{market}"
    assert canonical_channel(f"trades:QRDX:{tok}") == f"trades:{market}"
    hub = EventHub()
    q = hub.subscribe({canonical_channel(f"orderbook:QRDX:{tok}"), f"trades:{market}", "tickers"})
    pub = PerpStreamPublisher(hub)
    pub.step(m)                                    # first look: the current book and tickers
    first = [q.get_nowait() for _ in range(q.qsize())]
    assert {e["type"] for e in first} == {"orderbook", "ticker"}

    m.begin_block(2, float(T0 + 70))
    _run(m, MAKER, ExchangeOpType.PLACE_ORDER, pair=market, side="sell", order_type="limit",
         price="2.5", amount="2")
    _run(m, TRADER, ExchangeOpType.PLACE_ORDER, pair=market, side="buy", order_type="limit",
         price="2.5", amount="1")
    m.commit_block()
    pub.step(m)
    events = [q.get_nowait() for _ in range(q.qsize())]
    by_type = {e["type"]: e for e in events}
    assert by_type["trade"]["key"] == market and by_type["trade"]["trade"]["price"] == "2.5"
    assert by_type["orderbook"]["book"]["asks"][0]["amount"] == "1"
    assert by_type["ticker"]["ticker"]["last_price"] == "2.5"
    pub.step(m)                                    # nothing changed: nothing sent
    assert q.qsize() == 0

    snaps = initial_snapshots(m, {f"orderbook:{market}", f"trades:{market}", "tickers"})
    assert {s["type"] for s in snaps} == {"orderbook", "trades", "ticker"}
    assert all(s["snapshot"] for s in snaps)
