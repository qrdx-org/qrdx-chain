"""
The trading history (qrdx/trading_history.py): every trade, every order's life, funding and
per-minute market samples, written from the exchange journal to the database as blocks commit —
kept beyond the journal's in-memory window, cut back with the chain on a reorg.
"""
import tempfile
from decimal import Decimal as D

import pytest

from qrdx import constants, trading_history
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange.block_processor import process_exchange_transactions

MID = "BTC-QRDX-PERP"
T0 = 1_700_000_000


@pytest.fixture
async def setup(monkeypatch):
    monkeypatch.setattr(constants, "PERP_FUNDING_INTERVAL_SECONDS", 60)
    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.begin_block(0, float(T0))
    m.clearinghouse.create_market("BTC")
    m.clearinghouse.set_oracle_price(MID, D(100), now=T0)
    for o in ("maker", "other"):
        m.clearinghouse.deposit(o, D(10 ** 6))
    m.clearinghouse.deposit("trader", D(60))
    yield db, m
    ExchangeStateManager.reset_instance()
    await db.connection.close()


def _tx(m, sender, op, params):
    nonce = m.get_nonce(sender)
    m._planned = getattr(m, "_planned", {})
    nonce = max(nonce, m._planned.get(sender, 0))
    m._planned[sender] = nonce + 1
    return ExchangeTransaction(op_type=op, sender=sender, nonce=nonce, params=params,
                               gas_limit=10 ** 6)


def _block(m, height, txs, t):
    ok, err, _root = process_exchange_transactions(height, float(t), txs, m)
    assert ok, err
    m.commit_block()


async def test_trades_orders_funding_and_samples_are_kept(setup):
    db, m = setup
    order = lambda who, side, size, price, **kw: _tx(m, who, ExchangeOpType.PERP_ORDER, {  # noqa
        "market_id": MID, "side": side, "size": str(size), "price": str(price), **kw})
    _block(m, 1, [order("maker", "sell", 5, 100), order("trader", "buy", 5, 100),
                  order("maker", "sell", 1, 120),
                  _tx(m, "maker", ExchangeOpType.PERP_CANCEL, {"market_id": MID,
                                                               "order_id": "nope"})], T0)
    # The mark falls: the trader is liquidated into a bid; a funding interval passes.
    m.clearinghouse.place_order("other", MID, "bid", "buy", D(10), D(89), 0)
    m.clearinghouse.set_oracle_price(MID, D(80), now=T0 + 61)
    _block(m, 2, [], T0 + 61)
    assert await trading_history.flush(db, m.journal) == 2

    trades = await trading_history.trades(db, address="trader")
    kinds = [t["kind"] for t in trades["items"]]
    assert kinds == ["liquidation", "trade"]                      # newest first
    first = trades["items"][-1]
    assert first["role"] == "taker" and first["maker"] == "maker" and first["taker_order_id"]
    assert D(first["fee"]) == D(500) * D("0.0005")
    orders = await trading_history.orders(db, address="maker")
    events = [o["event"] for o in orders["items"]]
    assert events == ["rejected", "placed", "placed"]             # the bad cancel, refused
    assert (await trading_history.orders(db, address="trader"))["items"][0]["event"] == "liquidated"
    funding = await trading_history.funding(db, MID)
    assert funding["items"] and funding["items"][0]["market"] == MID
    samples = await trading_history.samples(db, MID)
    assert [s["block_time"] for s in samples] == [T0, T0 + 61]
    board = await trading_history.leaderboard(db, window="all", metric="volume")
    assert board[0]["volume"] > 0 and {r["account"] for r in board} >= {"maker", "other"}

    # Pages: one at a time, by cursor.
    page = await trading_history.trades(db, market=MID, limit=1)
    nxt = await trading_history.trades(db, market=MID, limit=1, cursor=page["next_cursor"])
    assert page["items"][0]["cursor"] != nxt["items"][0]["cursor"]


async def test_a_reorg_cuts_the_history_back(setup):
    db, m = setup
    order = lambda who, side: _tx(m, who, ExchangeOpType.PERP_ORDER, {  # noqa
        "market_id": MID, "side": side, "size": "1", "price": "100"})
    _block(m, 1, [order("maker", "sell"), order("other", "buy")], T0)
    _block(m, 2, [order("maker", "sell"), order("other", "buy")], T0 + 1)
    await trading_history.flush(db, m.journal)
    assert len((await trading_history.trades(db, market=MID))["items"]) == 2
    m.journal.rollback_to(1)                                      # block 2 orphaned
    await trading_history.flush(db, m.journal)
    rows = (await trading_history.trades(db, market=MID))["items"]
    assert [r["block_height"] for r in rows] == [1]


async def test_the_history_follows_the_journal_through_the_poller(setup):
    db, m = setup
    _block(m, 1, [_tx(m, "maker", ExchangeOpType.PERP_ORDER, {
        "market_id": MID, "side": "sell", "size": "1", "price": "101"})], T0)
    await trading_history.history_poller(lambda: db, None, get_journal=lambda: m.journal,
                                         interval=0, _max_iterations=1)
    assert not m.journal.history_outbox
    assert (await trading_history.orders(db, address="maker"))["items"][0]["event"] == "placed"
