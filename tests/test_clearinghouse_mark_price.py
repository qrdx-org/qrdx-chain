"""
Mark price and the per-block exchange tick (docs/PERPS_CLEARINGHOUSE.md, Phase 2).

Margin, unrealized PnL and (Phase 3) liquidations are judged at the MARK price, not the last
trade: mark = median(oracle + 150 s EMA of the book premium, median of best bid / best ask /
last trade, 30 s EMA of that book median), held within ±5 % of the oracle. A single large trade
or a spoofed order on a thin book therefore cannot move it far on its own.

The EMAs advance with block time, so the exchange must tick on EVERY block — not only on blocks
that carry exchange transactions — identically on every path. That is pinned here too.
"""
import inspect
import json
import os
import tempfile
from decimal import Decimal

import pytest

from qrdx.exchange.clearinghouse import Clearinghouse, MARK_ORACLE_BAND

D = Decimal
BTC = "BTC-QRDX-PERP"
T0 = D(1_700_000_000)


def _market_with_book(bid, ask, oracle=D("30000")):
    ch = Clearinghouse()
    ch.create_market("BTC")
    ch.set_oracle_price(BTC, oracle)
    for who in ("mm", "taker"):
        ch.deposit(who, D("10000000"))
    ch.place_order("mm", BTC, "b1", "buy", D("1"), D(bid), 1)
    ch.place_order("mm", BTC, "a1", "sell", D("1"), D(ask), 2)
    return ch


def test_mark_equals_oracle_with_an_empty_book():
    ch = Clearinghouse()
    ch.create_market("BTC")
    ch.set_oracle_price(BTC, D("30000"))
    ch.tick(T0)
    assert ch.markets[BTC].mark_price == D("30000")


def test_emas_advance_only_with_block_time():
    ch = _market_with_book("30050", "30150")
    ch.tick(T0)
    state = ch.canonical()
    ch.tick(T0)                                   # same block time: nothing moves
    assert ch.canonical() == state
    ch.tick(T0 + 10)
    assert ch.canonical() != state


def _quiet(ch, start, seconds):
    """Tick every 2 s (the testnet slot) for ``seconds``; returns the next block time."""
    for t in range(0, seconds, 2):
        ch.tick(start + t)
    return start + seconds


def test_a_thin_book_squeeze_moves_the_mark_gradually_and_never_past_the_band():
    """Two colluding accounts clear the only ask and trade with each other at 45,000, leaving a
    45,000 ask resting: best ask and last trade are both 45,000, so the book median is too."""
    ch = _market_with_book("29990", "30010")
    oracle = ch.markets[BTC].oracle_price
    ch.place_order("taker", BTC, "t0", "buy", D("0.1"), D("30010"), 3)     # a last trade
    now = _quiet(ch, T0, 600)
    quiet = ch.markets[BTC].mark_price
    assert abs(quiet - oracle) <= D("10")

    for who in ("attacker_a", "attacker_b"):
        ch.deposit(who, D("100000000"))
    ch.place_order("attacker_b", BTC, "x1", "buy", D("0.9"), D("30010"), 4)  # clears the ask
    ch.place_order("attacker_a", BTC, "x2", "sell", D("2"), D("45000"), 5)
    ch.place_order("attacker_b", BTC, "x3", "buy", D("1"), D("45000"), 6)
    assert ch.markets[BTC].last_trade_price == D("45000")
    ch.tick(now)
    one_block = ch.markets[BTC].mark_price
    assert quiet < one_block < quiet * D("1.04"), (
        f"one block of a 50 % squeeze moved the mark {quiet} → {one_block}")

    marks = []
    for t in range(2, 300, 2):                    # held for five minutes
        ch.tick(now + t)
        marks.append(ch.markets[BTC].mark_price)
    assert max(marks) == oracle * (1 + MARK_ORACLE_BAND), "the band is the ceiling"

    # The honest book returns: the squeeze unwinds as fast as the 30 s book EMA forgets it.
    ch.cancel_order("attacker_a", BTC, "x2")
    ch.place_order("mm", BTC, "a2", "sell", D("1"), D("30010"), 7)
    ch.place_order("taker", BTC, "t1", "buy", D("0.1"), D("30010"), 8)
    _quiet(ch, now + 300, 180)
    assert abs(ch.markets[BTC].mark_price - oracle) <= D("0.005") * oracle


def test_a_sustained_premium_is_followed_gradually():
    ch = _market_with_book("29990", "30010")
    ch.place_order("taker", BTC, "t0", "buy", D("0.1"), D("30010"), 3)
    now = _quiet(ch, T0, 600)
    # The book reprices ~1 % over the oracle and trades there.
    ch.cancel_order("mm", BTC, "b1")
    ch.cancel_order("mm", BTC, "a1")
    ch.place_order("mm", BTC, "b2", "buy", D("1"), D("30290"), 4)
    ch.place_order("mm", BTC, "a2", "sell", D("1"), D("30310"), 5)
    ch.place_order("taker", BTC, "t1", "buy", D("0.1"), D("30310"), 6)
    marks = []
    for t in range(0, 600, 2):
        ch.tick(now + t)
        marks.append(ch.markets[BTC].mark_price)
    assert marks[0] < D("30100"), f"the mark jumped straight to the book: {marks[0]}"
    assert all(b >= a - D("1e-12") for a, b in zip(marks, marks[1:])), (
        "the mark should climb toward the book, never back")
    assert D("30250") < marks[-1] <= D("30310")


def test_an_order_that_would_hit_its_own_resting_order_never_crosses_the_book():
    """Self-trade prevention used to skip the sender's own resting order and rest the
    remainder ACROSS it (a 30,290 bid over a 30,010 ask) — a crossed book that moved the mid
    price, and so the mark, at no cost. Now the remainder is cancelled; fills already made
    against other traders stand."""
    ch = _market_with_book("29990", "30010")                  # mm: bid 29,990 / ask 30,010
    ch.place_order("taker", BTC, "t0", "sell", D("0.5"), D("30020"), 3)   # rests above mm
    fills = ch.place_order("mm", BTC, "b2", "buy", D("1"), D("30290"), 4)
    assert fills == []                                         # its own ask is best: stop
    book = ch.markets[BTC].book
    assert book.best_bid == D("29990") and book.best_ask == D("30010")
    assert "b2" not in ch.markets[BTC].orders

    ch.cancel_order("mm", BTC, "a1")                           # now the taker's ask is best
    ch.place_order("mm", BTC, "a3", "sell", D("1"), D("30100"), 5)
    fills = ch.place_order("mm", BTC, "b3", "buy", D("2"), D("30290"), 6)
    assert [D(f["amount"]) for f in fills] == [D("0.5")]        # takes the taker's 30,020 ...
    assert book.best_bid == D("29990") and book.best_ask == D("30100")   # ... and stops
    assert ch.identity_gap() == 0


def test_the_mark_is_deterministic():
    def run():
        ch = _market_with_book("30100", "30200")
        for t in range(0, 300, 3):
            ch.tick(T0 + t)
        return ch.state_hash()
    assert run() == run()


# ── the tick runs on every block, on every path ───────────────────────────

def test_every_path_ticks_blocks_without_exchange_transactions():
    from qrdx import derived_state_rebuild
    from qrdx.exchange import block_processor as BP
    from qrdx.node import main as node_main
    from qrdx.rpc.modules import p2p
    from qrdx.validator import node_integration as NI

    main_src = inspect.getsource(node_main)
    assert main_src.count("_exchange_tick_on_import(") >= 3      # def + sync + REST
    assert "run_exchange_tick(" in inspect.getsource(p2p)
    assert "run_exchange_tick(next_height" in inspect.getsource(NI.ValidatorNode._block_production_loop)
    assert "run_exchange_tick(height" in inspect.getsource(
        derived_state_rebuild.rebuild_derived_state_interleaved)
    assert "run_exchange_tick(height" in inspect.getsource(BP.rebuild_exchange_state_from_chain)
    assert "mgr.clearinghouse.tick(" in inspect.getsource(BP._execute_block_boundary_duties)


async def test_forward_with_ticks_equals_the_rebuild(monkeypatch):
    """A chain whose quiet blocks still move the mark (a resting book over the oracle): forward
    application that ticks every block must equal the interleaved rebuild — and a replay that
    skips the quiet blocks, as every path used to, must NOT."""
    from qrdx import constants
    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.database_sqlite import DatabaseSQLite
    from qrdx.derived_state_rebuild import rebuild_derived_state_interleaved
    from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
    from qrdx.exchange import block_processor as BP
    from qrdx.exchange import encode_exchange_txs

    keys = [PQPrivateKey.generate() for _ in range(2)]
    rep, mm = (k.public_key.to_address() for k in keys)
    monkeypatch.setattr(constants, "ORACLE_REPORTERS", (rep,))
    nonces = {rep: 0, mm: 0}

    def tx(key, op, params):
        addr = key.public_key.to_address()
        t = ExchangeTransaction(op_type=op, sender=addr, nonce=nonces[addr], params=params,
                                gas_limit=2_000_000, gas_price=10**9)
        nonces[addr] += 1
        t.public_key = key.public_key.to_bytes()
        t.signature = key.sign(t.signing_bytes()).to_bytes()
        return t

    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    try:
        async def add(h, txs=None, alloc=None):
            bh = f"{h:064x}"
            await db.add_block(block_hash=bh, block_height=h, block_content="",
                               validator_address="0xPQ" + "00" * 32, timestamp=int(T0) + 6 * h)
            for i, (r, a) in enumerate(alloc or []):
                await db.add_transaction(tx_hash=f"a{h}{i}", block_hash=bh, tx_hex=json.dumps(
                    {"type": "genesis_allocation", "recipient": r, "amount": a}))
            if txs:
                await db.add_block_exchange_txs(bh, encode_exchange_txs(txs))

        await add(0, alloc=[(mm, "10000000"), (keys[0].public_key.to_address(), "1000")])
        await add(1, [tx(keys[0], ExchangeOpType.CREATE_MARKET, {"base_token": "BTC"}),
                      tx(keys[0], ExchangeOpType.UPDATE_ORACLE,
                         {"pair": "BTC:QRDX", "price": "30000"}),
                      tx(keys[1], ExchangeOpType.PERP_DEPOSIT, {"amount": "1000000"})])
        await add(2, [tx(keys[1], ExchangeOpType.PERP_ORDER,
                         {"market_id": BTC, "side": "buy", "size": "1", "price": "30500"}),
                      tx(keys[1], ExchangeOpType.PERP_ORDER,
                         {"market_id": BTC, "side": "sell", "size": "1", "price": "30700"})])
        for h in range(3, 40):                        # quiet blocks: no exchange transactions
            await add(h)
        tip = 39

        async def forward(tick_quiet_blocks):
            await db.clear_account_state()
            await db.seed_genesis_account_state()
            await db.connection.commit()
            ExchangeStateManager.reset_instance()
            mgr = ExchangeStateManager.get_instance()
            BP.apply_enforcement(mgr)                  # the production gates, as the rebuild
            for h in range(1, tip + 1):
                section = await db.get_block_exchange_txs(f"{h:064x}")
                ts = float(int(T0) + 6 * h)
                if section:
                    txs = BP.decode_exchange_txs(section)
                    await BP.preload_sender_balances(db, txs, mgr)
                    ok, err, _ = BP.process_exchange_transactions(h, ts, txs, mgr)
                    assert ok, err
                    mgr.commit_block()
                    await BP.flush_exchange_balance_deltas(db, mgr, enforce=True)
                elif tick_quiet_blocks:
                    BP.run_exchange_tick(h, ts, mgr)
            await db.connection.commit()
            return mgr.compute_state_root(), mgr.clearinghouse.markets[BTC].mark_price

        ticked_root, ticked_mark = await forward(True)
        skipped_root, skipped_mark = await forward(False)
        assert skipped_root != ticked_root and skipped_mark != ticked_mark, (
            "the quiet blocks should move the mark — otherwise this test proves nothing")

        await rebuild_derived_state_interleaved(db)
        mgr = ExchangeStateManager.get_instance()
        assert mgr.compute_state_root() == ticked_root
        assert mgr.clearinghouse.markets[BTC].mark_price == ticked_mark
    finally:
        ExchangeStateManager.reset_instance()
        path = db.db_path
        await db.close()
        os.remove(path)
