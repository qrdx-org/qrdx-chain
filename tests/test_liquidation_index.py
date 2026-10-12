"""
The liquidation index (qrdx/exchange/clearinghouse.py ``_LiquidationIndex``).

Every block's tick used to compute the equity of every account with a position: about 3 µs an
account, 148 ms at 50,000 — more than half a 250 ms slot. Equity and maintenance are linear in
the mark, so a position whose margin covers one market has an exact liquidation price, kept
sorted per market; a tick checks only the owners whose price the new mark crossed (and every
account with cross positions in several markets). What must hold: the indexed pass liquidates
exactly what checking every owner would, in the same order — including owners a liquidation
pushes under during the pass. With verification on, every pass is compared with that full scan
on a copy; these tests force it on.
"""
import random
import time
from decimal import Decimal

import pytest

from qrdx.exchange import clearinghouse as CH
from qrdx.exchange.clearinghouse import Account, Clearinghouse, Position

D = Decimal
BTC, ETH = "BTC-QRDX-PERP", "ETH-QRDX-PERP"
T0 = D(1_700_000_000)


@pytest.fixture
def verify(monkeypatch):
    monkeypatch.setattr(CH, "verifying", lambda: True)


def _market_pair():
    ch = Clearinghouse()
    for base, price in (("BTC", 30000), ("ETH", 2000)):
        ch.create_market(base)
        ch.set_oracle_price(f"{base}-QRDX-PERP", D(price))
    return ch


def _trade(ch, rng, buyer, seller, mid, price, tag):
    size = D(rng.choice(["0.1", "0.5", "1", "2"])) * (1 if mid == BTC else 10)
    for who in (buyer, seller):
        if rng.random() < 0.3:
            lev = D(rng.choice([3, 5, 10]))
            try:
                ch.set_leverage(who, mid, lev, isolated=rng.random() < 0.5)
            except CH.ClearinghouseError:
                pass
    try:
        ch.place_order(seller, mid, f"s{tag}", "sell", size, D(price), 0)
        ch.place_order(buyer, mid, f"b{tag}", "buy", size, D(price), 0)
    except CH.ClearinghouseError:
        pass


@pytest.mark.parametrize("seed", range(6))
def test_the_indexed_pass_liquidates_exactly_what_the_full_scan_does(verify, seed):
    rng = random.Random(seed)
    ch = _market_pair()
    traders = [f"t{i:03d}" for i in range(48)]
    for t in traders:
        ch.deposit(t, D(rng.choice([1500, 3000, 6000, 20000])))
    ch.deposit("whale", D(50_000_000))
    prices = {BTC: D(30000), ETH: D(2000)}
    for i in range(160):
        mid = rng.choice([BTC, ETH])
        a, b = rng.sample(traders + ["whale"], 2)
        _trade(ch, rng, a, b, mid, prices[mid], i)
    liquidations = 0
    now = T0
    for step in range(40):
        for mid in prices:
            prices[mid] = (prices[mid] * D(1 + rng.uniform(-0.06, 0.06))).quantize(D("0.01"))
            ch.set_oracle_price(mid, prices[mid])
        now += 1
        events = ch.tick(now)          # every pass is compared with the full scan
        liquidations += sum(1 for e in events if e.get("type") == "liquidation")
        assert ch.identity_gap() == 0
    assert liquidations > 0, "the scenario must liquidate something to test anything"


def test_a_stale_index_is_caught(verify, monkeypatch):
    ch = _market_pair()
    ch.deposit("alice", D(3500))
    ch.deposit("bob", D(10_000_000))
    ch.place_order("bob", BTC, "s", "sell", D(1), D(30000), 0)
    ch.place_order("alice", BTC, "b", "buy", D(1), D(30000), 0)
    monkeypatch.setattr(Clearinghouse, "_liquidation_candidates", lambda self, index: set())
    ch.set_oracle_price(BTC, D(26000))
    with pytest.raises(AssertionError, match="differs from the full scan"):
        ch.tick(T0 + 1)


def test_the_index_costs_what_crossed_not_every_account(monkeypatch):
    monkeypatch.setattr(CH, "verifying", lambda: False)
    ch = _market_pair()
    n = 20_000
    for i in range(n):            # well-collateralised positions: nobody near liquidation
        owner = f"a{i:06d}"
        size = D(1) if i % 2 else D(-1)
        mid = BTC if i % 3 else ETH
        price = D(30000) if mid == BTC else D(2000)
        acct = Account(collateral=price)
        acct.positions[mid] = Position(size=size, entry_price=price)
        ch.accounts[owner] = acct
    ch._liquidation_pass()       # builds the index once
    ch.commitment()              # as every block does: the marks of the setup are consumed
    ch._liquidation_pass()       # ...by the next tick, which re-indexes what changed
    t0 = time.perf_counter()
    for _ in range(20):
        assert ch._liquidation_pass() == []
    indexed = (time.perf_counter() - t0) / 20
    t0 = time.perf_counter()
    assert ch._liquidation_pass_full() == []
    full = time.perf_counter() - t0
    assert indexed < full / 20, f"indexed {indexed * 1e3:.2f} ms vs full {full * 1e3:.2f} ms"
