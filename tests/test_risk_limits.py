"""
Per-market risk limits (docs/CONSENSUS_ROADMAP.md 2, 3): the price band against the oracle, the
circuit breaker, the open-interest cap, and tiered initial margin.
"""
from decimal import Decimal

import pytest

from qrdx import constants
from qrdx.exchange import clearinghouse as chmod
from qrdx.exchange.clearinghouse import (
    Clearinghouse,
    ClearinghouseError,
    initial_margin,
    market_maker_address,
)

D = Decimal
BTC = "BTC-QRDX-PERP"
T0 = D(1_700_000_000)


def _ch():
    ch = Clearinghouse()
    ch.create_market("BTC")
    ch.set_oracle_price(BTC, D(30000))
    ch.new_block(T0)
    for who in ("alice", "bob", "mm"):
        ch.deposit(who, D(10_000_000))
    return ch


def _trade(ch, buyer, seller, size, price, n=[0]):
    n[0] += 1
    ch.place_order(seller, BTC, f"s{n[0]}", "sell", D(size), D(price), 0)
    ch.place_order(buyer, BTC, f"b{n[0]}", "buy", D(size), D(price), 0)


# ── price band ──────────────────────────────────────────────────────────────

def test_an_order_far_worse_than_the_oracle_is_refused():
    ch = _ch()
    with pytest.raises(ClearinghouseError, match="worse than the oracle"):
        ch.place_order("alice", BTC, "b", "buy", D(1), D(36001), 0)
    with pytest.raises(ClearinghouseError, match="worse than the oracle"):
        ch.place_order("alice", BTC, "s", "sell", D(1), D(23999), 0)
    ch.place_order("alice", BTC, "b", "buy", D(1), D(36000), 0)       # at the band: rests
    ch.place_order("bob", BTC, "s", "sell", D(1), D(45000), 1)        # better for its owner


def test_the_band_is_chain_spec_and_zero_turns_it_off(monkeypatch):
    monkeypatch.setattr(constants, "PERP_PRICE_BAND_BPS", 0)
    ch = _ch()
    ch.place_order("alice", BTC, "b", "buy", D(1), D(60000), 0)


# ── circuit breaker ─────────────────────────────────────────────────────────

def _crash(ch, to, now):
    ch.set_oracle_price(BTC, D(to))
    events = []
    for t in range(0, 60, 2):
        ch.new_block(now + t)
        events += ch.tick(now + t)
    return events, now + 60


def test_a_fast_move_halts_new_exposure_and_the_cooldown_lifts_it():
    ch = _ch()
    _trade(ch, "alice", "bob", 1, 30000)
    ch.new_block(T0)
    ch.tick(T0)
    events, now = _crash(ch, 26000, T0 + 2)                          # -13 % within the window
    tripped = [e for e in events if e["type"] == "circuit_breaker"]
    assert len(tripped) == 1 and tripped[0]["market"] == BTC
    m = ch.markets[BTC]
    assert ch.halted(m)
    with pytest.raises(ClearinghouseError, match="circuit breaker"):
        ch.place_order("mm", BTC, "x", "buy", D(1), D(26000), 0)
    ch.place_order("alice", BTC, "r", "sell", D("0.5"), D(26000), 0, reduce_only=True)
    header = chmod._market_header(m)
    assert header["breaker"][2] == str(m.halted_until)
    ch.new_block(m.halted_until)
    ch.tick(m.halted_until)
    assert not ch.halted(m)
    ch.place_order("mm", BTC, "x", "buy", D(1), D(26000), 1)


def test_a_slow_move_does_not_trip_it():
    ch = _ch()
    ch.new_block(T0)
    ch.tick(T0)
    price, now = D(30000), T0
    for _ in range(12):                                               # -2 % a window, 12 windows
        price = price * D("0.98")
        events, now = _crash(ch, price.quantize(D(1)), now + 300)
        assert not [e for e in events if e["type"] == "circuit_breaker"]
    assert not ch.halted(ch.markets[BTC])


def test_the_halt_is_undone_with_a_rollback():
    """The breaker's state is in the market's committed header: snapshot and state hash."""
    ch = _ch()
    ch.new_block(T0)
    ch.tick(T0)
    before = ch.state_hash()
    _crash(ch, 26000, T0 + 2)
    assert ch.state_hash() != before


# ── open-interest cap ───────────────────────────────────────────────────────

def test_open_interest_is_capped_and_a_refused_fill_leaves_nothing(monkeypatch):
    monkeypatch.setattr(constants, "PERP_MIN_OI_CAP", 60_000)        # 2 BTC at 30,000
    ch = _ch()
    _trade(ch, "alice", "bob", 1, 30000)
    ch.place_order("bob", BTC, "ask", "sell", D(2), D(30000), 5)
    before = ch.state_hash()
    with pytest.raises(ClearinghouseError, match="open interest is capped"):
        ch.place_order("alice", BTC, "lift", "buy", D(2), D(30000), 6)
    assert ch.state_hash() == before                                  # the fills were undone
    ch.place_order("alice", BTC, "lift", "buy", D(1), D(30000), 6)   # to the cap: fills
    assert ch.markets[BTC].open_interest == 2
    ch.place_order("alice", BTC, "out", "sell", D(1), D(30000), 7, reduce_only=True)


def test_a_liquidity_vault_sets_the_cap():
    ch = _ch()
    assert ch.oi_cap(ch.markets[BTC]) is None                         # no vault, no floor
    vault = market_maker_address(BTC)
    ch.create_user_vault("mm", vault, "liquidity", D(1000), D(0), T0, managed=BTC)
    cap = ch.oi_cap(ch.markets[BTC])
    assert cap == ch.cross_equity(vault) * chmod.OI_CAP_MULTIPLE


# ── leverage tiers ──────────────────────────────────────────────────────────

def test_initial_margin_is_tiered_and_continuous():
    m = _ch().markets[BTC]
    top = m.max_leverage
    assert initial_margin(m, top, D(500_000)) == D(500_000) / top
    two_m = initial_margin(m, top, D(2_000_000))
    assert two_m == D(1_000_000) / top + D(1_000_000) / (top / 2)
    eps = D("0.01")
    below, above = initial_margin(m, top, D(1_000_000) - eps), initial_margin(m, top, D(1_000_000))
    assert above - below < D(1)                                       # no cliff at a floor
    assert initial_margin(m, D(1), D(20_000_000)) == D(20_000_000)    # 1x: every tier is 1x


def test_a_large_position_needs_tiered_margin_but_maintenance_is_unchanged():
    ch = _ch()
    for who in ("whale", "maker"):
        ch.deposit(who, D(100_000_000))
    m = ch.markets[BTC]
    ch.set_leverage("whale", BTC, m.max_leverage, False)
    _trade(ch, "whale", "maker", 100, 30000)                          # 3M notional
    need = ch.cross_requirement("whale")
    flat = D(3_000_000) / m.max_leverage
    assert need > flat
    assert ch.cross_maintenance("whale") == D(3_000_000) * m.maintenance_rate


def test_a_small_account_cannot_reach_a_large_tier():
    ch = _ch()
    ch.deposit("small", D(60_000))
    ch.deposit("maker", D(100_000_000))
    m = ch.markets[BTC]
    ch.set_leverage("small", BTC, m.max_leverage, False)
    ch.place_order("maker", BTC, "ask", "sell", D(100), D(30000), 0)
    # 60k at 20x would be 1.2M flat; tiered, 1.2M needs 50k + 200k / 10 = 70k.
    with pytest.raises(ClearinghouseError, match="margin"):
        ch.place_order("small", BTC, "big", "buy", D(40), D(30000), 0)
    ch.place_order("small", BTC, "ok", "buy", D(30), D(30000), 1)    # 900k: one tier
