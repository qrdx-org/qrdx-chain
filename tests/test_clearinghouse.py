"""
The perps clearinghouse is zero-sum: trades only move value between accounts.

docs/PERPS_CLEARINGHOUSE.md. The old engine had no counterparty, so it minted QRDX whenever a
trader won and burned it whenever one lost. These tests pin the replacement's invariants:

  * every fill has a buyer and a seller, so each market's net size stays exactly zero;
  * holder == Σ collateral − Σ size × entry, EXACTLY, after every operation;
  * real QRDX only moves on deposit / withdraw — what one trader gains, others lose.
"""
import random
from decimal import Decimal

import pytest

from qrdx.exchange.clearinghouse import (
    Clearinghouse, ClearinghouseError, MAKER_FEE_RATE, TAKER_FEE_RATE,
)

D = Decimal
BTC = "BTC-QRDX-PERP"


@pytest.fixture
def ch():
    c = Clearinghouse()
    c.create_market("BTC", max_leverage=D("20"))
    c.set_oracle_price(BTC, D("30000"))
    return c


class Seq:
    """Monotonic order ids and nonces, as transaction hashes and exchange nonces provide."""
    def __init__(self):
        self.n = 0

    def __call__(self):
        self.n += 1
        return f"o{self.n}", self.n


@pytest.fixture
def seq():
    return Seq()


def _order(ch, seq, owner, side, size, price, **kw):
    oid, nonce = seq()
    return ch.place_order(owner, BTC, oid, side, D(str(size)), D(str(price)), nonce, **kw)


def _sound(ch):
    assert ch.identity_gap() == 0, f"identity broken by {ch.identity_gap()}"
    for mid in ch.markets:
        assert ch.net_size(mid) == 0, f"{mid} net size {ch.net_size(mid)}"


# ── the property the old engine violated ──────────────────────────────────

def test_a_winners_profit_is_exactly_the_losers_loss(ch, seq):
    ch.deposit("alice", D("10000"))
    ch.deposit("bob", D("10000"))
    _order(ch, seq, "bob", "sell", 1, 30000)          # bob rests a sell
    _order(ch, seq, "alice", "buy", 1, 30000)         # alice lifts it: long 1 vs bob short 1
    _sound(ch)

    ch.set_oracle_price(BTC, D("33000"))               # BTC rallies
    _order(ch, seq, "bob", "buy", 1, 33000)           # bob rests a buy to close
    _order(ch, seq, "alice", "sell", 1, 33000, reduce_only=True)
    _sound(ch)

    a, b = ch.accounts["alice"], ch.accounts["bob"]
    assert not a.positions and not b.positions
    # Alice +3,000 and Bob −3,000 exactly; each paid fees (taker 0.05 %, maker 0.02 %) to the
    # vault. Nothing created or destroyed.
    open_fee, close_fee = D("30000"), D("33000")
    assert a.collateral == D("13000") - (open_fee + close_fee) * TAKER_FEE_RATE
    assert b.collateral == D("7000") - (open_fee + close_fee) * MAKER_FEE_RATE
    assert a.collateral + b.collateral + ch.vault_collateral == D("20000")
    assert ch.holder_balance == D("20000")


def test_net_size_is_zero_in_every_state(ch, seq):
    for who in ("a", "b", "c"):
        ch.deposit(who, D("100000"))
    _order(ch, seq, "a", "sell", 2, 30000)
    _order(ch, seq, "b", "buy", D("0.5"), 30100)       # partial fill
    _sound(ch)
    _order(ch, seq, "c", "buy", 3, 30000)              # takes the rest, then rests
    _sound(ch)
    assert ch.markets[BTC].open_interest == D("2")


# ── netting: increase, reduce, flip ───────────────────────────────────────

def test_averaging_into_a_position_keeps_the_identity_exact(ch, seq):
    for who in ("a", "b"):
        ch.deposit(who, D("100000"))
    for price in (30000, 30001, 30003, 29999):         # averages that do not divide evenly
        ch.set_oracle_price(BTC, D(price))
        _order(ch, seq, "b", "sell", D("0.3"), price)
        _order(ch, seq, "a", "buy", D("0.3"), price)
        _sound(ch)
    pos = ch.accounts["a"].positions[BTC]
    assert pos.size == D("1.2")


def test_reducing_realizes_pnl_and_keeps_entry(ch, seq):
    for who in ("a", "b", "c"):
        ch.deposit(who, D("100000"))
    _order(ch, seq, "b", "sell", 2, 30000)
    _order(ch, seq, "a", "buy", 2, 30000)
    ch.set_oracle_price(BTC, D("31000"))
    _order(ch, seq, "c", "buy", 1, 31000)
    before = ch.accounts["a"].collateral
    fills = _order(ch, seq, "a", "sell", 1, 31000)
    assert D(fills[0]["realized"]["a"]) == D("1000")
    pos = ch.accounts["a"].positions[BTC]
    assert pos.size == 1 and pos.entry_price == 30000
    assert ch.accounts["a"].collateral == before + D("1000") - D("31000") * TAKER_FEE_RATE
    _sound(ch)


def test_flipping_through_zero(ch, seq):
    for who in ("a", "b", "c"):
        ch.deposit(who, D("100000"))
    _order(ch, seq, "b", "sell", 1, 30000)
    _order(ch, seq, "a", "buy", 1, 30000)               # a long 1 @ 30,000
    ch.set_oracle_price(BTC, D("29000"))
    _order(ch, seq, "c", "buy", 3, 29000)
    fills = _order(ch, seq, "a", "sell", 3, 29000)      # a: close 1 (−1,000), open short 2
    assert D(fills[0]["realized"]["a"]) == D("-1000")
    pos = ch.accounts["a"].positions[BTC]
    assert pos.size == -2 and pos.entry_price == 29000
    _sound(ch)


# ── margin ────────────────────────────────────────────────────────────────

def test_an_order_beyond_initial_margin_is_refused_and_changes_nothing(ch, seq):
    ch.deposit("a", D("1000"))
    ch.set_leverage("a", BTC, D("10"), isolated=False)
    before = ch.canonical()
    with pytest.raises(ClearinghouseError, match="insufficient margin"):
        _order(ch, seq, "a", "buy", 1, 30000)            # needs 3,000 at 10x
    assert ch.canonical() == before


def test_resting_orders_reserve_margin(ch, seq):
    ch.deposit("a", D("3100"))
    ch.set_leverage("a", BTC, D("10"), isolated=False)
    _order(ch, seq, "a", "buy", 1, 30000)                # rests, reserves 3,000
    with pytest.raises(ClearinghouseError):
        _order(ch, seq, "a", "buy", 1, 30000)
    assert ch.withdrawable("a") == D("100")


def test_reduce_only_needs_no_margin_but_must_reduce(ch, seq):
    ch.deposit("a", D("3200"))
    ch.deposit("b", D("100000"))
    ch.set_leverage("a", BTC, D("10"), isolated=False)
    _order(ch, seq, "b", "sell", 1, 30000)
    _order(ch, seq, "a", "buy", 1, 30000)
    with pytest.raises(ClearinghouseError, match="reduce"):
        _order(ch, seq, "a", "buy", D("0.1"), 30000, reduce_only=True)
    with pytest.raises(ClearinghouseError, match="reduce"):
        _order(ch, seq, "a", "sell", 2, 30000, reduce_only=True)
    _order(ch, seq, "a", "sell", 1, 30000, reduce_only=True)   # rests fine
    _sound(ch)


def test_unrealized_profit_cannot_be_withdrawn_until_realized(ch, seq):
    for who in ("a", "b"):
        ch.deposit(who, D("10000"))
    _order(ch, seq, "b", "sell", 1, 30000)
    _order(ch, seq, "a", "buy", 1, 30000)
    ch.set_oracle_price(BTC, D("40000"))                  # a is up 10,000 on paper
    assert ch.withdrawable("a") <= ch.accounts["a"].collateral
    with pytest.raises(ClearinghouseError):
        ch.withdraw("a", ch.accounts["a"].collateral + 1)


def test_isolated_margin_moves_out_of_cross_and_back(ch, seq):
    for who in ("a", "b"):
        ch.deposit(who, D("100000"))
    ch.set_leverage("a", BTC, D("5"), isolated=True)
    _order(ch, seq, "b", "sell", 1, 30000)
    _order(ch, seq, "a", "buy", 1, 30000)
    pos = ch.accounts["a"].positions[BTC]
    assert pos.isolated_margin == D("6000")              # 30,000 / 5
    _sound(ch)
    ch.set_oracle_price(BTC, D("31000"))
    _order(ch, seq, "b", "buy", 1, 31000)
    _order(ch, seq, "a", "sell", 1, 31000, reduce_only=True)
    assert BTC not in ch.accounts["a"].positions          # margin + PnL back in cross
    _sound(ch)


def test_margin_mode_cannot_change_with_an_open_position(ch, seq):
    for who in ("a", "b"):
        ch.deposit(who, D("100000"))
    _order(ch, seq, "b", "sell", 1, 30000)
    _order(ch, seq, "a", "buy", 1, 30000)
    with pytest.raises(ClearinghouseError, match="mode"):
        ch.set_leverage("a", BTC, D("10"), isolated=True)


# ── fees and deposits ────────────────────────────────────────────────────

def test_fees_move_to_the_vault(ch, seq):
    for who in ("a", "b"):
        ch.deposit(who, D("100000"))
    _order(ch, seq, "b", "sell", 1, 30000)
    _order(ch, seq, "a", "buy", 1, 30000)
    assert ch.vault_collateral == D("30000") * (MAKER_FEE_RATE + TAKER_FEE_RATE)
    _sound(ch)


@pytest.mark.parametrize("amount", ["0", "-5", "1.0000000000000000001"])
def test_deposits_must_be_positive_wei_amounts(ch, amount):
    with pytest.raises(ClearinghouseError):
        ch.deposit("a", D(amount))


def test_a_market_needs_a_price_before_trading():
    c = Clearinghouse()
    c.create_market("ETH")
    c.deposit("a", D("1000"))
    with pytest.raises(ClearinghouseError, match="no price"):
        c.place_order("a", "ETH-QRDX-PERP", "o1", "buy", D("1"), D("2000"), 1)


# ── randomized: the invariants hold under any sequence ───────────────────

def test_invariants_hold_under_random_trading():
    rng = random.Random(20261001)
    ch = Clearinghouse()
    ch.create_market("BTC", max_leverage=D("20"))
    ch.create_market("ETH", max_leverage=D("10"))
    ch.set_oracle_price("BTC-QRDX-PERP", D("30000"))
    ch.set_oracle_price("ETH-QRDX-PERP", D("2000"))
    traders = [f"t{i}" for i in range(6)]
    for t in traders:
        ch.deposit(t, D(rng.randint(5_000, 200_000)))
        if rng.random() < 0.5:
            ch.set_leverage(t, "ETH-QRDX-PERP", D(rng.randint(1, 10)), isolated=True)
    n = 0
    deposited = sum(ch.accounts[t].collateral for t in traders)
    withdrawn = D(0)
    for step in range(600):
        mid = rng.choice(["BTC-QRDX-PERP", "ETH-QRDX-PERP"])
        m = ch.markets[mid]
        t = rng.choice(traders)
        action = rng.random()
        try:
            if action < 0.70:
                n += 1
                drift = D(rng.randint(-200, 200)) / 10000
                px = (m.mark_price * (1 + drift)).quantize(D("0.01"))
                ch.place_order(t, mid, f"o{n}", rng.choice(["buy", "sell"]),
                               D(rng.randint(1, 50)) / 10, px, n,
                               ioc=rng.random() < 0.3)
            elif action < 0.80:
                ch.set_oracle_price(mid, (m.mark_price * (1 + D(rng.randint(-300, 300)) / 10000)
                                          ).quantize(D("0.01")))
            elif action < 0.90:
                open_ids = [oid for oid, meta in m.orders.items() if meta.owner == t]
                if open_ids:
                    ch.cancel_order(t, mid, rng.choice(open_ids))
            else:
                amt = (ch.withdrawable(t) / 2).quantize(D("1e-18"))
                if amt > 0:
                    withdrawn += ch.withdraw(t, amt)
        except (ClearinghouseError, ValueError):
            pass
        _sound(ch)
        assert ch.holder_balance == deposited - withdrawn
        assert ch.holder_balance >= 0
    assert any(p.size != 0 for a in ch.accounts.values() for p in a.positions.values())


def test_the_state_hash_is_deterministic(seq):
    def build():
        c = Clearinghouse()
        c.create_market("BTC")
        c.set_oracle_price(BTC, D("30000"))
        c.deposit("a", D("100000"))
        c.deposit("b", D("100000"))
        s = Seq()
        for side, who in (("sell", "b"), ("buy", "a")):
            oid, nonce = s()
            c.place_order(who, BTC, oid, side, D("1"), D("30000"), nonce)
        return c
    assert build().state_hash() == build().state_hash()
