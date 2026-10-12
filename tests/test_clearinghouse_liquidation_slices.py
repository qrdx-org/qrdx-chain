"""
Large liquidations in slices, and the vault unwinding what it takes over
(docs/PERPS_CLEARINGHOUSE.md, Phase 3).

A position above LIQUIDATION_SLICE_NOTIONAL used to be sent to the book whole: on a thin book
one market order swept it down to the bankruptcy price. Now, as Hyperliquid, a book liquidation
sends LIQUIDATION_SLICE_FRACTION of it and the position cools down for
LIQUIDATION_COOLDOWN_SECONDS — meanwhile only the backstop acts.

The vault used to hold what it took over until it fell under maintenance itself. Now, once
every VAULT_UNWIND_SECONDS per market, it sends a slice to the book as a reduce-only IOC at most
VAULT_UNWIND_SLIPPAGE through mark — never dumping through a thin book.
"""
from decimal import Decimal

from qrdx.exchange.clearinghouse import (
    BACKSTOP_FRACTION, LIQUIDATION_COOLDOWN_SECONDS, LIQUIDATION_SLICE_FRACTION,
    LIQUIDATION_SLICE_NOTIONAL, VAULT, VAULT_UNWIND_SECONDS, VAULT_UNWIND_SLIPPAGE, Clearinghouse,
    _encode_account,
)

D = Decimal
BTC = "BTC-QRDX-PERP"
T0 = D(1_700_000_000)


def _ch():
    ch = Clearinghouse()
    ch.create_market("BTC")
    ch.set_oracle_price(BTC, D(30000))
    ch.deposit("bob", D(100_000_000))
    ch.deposit("carol", D(100_000_000))
    ch.deposit("lp", D(10_000_000))
    ch.vault_deposit("lp", D(1_000_000), T0, 0)            # a vault with capital to take over
    return ch


def _long(ch, size, deposit):
    """Alice goes long ``size`` at 30,000 against bob."""
    ch.deposit("alice", D(deposit))
    ch.place_order("bob", BTC, "s", "sell", D(size), D(30000), 0)
    ch.place_order("alice", BTC, "b", "buy", D(size), D(30000), 0)


def _price_at(ch, owner, fraction_of_maintenance):
    """The mark at which ``owner``'s single long has equity = fraction × maintenance."""
    a = ch.accounts[owner]
    p = a.positions[BTC]
    r = ch.markets[BTC].maintenance_rate
    # collateral + size·(P − entry) = f · size · P · r
    price = (p.size * p.entry_price - a.collateral) / (p.size * (1 - fraction_of_maintenance * r))
    return price.quantize(D("0.01"))


def _sound(ch):
    assert ch.identity_gap() == 0
    assert ch.net_size(BTC) == 0


def _liquidations(events):
    return [e for e in events if e["type"] == "liquidation"]


# ── slices ────────────────────────────────────────────────────────────────

def test_a_large_position_is_liquidated_a_slice_at_a_time():
    ch = _ch()
    _long(ch, 10, 40_000)                                   # 300,000 notional
    price = _price_at(ch, "alice", D("0.7"))                # under maintenance, over ⅔
    assert 10 * price > LIQUIDATION_SLICE_NOTIONAL
    ch.set_oracle_price(BTC, price)
    ch.place_order("carol", BTC, "bid", "buy", D(10), price - 5, 0)   # deep enough for all
    events = _liquidations(ch.tick(T0))
    assert [(e["stage"], e["filled"]) for e in events] == [("book", 10 * LIQUIDATION_SLICE_FRACTION)]
    pos = ch.accounts["alice"].positions[BTC]
    assert pos.size == 8 and pos.close_time == T0
    assert ch.cross_equity("alice") < ch.cross_maintenance("alice")   # still under …
    assert _liquidations(ch.tick(T0 + 10)) == []                       # … but cooling down
    assert ch.accounts["alice"].positions[BTC].size == 8
    events = _liquidations(ch.tick(T0 + LIQUIDATION_COOLDOWN_SECONDS))
    assert [e["filled"] for e in events] == [D("1.6")]      # the next slice, of what is left
    assert ch.accounts["alice"].positions[BTC].size == D("6.4")
    _sound(ch)


def test_the_backstop_acts_during_the_cooldown():
    ch = _ch()
    _long(ch, 10, 40_000)
    price = _price_at(ch, "alice", D("0.9"))
    ch.set_oracle_price(BTC, price)
    ch.place_order("carol", BTC, "bid", "buy", D(2), price - 5, 0)
    assert [e["stage"] for e in _liquidations(ch.tick(T0))] == ["book"]
    ch.set_oracle_price(BTC, _price_at(ch, "alice", BACKSTOP_FRACTION / 2))   # far under ⅔
    events = _liquidations(ch.tick(T0 + 5))
    assert [e["stage"] for e in events] == ["backstop"]
    assert BTC not in ch.accounts["alice"].positions
    assert ch.accounts[VAULT].positions[BTC].size == 8
    _sound(ch)


def test_a_position_under_the_slice_notional_is_closed_whole():
    ch = _ch()
    _long(ch, 1, 3500)                                      # 30,000 notional
    price = _price_at(ch, "alice", D("0.9"))
    ch.set_oracle_price(BTC, price)
    ch.place_order("carol", BTC, "bid", "buy", D(1), price - 5, 0)
    assert [e["filled"] for e in _liquidations(ch.tick(T0))] == [1]
    assert BTC not in ch.accounts["alice"].positions
    _sound(ch)


def test_the_close_time_is_committed_only_once_set():
    """Accounts that never met a protocol close encode exactly as before (unchanged roots)."""
    ch = _ch()
    _long(ch, 10, 40_000)
    assert len(_encode_account("alice", ch.accounts["alice"])["positions"][BTC]) == 3
    price = _price_at(ch, "alice", D("0.9"))
    ch.set_oracle_price(BTC, price)
    ch.place_order("carol", BTC, "bid", "buy", D(10), price - 5, 0)
    ch.tick(T0)
    assert _encode_account("alice", ch.accounts["alice"])["positions"][BTC][3] == str(T0)


# ── the vault unwinds ─────────────────────────────────────────────────────

def _vault_takes(ch, size, deposit):
    """No bids at all: alice's long goes straight to the vault."""
    _long(ch, size, deposit)
    price = _price_at(ch, "alice", BACKSTOP_FRACTION / 2)
    ch.set_oracle_price(BTC, price)
    assert [e["stage"] for e in _liquidations(ch.tick(T0))] == ["backstop"]
    assert ch.accounts[VAULT].positions[BTC].size == size
    assert ch.accounts[VAULT].positions[BTC].close_time == T0
    return ch.markets[BTC].mark_price


def test_the_vault_unwinds_what_it_took_over_near_mark():
    ch = _ch()
    mark = _vault_takes(ch, 1, 3500)
    ch.place_order("carol", BTC, "bid", "buy", D(1), (mark * D("0.998")).quantize(D("0.01")), 0)
    assert [e for e in ch.tick(T0 + 10) if e["type"] == "vault_unwind"] == []   # too soon
    events = [e for e in ch.tick(T0 + VAULT_UNWIND_SECONDS) if e["type"] == "vault_unwind"]
    assert [(e["market"], e["filled"]) for e in events] == [(BTC, 1)]
    assert BTC not in ch.accounts[VAULT].positions
    assert ch.accounts["carol"].positions[BTC].size == 1
    _sound(ch)


def test_the_vault_never_sells_through_the_slippage_limit():
    ch = _ch()
    mark = _vault_takes(ch, 1, 3500)
    too_low = (mark * (1 - 2 * VAULT_UNWIND_SLIPPAGE)).quantize(D("0.01"))
    ch.place_order("carol", BTC, "bid", "buy", D(1), too_low, 0)
    assert [e for e in ch.tick(T0 + VAULT_UNWIND_SECONDS) if e["type"] == "vault_unwind"] == []
    pos = ch.accounts[VAULT].positions[BTC]
    assert pos.size == 1 and pos.close_time == T0 + VAULT_UNWIND_SECONDS   # tries again later
    assert ch.markets[BTC].book.get_order("bid").filled == 0
    _sound(ch)


def test_a_large_vault_position_unwinds_in_slices():
    ch = _ch()
    mark = _vault_takes(ch, 10, 40_000)
    ch.place_order("carol", BTC, "bid", "buy", D(10), mark, 0)
    t = T0
    sizes = []
    for _ in range(3):
        t += VAULT_UNWIND_SECONDS
        ch.tick(t)
        sizes.append(ch.accounts[VAULT].positions[BTC].size)
    assert sizes == [D(8), D("6.4"), D("5.12")]
    _sound(ch)
