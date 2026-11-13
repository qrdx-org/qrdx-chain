"""
The perps order grid (docs/HYPERLIQUID_PARITY.md), Hyperliquid's: sizes in whole lots of the
market's ``sz_decimals``, prices in at most 5 significant figures and 6 − sz_decimals decimals,
and an order worth at least PERP_MIN_ORDER_VALUE unless it only reduces.
"""
from decimal import Decimal as D

import pytest

from qrdx import constants
from qrdx.exchange.clearinghouse import Clearinghouse, ClearinghouseError

MID = "BTC-QRDX-PERP"


@pytest.fixture
def ch(monkeypatch):
    monkeypatch.setattr(constants, "PERP_MIN_ORDER_VALUE", 10)
    c = Clearinghouse()
    c.create_market("BTC", sz_decimals=3)
    c.set_oracle_price(MID, D(30000))
    for who in ("a", "b"):
        c.deposit(who, D(1_000_000))
    return c


@pytest.mark.parametrize("size, price, why", [
    ("0.0005", "30000", "multiples of 0.001"),
    ("1", "30000.5", "significant figures"),             # 6 significant figures
    ("1", "3.1234", "decimals"),                          # 3 decimals at most with sz 3
    ("0.0001", "30000", "multiples"),
    ("0.0003", "30000", "multiples"),
])
def test_an_order_off_the_grid_is_refused(ch, size, price, why):
    with pytest.raises(ClearinghouseError, match=why):
        ch.place_order("a", MID, "x", "buy", D(size), D(price), 0)


@pytest.mark.parametrize("size, price", [("0.001", "30000"), ("1.25", "29999"),
                                         ("2", "31234"), ("0.5", "30001")])
def test_an_order_on_the_grid_is_placed(ch, size, price):
    ch.place_order("a", MID, "x", "buy", D(size), D(price), 0)


def test_a_small_order_is_refused_unless_it_only_reduces(ch):
    eth = "ETH-QRDX-PERP"
    ch.create_market("ETH", sz_decimals=3)
    ch.set_oracle_price(eth, D(3000))
    with pytest.raises(ClearinghouseError, match="worth at least 10"):
        ch.place_order("a", eth, "x", "buy", D("0.001"), D("3000"), 0)     # worth 3
    ch.place_order("b", eth, "s", "sell", D("1"), D("3000"), 0)
    ch.place_order("a", eth, "b", "buy", D("1"), D("3000"), 0)
    ch.place_order("b", eth, "s2", "buy", D("1"), D("3000"), 1)
    ch.place_order("a", eth, "r", "sell", D("0.001"), D("3000"), 1, reduce_only=True, ioc=True)


def test_triggers_and_modifies_keep_to_the_grid(ch):
    with pytest.raises(ClearinghouseError, match="significant figures"):
        ch.place_trigger("a", MID, "t", "sell", "sl", D("25000.5"), size=D(1))
    ch.place_trigger("a", MID, "t", "sell", "sl", D("25000"), size=D(1))
    ch.place_order("a", MID, "o", "buy", D(1), D(29000), 0)
    with pytest.raises(ClearinghouseError, match="multiples"):
        ch.modify_order("a", MID, "o", "o2", size=D("0.0005"))


def test_a_market_without_a_grid_takes_any_size(monkeypatch):
    monkeypatch.setattr(constants, "PERP_MIN_ORDER_VALUE", 0)
    c = Clearinghouse()
    c.create_market("BTC")
    c.set_oracle_price(MID, D(30000))
    c.deposit("a", D(1_000_000))
    c.place_order("a", MID, "x", "buy", D("0.00012345"), D("30000.123"), 0)
