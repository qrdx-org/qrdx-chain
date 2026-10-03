"""
Phase E prerequisite — CREATE_MARKET exchange op makes perps reachable via consensus.

Without this there is no way to create a perp market on the live network, so no perp can
trade. Markets live in the clearinghouse (docs/PERPS_CLEARINGHOUSE.md). Pins: the op creates a market (changing the
exchange root), positions can then be opened, duplicates fail non-critically, and
param validation requires base_token.
"""
from decimal import Decimal
from types import SimpleNamespace

import pytest

from qrdx.exchange.state_manager import ExchangeStateManager
from qrdx.exchange.transactions import ExchangeOpType, ExchangeTransaction



def _create_market_tx(sender="0xPQaa", base="BTC", **extra):
    return SimpleNamespace(op_type=ExchangeOpType.CREATE_MARKET, sender=sender,
                           params={"base_token": base, **extra})


def _order_tx(sender, market_id, side, nonce):
    """A PERP_ORDER as the manager receives it (tx_hash supplies the order id)."""
    return SimpleNamespace(op_type=ExchangeOpType.PERP_ORDER, sender=sender, nonce=nonce,
                           params={"market_id": market_id, "side": side, "size": "1",
                                   "price": "30000"},
                           tx_hash=lambda: f"{sender}-{nonce}".ljust(16, "0"))


def test_create_market_then_trade():
    mgr = ExchangeStateManager()
    root_before = mgr.compute_state_root()
    res = mgr._op_create_market(_create_market_tx())
    assert res.success and res.data["market_id"] == "BTC-QRDX-PERP"
    assert mgr.compute_state_root() != root_before, "market creation must change the exchange root"
    ch = mgr.clearinghouse
    for who in ("0xPQbb", "0xPQcc"):
        ch.deposit(who, Decimal("100000"))
    # A new market cannot trade until it has an oracle price...
    unpriced = mgr._op_perp_order(_order_tx("0xPQbb", "BTC-QRDX-PERP", "buy", 1))
    assert not unpriced.success and "no price" in unpriced.error
    # ...and once it has one, an order book trade opens equal and opposite positions.
    ch.set_oracle_price("BTC-QRDX-PERP", Decimal("30000"))
    assert mgr._op_perp_order(_order_tx("0xPQcc", "BTC-QRDX-PERP", "sell", 2)).success
    assert mgr._op_perp_order(_order_tx("0xPQbb", "BTC-QRDX-PERP", "buy", 3)).success
    assert ch.accounts["0xPQbb"].positions["BTC-QRDX-PERP"].size == 1
    assert ch.net_size("BTC-QRDX-PERP") == 0


def test_duplicate_market_is_noncritical_failure():
    mgr = ExchangeStateManager()
    assert mgr._op_create_market(_create_market_tx()).success
    dup = mgr._op_create_market(_create_market_tx())
    assert not dup.success and "exists" in (dup.error or "").lower()


def test_an_order_on_a_missing_market_fails():
    mgr = ExchangeStateManager()
    res = mgr._op_perp_order(_order_tx("0xPQcc", "BTC-QRDX-PERP", "buy", 1))
    assert not res.success and "not found" in res.error


def test_validation_requires_base_token():
    # validate_basic() runs the per-op param checks: missing base_token raises.
    bad = ExchangeTransaction(
        op_type=ExchangeOpType.CREATE_MARKET, sender="0xPQaa", nonce=0,
        params={}, gas_limit=1_000_000, gas_price=10**9)
    with pytest.raises(ValueError):
        bad.validate_basic()
    ok = ExchangeTransaction(
        op_type=ExchangeOpType.CREATE_MARKET, sender="0xPQaa", nonce=0,
        params={"base_token": "ETH"}, gas_limit=1_000_000, gas_price=10**9)
    assert ok.validate_basic()  # should not raise
