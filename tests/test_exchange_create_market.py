"""
Phase E prerequisite — CREATE_MARKET exchange op makes perps reachable via consensus.

Without this there is no way to create a perp market on the live network, so
OPEN_POSITION can never succeed. Pins: the op creates a market (changing the
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


def _open_tx(sender, market_id):
    return SimpleNamespace(op_type=ExchangeOpType.OPEN_POSITION, sender=sender, params={
        "market_id": market_id, "side": "long", "size": "1", "leverage": "10", "price": "30000"})


def test_create_market_then_open_position():
    mgr = ExchangeStateManager()
    root_before = mgr.compute_state_root()
    res = mgr._op_create_market(_create_market_tx())
    assert res.success and res.data["market_id"] == "BTC-QRDX-PERP"
    assert mgr.compute_state_root() != root_before, "market creation must change the exchange root"
    # Now a position can be opened on it (previously impossible — no market).
    opened = mgr._op_open_position(_open_tx("0xPQbb", "BTC-QRDX-PERP"))
    assert opened.success


def test_duplicate_market_is_noncritical_failure():
    mgr = ExchangeStateManager()
    assert mgr._op_create_market(_create_market_tx()).success
    dup = mgr._op_create_market(_create_market_tx())
    assert not dup.success and "exists" in (dup.error or "").lower()


def test_open_position_without_market_fails():
    mgr = ExchangeStateManager()
    # No market exists → opening cannot succeed (raises; the block processor treats
    # it as a failed tx). The point: it does NOT open a position.
    with pytest.raises(Exception):
        mgr._op_open_position(_open_tx("0xPQcc", "BTC-QRDX-PERP"))


def test_validation_requires_base_token():
    # validate_basic() runs the per-op param checks: missing base_token raises.
    bad = ExchangeTransaction(
        op_type=ExchangeOpType.CREATE_MARKET, sender="0xPQaa", nonce=0,
        params={}, gas_limit=1_000_000, gas_price=Decimal("1"))
    with pytest.raises(ValueError):
        bad.validate_basic()
    ok = ExchangeTransaction(
        op_type=ExchangeOpType.CREATE_MARKET, sender="0xPQaa", nonce=0,
        params={"base_token": "ETH"}, gas_limit=1_000_000, gas_price=Decimal("1"))
    assert ok.validate_basic()  # should not raise
