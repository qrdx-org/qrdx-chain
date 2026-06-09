"""
Phase E (increment 1) — exchange real-balance bridge + observe-only collateral check.

The exchange must eventually back perp margin with real account_state collateral.
This first increment adds the balance bridge (pre-load available balances) and an
OBSERVE-only check in open_position: it warns when margin exceeds the trader's
available balance but does NOT yet reject (the engine still opens the position).
Pins the bridge API + that the check observes without changing behaviour.
"""

import logging
from decimal import Decimal
from types import SimpleNamespace

from qrdx.exchange.state_manager import ExchangeStateManager


def _open_tx(sender, market_id, size="1", leverage="10", price="30000", side="long"):
    return SimpleNamespace(sender=sender, params={
        "market_id": market_id, "side": side, "size": size,
        "leverage": leverage, "price": price,
    })


def _mgr_with_market():
    mgr = ExchangeStateManager()
    market = mgr.perp_engine.create_market("BTC")  # BTC-QRDX-PERP
    return mgr, market.id


def test_balance_bridge_api():
    mgr = ExchangeStateManager()
    assert mgr.available_balance("0xPQaa") is None  # not loaded
    mgr.set_available_balance("0xPQaa", Decimal("1000"))
    assert mgr.available_balance("0xPQaa") == Decimal("1000")
    mgr.clear_available_balances()
    assert mgr.available_balance("0xPQaa") is None


def test_open_position_observes_insufficient_collateral(caplog):
    mgr, mid = _mgr_with_market()
    sender = "0xPQ" + "11" * 16
    # size 1 @ 30000, 10x → margin ~3000. Give only 100 available.
    mgr.set_available_balance(sender, Decimal("100"))
    with caplog.at_level(logging.WARNING):
        res = mgr._op_open_position(_open_tx(sender, mid))
    assert res.success, "observe-only: the position must still open (no rejection yet)"
    assert any("Phase E observe" in r.message for r in caplog.records), \
        "should warn that margin exceeds available collateral"


def test_open_position_no_warning_when_collateral_sufficient(caplog):
    mgr, mid = _mgr_with_market()
    sender = "0xPQ" + "22" * 16
    mgr.set_available_balance(sender, Decimal("1000000"))  # ample
    with caplog.at_level(logging.WARNING):
        res = mgr._op_open_position(_open_tx(sender, mid))
    assert res.success
    assert not any("Phase E observe" in r.message for r in caplog.records)


def test_no_check_when_balance_not_preloaded(caplog):
    """If balances aren't pre-loaded (None), the check is skipped — no false warns."""
    mgr, mid = _mgr_with_market()
    sender = "0xPQ" + "33" * 16
    with caplog.at_level(logging.WARNING):
        res = mgr._op_open_position(_open_tx(sender, mid))
    assert res.success
    assert not any("Phase E observe" in r.message for r in caplog.records)
