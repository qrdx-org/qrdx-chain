"""
Phase E — the exchange's real-balance bridge (pre-loaded available balances).

The perp-specific tests that used to live here exercised OPEN_POSITION / CLOSE_POSITION /
ADD_MARGIN, which traded against nobody and so minted and burned QRDX. Those ops are retired;
perp collateral now lives in the clearinghouse (docs/PERPS_CLEARINGHOUSE.md) and is covered by
tests/test_clearinghouse.py, tests/test_perps_manager.py and
tests/test_exchange_collateral_determinism.py.
"""

from decimal import Decimal

from qrdx.exchange.state_manager import ExchangeStateManager


def test_balance_bridge_api():
    mgr = ExchangeStateManager()
    assert mgr.available_balance("0xPQaa") is None  # not loaded
    mgr.set_available_balance("0xPQaa", Decimal("1000"))
    assert mgr.available_balance("0xPQaa") == Decimal("1000")
    mgr.clear_available_balances()
    assert mgr.available_balance("0xPQaa") is None
