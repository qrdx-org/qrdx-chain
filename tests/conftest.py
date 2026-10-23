"""
Test-session defaults for consensus parameters that production leaves unset.

Perps settle in a configured collateral token (production: the bridged USD stablecoin; see
docs/PERPS_CLEARINGHOUSE.md). Most perps tests were written against native-QRDX settlement and
QRDX-quoted markets ("BTC-QRDX-PERP"), which remain a supported configuration; they run with it
here. Token settlement has its own tests (tests/test_perps_stablecoin.py), which set it
explicitly. Set before any test module imports qrdx.constants.
"""
import os

os.environ.setdefault("QRDX_PERP_COLLATERAL_TOKEN", "QRDX")
os.environ.setdefault("QRDX_PERP_QUOTE", "QRDX")
# Markets are listed without seeding a liquidity vault in most tests (the requirement — 10,000 by
# default — has its own: tests/test_market_liquidity.py).
os.environ.setdefault("QRDX_PERP_MARKET_MIN_LIQUIDITY", "0")
# Likewise without the order grid (sizes, prices, a minimum value: tests/test_order_grid.py).
os.environ.setdefault("QRDX_PERP_MIN_ORDER_VALUE", "0")
os.environ.setdefault("QRDX_PERP_DEFAULT_SZ_DECIMALS", "-1")

# Every incremental exchange root is checked against a from-scratch recomputation, so any code
# that changes exchange state without the commitment tracking seeing it fails the test that
# exercises it (qrdx/exchange/commitment.py).
os.environ.setdefault("QRDX_VERIFY_STATE_COMMITMENTS", "1")


import pytest  # noqa: E402


@pytest.fixture
def no_risk_limits(monkeypatch):
    """The perps price band and circuit breaker off (a chain spec may turn them off), for tests
    of defenses that must hold without them: the mark under a squeeze, the clearinghouse's
    zero-sum at any price. The limits have their own tests (tests/test_risk_limits.py)."""
    from qrdx import constants

    monkeypatch.setattr(constants, "PERP_PRICE_BAND_BPS", 0)
    monkeypatch.setattr(constants, "PERP_BREAKER_MOVE_BPS", 0)


@pytest.fixture
def no_staker_fees(monkeypatch):
    """The stakers' fee share off (STAKER_FEE_SHARE_BPS 0), for tests of the backstop vault's
    exact accounting that predate it. The share has its own tests (tests/test_staker_fees.py)."""
    from qrdx import constants

    monkeypatch.setattr(constants, "STAKER_FEE_SHARE_BPS", 0)


@pytest.fixture
def no_trading_fees(monkeypatch):
    """Trading fees off (every fee tier at zero), for tests of escrow and settlement mechanics
    that predate spot fees and check exact amounts. The fees have their own tests
    (tests/test_spot_fees.py; perps: tests/test_trading_ops.py)."""
    from decimal import Decimal

    from qrdx.exchange import clearinghouse

    monkeypatch.setattr(clearinghouse, "FEE_TIERS", ((Decimal(0), Decimal(0), Decimal(0)),))
