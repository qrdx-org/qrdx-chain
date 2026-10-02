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
