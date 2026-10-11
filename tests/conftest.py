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

# Every incremental exchange root is checked against a from-scratch recomputation, so any code
# that changes exchange state without the commitment tracking seeing it fails the test that
# exercises it (qrdx/exchange/commitment.py).
os.environ.setdefault("QRDX_VERIFY_STATE_COMMITMENTS", "1")
