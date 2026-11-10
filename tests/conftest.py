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
# No genesis perp markets (BTC, ETH, SOL by default): a test lists what it trades. Genesis markets
# have their own tests (tests/test_perp_markets.py), and the ``genesis_btc`` fixture.
os.environ.setdefault("QRDX_PERP_GENESIS_MARKETS", "")

# Every incremental exchange root is checked against a from-scratch recomputation, so any code
# that changes exchange state without the commitment tracking seeing it fails the test that
# exercises it (qrdx/exchange/commitment.py).
os.environ.setdefault("QRDX_VERIFY_STATE_COMMITMENTS", "1")
# Every answer the chain index gives from memory, checked against its table (qrdx/chain_index.py).
os.environ.setdefault("QRDX_VERIFY_CHAIN_INDEX", "1")
# Each open store reserves address space for its file (qrdx/store.py): tests open hundreds.
os.environ.setdefault("QRDX_STORE_MAX_GB", "2")


import pytest  # noqa: E402


def pytest_sessionfinish(session, exitstatus):
    """The stores beside the temporary databases tests made and deleted (a test removes its
    ``.db`` file; the store's file and lock file sit beside it: qrdx/store.py)."""
    import glob
    import tempfile

    for path in glob.glob(os.path.join(tempfile.gettempdir(), "*.db.store")):
        if not os.path.exists(path[: -len(".store")]):
            for name in (path, path + "-lck"):
                try:
                    os.remove(name)
                except OSError:
                    pass


@pytest.fixture
def no_risk_limits(monkeypatch):
    """The perps price band and circuit breaker off (a chain spec may turn them off), for tests
    of defenses that must hold without them: the mark under a squeeze, the clearinghouse's
    zero-sum at any price. The limits have their own tests (tests/test_risk_limits.py)."""
    from qrdx import constants

    monkeypatch.setattr(constants, "PERP_PRICE_BAND_BPS", 0)
    monkeypatch.setattr(constants, "PERP_BREAKER_MOVE_BPS", 0)


@pytest.fixture
def genesis_btc(monkeypatch):
    """BTC, the one genesis perp market (PERP_GENESIS_MARKETS): every block path — forward,
    import and rebuild — creates it with the first block, so a test on a chain of blocks trades
    it from the start. Maximum leverage 20, no order grid."""
    from qrdx import constants

    monkeypatch.setattr(constants, "PERP_GENESIS_MARKETS", ("BTC:20:-1",))


@pytest.fixture
def oracle_committee():
    """A one-validator oracle committee for tests that price validator markets with real votes
    (ORACLE_VOTE): no single key prices a market, so a test's prices come the way a network's
    do. ``load(mgr)`` sets the committee on a manager (each rebuild's too); ``vote(prices)``
    signs a vote — it applies at its block's tick, after the block's transactions."""
    import json
    from types import SimpleNamespace

    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.exchange import ExchangeOpType, ExchangeTransaction

    key = PQPrivateKey.generate()
    addr = key.public_key.to_address()
    genesis = json.dumps({"type": "genesis", "validators": 1,
                          "validator_set": [{"address": addr, "stake": "1000"}]})
    seq = [0]

    def vote(prices):
        seq[0] += 1
        tx = ExchangeTransaction(op_type=ExchangeOpType.ORACLE_VOTE, sender=addr, nonce=seq[0],
                                 params={"prices": {b: str(p) for b, p in prices.items()}},
                                 gas_limit=100_000)
        tx.public_key = key.public_key.to_bytes()
        tx.signature = key.sign(tx.signing_bytes()).to_bytes()
        return tx

    return SimpleNamespace(address=addr, key=key, genesis=genesis,
                           load=lambda mgr: mgr.load_oracle_committee(genesis), vote=vote)


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
