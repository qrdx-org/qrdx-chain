"""
Oracle hardening (docs/CONSENSUS_ROADMAP.md 5): a price needs ORACLE_MIN_VOTERS fresh votes as
well as a stake majority; it moves at most ORACLE_MAX_STEP_BPS a second of block time; and votes
far from the median are recorded against their validators.
"""
from decimal import Decimal

import pytest

from test_validator_oracle import BTC, T0, _oracle, _vote, setup  # noqa: F401  (fixture)

from qrdx import constants

pytestmark = pytest.mark.usefixtures("open_listing")  # lists markets with CREATE_MARKET

D = Decimal


def test_one_validator_with_a_stake_majority_is_not_enough(setup):
    mgr, v1, v2, v3, _ = setup
    assert _vote(mgr, v3, 30000).success                 # 300 of 500: a majority, one voter
    mgr.apply_oracle_votes(T0)
    assert _oracle(mgr) == 0
    assert _vote(mgr, v1, 30100).success and _vote(mgr, v2, 29900).success
    mgr.apply_oracle_votes(T0)
    assert _oracle(mgr) == D(30000)


def test_a_small_committee_needs_only_its_whole_self(setup, monkeypatch):
    mgr, v1, v2, v3, _ = setup
    monkeypatch.setattr(constants, "ORACLE_MIN_VOTERS", 10)
    for who in (v1, v2, v3):
        assert _vote(mgr, who, 30000).success
    mgr.apply_oracle_votes(T0)
    assert _oracle(mgr) == D(30000)                       # 3 of 3, though 10 are asked for


def test_the_price_walks_at_most_the_step_a_second(setup):
    mgr, v1, v2, v3, _ = setup
    for who in (v1, v2, v3):
        _vote(mgr, who, 30000)
    mgr.apply_oracle_votes(T0)
    step = D(constants.ORACLE_MAX_STEP_BPS) / 10_000
    for who in (v1, v2, v3):
        _vote(mgr, who, 15000, at=T0 + 1)                 # -50 % at once
    mgr.apply_oracle_votes(T0 + 1)
    assert _oracle(mgr) == D(30000) * (1 - step)          # one second: one step
    for t in range(2, 30):
        for who in (v1, v2, v3):
            _vote(mgr, who, 15000, at=T0 + t)
        mgr.apply_oracle_votes(T0 + t)
    assert _oracle(mgr) == D(15000)                       # it gets there while votes hold


def test_a_stale_oracle_catches_up_at_once(setup):
    """The bound is per second since the oracle last moved: after a halt it is no bound."""
    mgr, v1, v2, v3, _ = setup
    for who in (v1, v2, v3):
        _vote(mgr, who, 30000)
    mgr.apply_oracle_votes(T0)
    later = T0 + 3600
    for who in (v1, v2, v3):
        _vote(mgr, who, 20000, at=later)
    mgr.apply_oracle_votes(later)
    assert _oracle(mgr) == D(20000)


def test_outlying_votes_are_recorded_against_their_validators(setup):
    mgr, v1, v2, v3, _ = setup
    before = mgr.oracle_state_hash()
    _vote(mgr, v1, 30000)
    _vote(mgr, v2, 30010)
    _vote(mgr, v3, 30000)
    mgr.apply_oracle_votes(T0)
    assert mgr.oracle_outliers == {}
    _vote(mgr, v1, 36000, at=T0 + 1)                      # 20 % off the median
    mgr.apply_oracle_votes(T0 + 1)
    assert mgr.oracle_outliers == {v1.addr.lower(): 1}
    assert mgr.oracle_state_hash() != before
    snap = mgr.capture()
    mgr.oracle_outliers = {}
    mgr._restore_snapshot(snap)
    assert mgr.oracle_outliers == {v1.addr.lower(): 1}
