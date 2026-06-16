"""
Deterministic epoch reward/penalty deltas — qrdx.validator.epoch_rewards.
"""

from decimal import Decimal

from qrdx.validator.epoch_rewards import compute_epoch_reward_deltas


def _vals(*pairs):
    return [{"address": a, "effective_stake": s} for a, s in pairs]


def test_attester_rewarded_nonattester_penalized():
    rewards, penalties = compute_epoch_reward_deltas(
        _vals(("0xA", "10000"), ("0xB", "10000")), attester_addresses=["0xA"])
    assert rewards == {"0xA": Decimal("1.00000000")}      # 10000/10000
    assert penalties == {"0xB": Decimal("1.00000000")}


def test_deterministic():
    args = (_vals(("0xA", "50000"), ("0xB", "20000")), ["0xB"])
    assert compute_epoch_reward_deltas(*args) == compute_epoch_reward_deltas(*args)


def test_stake_proportional():
    rewards, _ = compute_epoch_reward_deltas(
        _vals(("0xA", "10000"), ("0xB", "20000")), attester_addresses=["0xA", "0xB"])
    assert rewards["0xB"] == rewards["0xA"] * 2


def test_zero_stake_skipped():
    rewards, penalties = compute_epoch_reward_deltas(
        _vals(("0xZ", "0")), attester_addresses=[])
    assert rewards == {} and penalties == {}


def test_no_attesters_all_penalized():
    rewards, penalties = compute_epoch_reward_deltas(
        _vals(("0xA", "10000"), ("0xB", "10000")), attester_addresses=[])
    assert rewards == {}
    assert set(penalties) == {"0xA", "0xB"}
