"""
Deterministic epoch reward/penalty deltas — qrdx.validator.epoch_rewards.
"""

from decimal import Decimal

from qrdx.validator.epoch_rewards import compute_epoch_reward_deltas, reward_quotient


def _vals(*pairs):
    return [{"address": a, "effective_stake": s} for a, s in pairs]


def test_attester_rewarded_nonattester_penalized():
    rewards, penalties = compute_epoch_reward_deltas(
        _vals(("0xA", "10000"), ("0xB", "10000")), attester_addresses=["0xA"],
        reward_quotient=Decimal(10000))
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


def test_the_rate_is_per_unit_of_time_not_per_epoch():
    """0.01% of stake per 64 s, whatever the slot: 8 s epochs (250 ms x 32, the standard) each
    carry an eighth of what 64 s epochs (2 s x 32) did, so a day accrues the same."""
    assert reward_quotient(2000, 32) == 10_000
    assert reward_quotient(250, 32) == 80_000
    assert reward_quotient(250, 8) == 320_000
    day_ms = 86_400_000
    for slot_ms, per_epoch in ((2000, 32), (250, 32), (500, 16)):
        epochs = Decimal(day_ms) / (slot_ms * per_epoch)
        assert epochs / reward_quotient(slot_ms, per_epoch) == Decimal(day_ms) / 64_000 / 10_000
