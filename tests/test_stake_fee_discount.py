"""
Staking fee discounts (docs/HYPERLIQUID_PARITY.md), Hyperliquid's: an account with QRDX at stake —
its own validator principal, its delegations at their pool's price — pays less in trading fees,
by tier. The stake comes from the validator set in force at the block's parent, loaded with the
oracle committee on every path.
"""
from decimal import Decimal as D

from qrdx.exchange.clearinghouse import FEE_TIERS, STAKE_FEE_DISCOUNTS, Clearinghouse
from qrdx.validator.epoch_state import EpochInputs, Pool, genesis_state, stakes, transition

V = "0xPQ" + "1" * 64
DELEGATOR = "0xPQ" + "d" * 64


def test_stakes_count_principal_and_pool_shares():
    s = genesis_state([{"address": V, "stake": "50000"}])
    s.pools[V] = Pool(V, 1000, value=D(2000), total_shares=D(1000), shares={DELEGATOR: D(500)})
    got = stakes(s)
    assert got[V.lower()] == 50000 and got[DELEGATOR.lower()] == 1000      # 500 shares at 2


def test_a_new_state_never_reuses_its_parents_stakes():
    s = genesis_state([{"address": V, "stake": "50000"}])
    assert stakes(s)[V.lower()] == 50000
    nxt = transition(s, 1, EpochInputs(ops=[("deposit", V, None, D(1000))], attesters=[],
                                       offenders=[]))
    assert stakes(nxt)[V.lower()] == 51000


def test_fees_shrink_by_the_stake_tier_and_rebates_stay_whole():
    ch = Clearinghouse()
    base_taker, base_maker = FEE_TIERS[0][1], FEE_TIERS[0][2]
    assert ch.fee_rates("0xPQa") == (base_taker, base_maker)
    for floor, discount in STAKE_FEE_DISCOUNTS:
        ch._staked = {"0xpqa": floor}
        taker, maker = ch.fee_rates("0xPQa")
        assert taker == base_taker * (1 - discount)
        assert maker == (base_maker * (1 - discount) if base_maker > 0 else base_maker)
