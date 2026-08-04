"""
Phase E — CREATE_POOL must debit the creator's real QRDX stake.

Pool creation validates ``stake_amount >= the per-type minimum`` but historically
never DEBITED it, so creating a pool cost nothing. This adds an observe→enforce
stake debit (mirroring the perp-margin path): the declared stake is checked against
the creator's pre-loaded available balance and recorded as a negative account_state
delta (flushed by the async wrapper), held in ``pool.state.stake_amount`` for a future
remove-pool return (staking pools) / forfeit (subsidized = burn).

Gated by ``enforce_pool_stake`` — SEPARATE from ``enforce_collateral`` because the
shared account_state flush is already enforced for collateral, so the DELTA RECORDING
(not just the flush) must be gated or the stake would debit as soon as collateral is.
"""

import logging
from decimal import Decimal
from types import SimpleNamespace

from qrdx.exchange.state_manager import ExchangeStateManager
from qrdx.exchange.amm import FeeTier, PoolType


def _pool_tx(sender, stake="10000", pool_type=PoolType.STANDARD,
             token0="0xAAA", token1="0xBBB"):
    return SimpleNamespace(sender=sender, params={
        "token0": token0, "token1": token1,
        "fee_tier": int(FeeTier.MEDIUM), "pool_type": int(pool_type),
        "initial_sqrt_price": "1000000000", "stake_amount": stake,
    })


def test_create_pool_observes_insufficient_stake(caplog):
    """Observe (default): warns when the creator can't afford the stake but still creates."""
    mgr = ExchangeStateManager()
    sender = "0xPQ" + "11" * 16
    mgr.set_available_balance(sender, Decimal("100"))  # << 10000 required
    with caplog.at_level(logging.WARNING):
        res = mgr._op_create_pool(_pool_tx(sender))
    assert res.success, "observe-only: the pool must still be created (no rejection yet)"
    assert any("Phase E observe" in r.message for r in caplog.records)
    assert mgr.balance_deltas() == {}, "observe: no real debit recorded"


def test_create_pool_no_debit_when_not_enforced():
    """Default (gate off): even an affordable stake records NO delta (behaviour-neutral)."""
    mgr = ExchangeStateManager()
    sender = "0xPQ" + "22" * 16
    mgr.set_available_balance(sender, Decimal("1000000"))
    res = mgr._op_create_pool(_pool_tx(sender))
    assert res.success
    assert mgr.balance_deltas() == {}


def test_create_pool_no_check_when_balance_not_preloaded(caplog):
    """If balances aren't pre-loaded (None), the check is skipped — no false warns."""
    mgr = ExchangeStateManager()
    sender = "0xPQ" + "33" * 16
    with caplog.at_level(logging.WARNING):
        res = mgr._op_create_pool(_pool_tx(sender))
    assert res.success
    assert not any("Phase E observe" in r.message for r in caplog.records)


def test_enforce_debits_stake_from_creator():
    """Enforce: the declared stake is a real negative balance delta + reduces available."""
    mgr = ExchangeStateManager()
    sender = "0xPQ" + "44" * 16
    mgr.enforce_pool_stake = True
    mgr.set_available_balance(sender, Decimal("1000000"))
    res = mgr._op_create_pool(_pool_tx(sender, stake="10000"))
    assert res.success
    assert mgr.balance_deltas()[sender] == -Decimal("10000")
    assert mgr.available_balance(sender) == Decimal("1000000") - Decimal("10000")


def test_enforce_rejects_unaffordable_stake():
    """Enforce: a creator who can't cover the stake is rejected, no pool, no delta."""
    mgr = ExchangeStateManager()
    sender = "0xPQ" + "55" * 16
    mgr.enforce_pool_stake = True
    mgr.set_available_balance(sender, Decimal("100"))  # << 10000
    res = mgr._op_create_pool(_pool_tx(sender))
    assert not res.success
    assert "insufficient balance for pool stake" in (res.error or "")
    assert mgr.balance_deltas() == {}


def test_enforce_subsidized_burn_debits_stake():
    """Subsidized pools burn their stake — still a real debit of the declared amount."""
    mgr = ExchangeStateManager()
    sender = "0xPQ" + "66" * 16
    mgr.enforce_pool_stake = True
    mgr.set_available_balance(sender, Decimal("1000000"))
    res = mgr._op_create_pool(_pool_tx(sender, stake="5000", pool_type=PoolType.SUBSIDIZED))
    assert res.success
    assert mgr.balance_deltas()[sender] == -Decimal("5000")


def test_enforce_below_minimum_stake_still_rejected_by_create():
    """create_pool's own stake>=minimum validation still applies under enforce (raises →
    the op surfaces the failure), and no debit is recorded for a failed create."""
    mgr = ExchangeStateManager()
    sender = "0xPQ" + "77" * 16
    mgr.enforce_pool_stake = True
    mgr.set_available_balance(sender, Decimal("1000000"))
    # 500 < STANDARD's 10000 minimum → create_pool raises inside the op.
    try:
        res = mgr._op_create_pool(_pool_tx(sender, stake="500"))
        assert not res.success
    except ValueError:
        pass  # create_pool raised on stake < required
    assert mgr.balance_deltas() == {}, "no debit when the pool was not created"
