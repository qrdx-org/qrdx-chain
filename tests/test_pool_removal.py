"""
Phase E — REMOVE_POOL refunds the creator's staked QRDX (the mirror of the CREATE_POOL stake
debit; completes the pool-stake lifecycle so stake is not locked forever).

Rules: only the creator removes; only an EMPTY pool (liquidity withdrawn first); a STAKING pool
refunds the exact staked amount; a SUBSIDIZED pool BURNED its stake → no refund. The refund is a
real account_state credit delta (reorg-reconstructed like a perp-margin release), gated by
``enforce_pool_stake`` (only refund when the debit actually happened).
"""
from decimal import Decimal
from types import SimpleNamespace

from qrdx.exchange.state_manager import ExchangeStateManager
from qrdx.exchange.amm import FeeTier, PoolType


def _create_tx(sender, stake="10000", pool_type=PoolType.STANDARD, token0="0xAAA", token1="0xBBB"):
    return SimpleNamespace(sender=sender, nonce=0, params={
        "token0": token0, "token1": token1, "fee_tier": int(FeeTier.MEDIUM),
        "pool_type": int(pool_type), "initial_sqrt_price": "1000000000", "stake_amount": stake})


def _remove_tx(sender, pool_id):
    return SimpleNamespace(sender=sender, nonce=1, params={"pool_id": pool_id})


def _mgr_enforced():
    mgr = ExchangeStateManager()
    mgr.enforce_pool_stake = True
    return mgr


def test_remove_pool_refunds_creator_stake():
    mgr = _mgr_enforced()
    creator = "0xPQ" + "11" * 16
    mgr.set_available_balance(creator, Decimal("1000000"))
    cr = mgr._op_create_pool(_create_tx(creator, stake="10000"))
    assert cr.success
    assert mgr.balance_deltas()[creator] == -Decimal("10000")  # debited on create
    pool_id = cr.data["pool_id"]

    rr = mgr._op_remove_pool(_remove_tx(creator, pool_id))
    assert rr.success and rr.data["refunded_stake"] == "10000"
    # Net over create(-10000) + remove(+10000) == 0 → stake returned exactly.
    assert mgr.balance_deltas()[creator] == Decimal("0")
    # Pool is gone.
    assert mgr.pool_manager.get_pool(pool_id) is None


def test_remove_pool_rejects_non_creator():
    mgr = _mgr_enforced()
    creator = "0xPQ" + "22" * 16
    other = "0xPQ" + "33" * 16
    mgr.set_available_balance(creator, Decimal("1000000"))
    pool_id = mgr._op_create_pool(_create_tx(creator)).data["pool_id"]
    rr = mgr._op_remove_pool(_remove_tx(other, pool_id))
    assert not rr.success and "creator" in (rr.error or "")
    assert mgr.pool_manager.get_pool(pool_id) is not None  # not removed


def test_remove_pool_rejects_with_active_liquidity():
    mgr = _mgr_enforced()
    creator = "0xPQ" + "44" * 16
    mgr.set_available_balance(creator, Decimal("1000000"))
    cr = mgr._op_create_pool(_create_tx(creator))
    pool_id = cr.data["pool_id"]
    # Simulate active liquidity on the pool.
    mgr.pool_manager.get_pool(pool_id).state.liquidity = Decimal("500")
    rr = mgr._op_remove_pool(_remove_tx(creator, pool_id))
    assert not rr.success and "liquidity" in (rr.error or "")
    assert mgr.pool_manager.get_pool(pool_id) is not None


def test_remove_subsidized_pool_burns_stake_no_refund():
    mgr = _mgr_enforced()
    creator = "0xPQ" + "55" * 16
    mgr.set_available_balance(creator, Decimal("1000000"))
    cr = mgr._op_create_pool(_create_tx(creator, stake="5000", pool_type=PoolType.SUBSIDIZED))
    assert mgr.balance_deltas()[creator] == -Decimal("5000")  # burned on create
    rr = mgr._op_remove_pool(_remove_tx(creator, cr.data["pool_id"]))
    assert rr.success and rr.data["refunded_stake"] == "0"
    assert rr.data["burned_stake"] == "5000"
    # No refund → the burn stands (net delta stays -5000).
    assert mgr.balance_deltas()[creator] == -Decimal("5000")


def test_remove_pool_no_refund_when_not_enforced():
    """Observe mode: create didn't debit, so remove must not credit (no free QRDX)."""
    mgr = ExchangeStateManager()  # enforce_pool_stake defaults False
    creator = "0xPQ" + "66" * 16
    mgr.set_available_balance(creator, Decimal("1000000"))
    pool_id = mgr._op_create_pool(_create_tx(creator)).data["pool_id"]
    assert mgr.balance_deltas() == {}  # no debit in observe
    rr = mgr._op_remove_pool(_remove_tx(creator, pool_id))
    assert rr.success and rr.data["refunded_stake"] == "0"
    assert mgr.balance_deltas() == {}  # no credit either


def test_remove_nonexistent_pool_fails():
    mgr = _mgr_enforced()
    rr = mgr._op_remove_pool(_remove_tx("0xPQ" + "77" * 16, "deadbeef"))
    assert not rr.success and "no such pool" in (rr.error or "")
