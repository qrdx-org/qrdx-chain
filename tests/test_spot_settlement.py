"""
Phase E (d) inc5 — spot AMM settlement against the real token ledger.

A swap moves tokens trader↔POOL (the pool is a deterministic holder of its
reserves); add/remove-liquidity move LP↔pool. These tests pin that the recorded
token deltas CONSERVE supply (every debit has a matching credit) across a
deploy→add-liquidity→swap flow, and that the swap sufficiency check observes /
enforces correctly.
"""

from decimal import Decimal
from types import SimpleNamespace

from qrdx.exchange.state_manager import ExchangeStateManager
from qrdx.exchange.amm import FeeTier, PoolType
from integration_tests.pool_operator import price_to_sqrt_price_q96  # V3 sqrt-price helper

ZERO = Decimal("0")


def _tx(sender, params, nonce=0):
    return SimpleNamespace(sender=sender, nonce=nonce, params=params,
                           tx_hash=lambda: "00" * 16)


def _net_by_token(deltas):
    """Sum deltas per token across all holders — must be ~0 (conservation)."""
    by_token = {}
    for (holder, token), d in deltas.items():
        by_token[token] = by_token.get(token, ZERO) + d
    return by_token


def _make_pool(mgr, tokenA, tokenB):
    sqrt_price = price_to_sqrt_price_q96(Decimal("1"))  # 1:1 price
    mgr._op_create_pool(_tx("0xPQlp", {
        "token0": tokenA, "token1": tokenB, "fee_tier": int(FeeTier.MEDIUM),
        "pool_type": "STANDARD", "initial_sqrt_price": str(sqrt_price),
        "stake_amount": "10000",
    }))
    # pool id
    for pool in mgr.pool_manager._pools.values():
        if {pool.state.token0, pool.state.token1} == {tokenA, tokenB}:
            return pool
    return None


def test_add_liquidity_then_swap_conserves_tokens():
    mgr = ExchangeStateManager()
    mgr.begin_block(1, 0.0)
    A = "0xtokenA"
    B = "0xtokenB"
    pool = _make_pool(mgr, A, B)
    assert pool is not None

    lp = "0xPQlp"
    spacing = pool.state.fee_tier.tick_spacing
    center = (pool.state.tick // spacing) * spacing
    mgr._op_add_liquidity(_tx(lp, {
        "pool_id": pool.state.id,
        "tick_lower": center - 10 * spacing,
        "tick_upper": center + 10 * spacing,
        "amount": "100000",
    }))

    trader = "0xPQtrader"
    mgr._op_swap(_tx(trader, {
        "token_in": A, "token_out": B, "amount_in": "100",
    }))

    # Every token nets to zero across all holders (LP + pool + trader).
    net = _net_by_token(mgr.token_balance_deltas())
    for token, total in net.items():
        assert abs(total) < Decimal("0.00000001"), f"{token} not conserved: {total}"

    # The pool holder actually received reserves and paid out.
    holder = ExchangeStateManager.pool_holder_address(pool.state.id)
    d = mgr.token_balance_deltas()
    assert d[(holder, A)] > 0   # pool gained token_in from LP + trader
    assert d[(trader, A)] == Decimal("-100")  # trader paid 100 A
    assert d[(trader, B)] > 0   # trader received some B


def test_swap_observe_allows_insufficient(caplog):
    import logging
    mgr = ExchangeStateManager()
    mgr.begin_block(1, 0.0)
    A, B = "0xtokA", "0xtokB"
    pool = _make_pool(mgr, A, B)
    spacing = pool.state.fee_tier.tick_spacing
    center = (pool.state.tick // spacing) * spacing
    mgr._op_add_liquidity(_tx("0xPQlp", {
        "pool_id": pool.state.id, "tick_lower": center - 10 * spacing,
        "tick_upper": center + 10 * spacing, "amount": "100000"}))
    trader = "0xPQpoor"
    mgr.set_available_token_balance(trader, A, Decimal("10"))  # not enough for 100
    with caplog.at_level(logging.WARNING):
        res = mgr._op_swap(_tx(trader, {"token_in": A, "token_out": B, "amount_in": "100"}))
    assert res.success  # observe
    assert any("Phase E observe" in r.message for r in caplog.records)


def test_swap_enforce_rejects_insufficient():
    mgr = ExchangeStateManager()
    mgr.enforce_spot_settlement = True
    mgr.begin_block(1, 0.0)
    A, B = "0xtokA", "0xtokB"
    pool = _make_pool(mgr, A, B)
    spacing = pool.state.fee_tier.tick_spacing
    center = (pool.state.tick // spacing) * spacing
    mgr._op_add_liquidity(_tx("0xPQlp", {
        "pool_id": pool.state.id, "tick_lower": center - 10 * spacing,
        "tick_upper": center + 10 * spacing, "amount": "100000"}))
    trader = "0xPQpoor"
    mgr.set_available_token_balance(trader, A, Decimal("10"))
    # Clear deltas accumulated by add_liquidity so we isolate the swap.
    before = dict(mgr.token_balance_deltas())
    res = mgr._op_swap(_tx(trader, {"token_in": A, "token_out": B, "amount_in": "100"}))
    assert not res.success and "insufficient token_in" in res.error
    # The rejected swap recorded no new token deltas.
    assert mgr.token_balance_deltas() == before
