"""
Phase E (c) — liquidation settlement.

On open the trader's margin is debited from real account_state; when a position
is liquidated at the block boundary the trader's *residual* equity (locked margin
minus the liquidation penalty, plus realized PnL, clamped at 0) must be credited
back. These tests pin (1) the ``margin_returned`` the perp engine computes and
(2) that ``_check_liquidations`` records it as a positive per-block balance delta
on the owner (the mirror of the open debit), flushed to account_state with the
block on the same path as margin / close settlement.
"""

from decimal import Decimal
from types import SimpleNamespace

from qrdx.exchange.state_manager import ExchangeStateManager
from qrdx.exchange.block_processor import _check_liquidations

ZERO = Decimal("0")


def _open(mgr, market_id, owner, size="1", leverage="10", price="30000", side="long"):
    mgr.set_available_balance(owner, Decimal("1000000"))
    res = mgr._op_open_position(SimpleNamespace(sender=owner, params={
        "market_id": market_id, "side": side, "size": size,
        "leverage": leverage, "price": price,
    }))
    assert res.success
    return Decimal(res.data["margin"])


def test_liquidation_returns_positive_residual_to_owner():
    """maint(0.05) > penalty(0.025): a liquidation leaves a positive residual that
    is credited back to the owner."""
    mgr = ExchangeStateManager()
    market = mgr.perp_engine.create_market(
        "ETH", initial_margin_rate=Decimal("0.10"), maintenance_margin_rate=Decimal("0.05"),
    )
    owner = "0xPQ" + "1a" * 16

    mgr.begin_block(1, 0.0)
    margin = _open(mgr, market.id, owner)  # margin 3000
    mgr.commit_block()

    # Next block: mark drops to 28000 → margin_ratio = (3000-2000)/28000 = 0.0357
    # < 0.05 maintenance → liquidatable.
    mgr.begin_block(2, 0.0)
    market.mark_price = Decimal("28000")
    _check_liquidations(mgr)

    # residual = (margin - penalty) + pnl = (3000 - 28000*0.025) + (28000-30000)
    #          = 2300 - 2000 = 300.
    assert mgr.balance_deltas().get(owner) == Decimal("300")
    assert margin == Decimal("3000")


def test_liquidation_default_rates_forfeits_full_margin():
    """Default rates: penalty(0.025) == maintenance(0.025), so a liquidation always
    consumes the whole maintenance buffer → residual 0 (no credit recorded)."""
    mgr = ExchangeStateManager()
    market = mgr.perp_engine.create_market("BTC")  # initial 0.05, maint 0.025
    owner = "0xPQ" + "2b" * 16

    mgr.begin_block(1, 0.0)
    _open(mgr, market.id, owner)  # margin 3000
    mgr.commit_block()

    mgr.begin_block(2, 0.0)
    market.mark_price = Decimal("27600")  # mr = 600/27600 = 0.0217 < 0.025 → liq
    _check_liquidations(mgr)

    # residual = (3000 - 690) + (27600-30000) = 2310 - 2400 = -90 → clamped to 0.
    # No positive delta recorded this block (trader forfeits the full margin).
    assert owner not in mgr.balance_deltas()


def test_margin_returned_field_clamped_non_negative():
    """The engine never reports a negative ``margin_returned``."""
    mgr = ExchangeStateManager()
    market = mgr.perp_engine.create_market("SOL")
    owner = "0xPQ" + "3c" * 16
    mgr.begin_block(1, 0.0)
    _open(mgr, market.id, owner)
    mgr.commit_block()

    market.mark_price = Decimal("20000")  # deeply underwater
    results = mgr.perp_engine.check_all_liquidations(market.id)
    assert len(results) == 1
    assert results[0].margin_returned >= ZERO


def test_healthy_position_not_liquidated_no_delta():
    mgr = ExchangeStateManager()
    market = mgr.perp_engine.create_market("AVAX")
    owner = "0xPQ" + "4d" * 16
    mgr.begin_block(1, 0.0)
    _open(mgr, market.id, owner)
    mgr.commit_block()

    mgr.begin_block(2, 0.0)
    market.mark_price = Decimal("30000")  # flat → healthy
    _check_liquidations(mgr)
    assert owner not in mgr.balance_deltas()
