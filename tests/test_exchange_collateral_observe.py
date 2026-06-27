"""
Phase E (increment 1) — exchange real-balance bridge + observe-only collateral check.

The exchange must eventually back perp margin with real account_state collateral.
This first increment adds the balance bridge (pre-load available balances) and an
OBSERVE-only check in open_position: it warns when margin exceeds the trader's
available balance but does NOT yet reject (the engine still opens the position).
Pins the bridge API + that the check observes without changing behaviour.
"""

import logging
from decimal import Decimal
from types import SimpleNamespace

from qrdx.exchange.state_manager import ExchangeStateManager


def _open_tx(sender, market_id, size="1", leverage="10", price="30000", side="long"):
    return SimpleNamespace(sender=sender, params={
        "market_id": market_id, "side": side, "size": size,
        "leverage": leverage, "price": price,
    })


def _mgr_with_market():
    mgr = ExchangeStateManager()
    market = mgr.perp_engine.create_market("BTC")  # BTC-QRDX-PERP
    return mgr, market.id


def test_balance_bridge_api():
    mgr = ExchangeStateManager()
    assert mgr.available_balance("0xPQaa") is None  # not loaded
    mgr.set_available_balance("0xPQaa", Decimal("1000"))
    assert mgr.available_balance("0xPQaa") == Decimal("1000")
    mgr.clear_available_balances()
    assert mgr.available_balance("0xPQaa") is None


def test_open_position_observes_insufficient_collateral(caplog):
    mgr, mid = _mgr_with_market()
    sender = "0xPQ" + "11" * 16
    # size 1 @ 30000, 10x → margin ~3000. Give only 100 available.
    mgr.set_available_balance(sender, Decimal("100"))
    with caplog.at_level(logging.WARNING):
        res = mgr._op_open_position(_open_tx(sender, mid))
    assert res.success, "observe-only: the position must still open (no rejection yet)"
    assert any("Phase E observe" in r.message for r in caplog.records), \
        "should warn that margin exceeds available collateral"


def test_open_position_no_warning_when_collateral_sufficient(caplog):
    mgr, mid = _mgr_with_market()
    sender = "0xPQ" + "22" * 16
    mgr.set_available_balance(sender, Decimal("1000000"))  # ample
    with caplog.at_level(logging.WARNING):
        res = mgr._op_open_position(_open_tx(sender, mid))
    assert res.success
    assert not any("Phase E observe" in r.message for r in caplog.records)


def test_no_check_when_balance_not_preloaded(caplog):
    """If balances aren't pre-loaded (None), the check is skipped — no false warns."""
    mgr, mid = _mgr_with_market()
    sender = "0xPQ" + "33" * 16
    with caplog.at_level(logging.WARNING):
        res = mgr._op_open_position(_open_tx(sender, mid))
    assert res.success
    assert not any("Phase E observe" in r.message for r in caplog.records)


def test_open_records_margin_as_balance_delta():
    """The locked margin is recorded as a negative real-balance delta for the block."""
    mgr, mid = _mgr_with_market()
    sender = "0xPQ" + "44" * 16
    mgr.set_available_balance(sender, Decimal("1000000"))
    res = mgr._op_open_position(_open_tx(sender, mid))
    margin = Decimal(res.data["margin"])
    deltas = mgr.balance_deltas()
    assert deltas[sender] == -margin
    # Available balance is reduced in step so further ops see the lock.
    assert mgr.available_balance(sender) == Decimal("1000000") - margin


def test_deltas_reset_per_block():
    mgr, mid = _mgr_with_market()
    sender = "0xPQ" + "55" * 16
    mgr.set_available_balance(sender, Decimal("1000000"))
    mgr._op_open_position(_open_tx(sender, mid))
    assert mgr.balance_deltas()  # non-empty
    mgr.begin_block(2, 0.0)
    assert mgr.balance_deltas() == {}  # reset


def test_enforce_rejects_insufficient_collateral():
    mgr, mid = _mgr_with_market()
    sender = "0xPQ" + "66" * 16
    mgr.enforce_collateral = True
    mgr.set_available_balance(sender, Decimal("100"))  # margin ~3000
    res = mgr._op_open_position(_open_tx(sender, mid))
    assert not res.success
    assert "insufficient collateral" in (res.error or "")
    # No position opened, no delta recorded.
    assert mgr.balance_deltas() == {}


def test_enforce_allows_sufficient_collateral():
    mgr, mid = _mgr_with_market()
    sender = "0xPQ" + "77" * 16
    mgr.enforce_collateral = True
    mgr.set_available_balance(sender, Decimal("1000000"))
    res = mgr._op_open_position(_open_tx(sender, mid))
    assert res.success
    assert mgr.balance_deltas()[sender] == -Decimal(res.data["margin"])


# --- Phase E: ADD_MARGIN must debit real collateral (was a free top-up) ------

def _add_margin_tx(sender, position_id, amount="500"):
    return SimpleNamespace(sender=sender, params={
        "position_id": position_id, "amount": amount,
    })


def test_add_margin_debits_trader_balance():
    mgr, mid = _mgr_with_market()
    sender = "0xPQ" + "a1" * 16
    mgr.set_available_balance(sender, Decimal("1000000"))
    open_res = mgr._op_open_position(_open_tx(sender, mid))
    pid = open_res.data["position_id"]
    margin0 = Decimal(open_res.data["margin"])
    avail_after_open = mgr.available_balance(sender)

    res = mgr._op_add_margin(_add_margin_tx(sender, pid, "500"))
    assert res.success
    assert Decimal(res.data["new_margin"]) == margin0 + Decimal("500")
    # The added margin is a real debit on top of the opening margin (conserves —
    # close credits the full locked margin back).
    assert mgr.balance_deltas()[sender] == -(margin0 + Decimal("500"))
    assert mgr.available_balance(sender) == avail_after_open - Decimal("500")


def test_add_margin_enforce_rejects_non_owner():
    mgr, mid = _mgr_with_market()
    owner = "0xPQ" + "a2" * 16
    other = "0xPQ" + "a3" * 16
    mgr.enforce_collateral = True
    mgr.set_available_balance(owner, Decimal("1000000"))
    mgr.set_available_balance(other, Decimal("1000000"))
    pid = mgr._op_open_position(_open_tx(owner, mid)).data["position_id"]
    res = mgr._op_add_margin(_add_margin_tx(other, pid, "500"))
    assert not res.success and "owner" in (res.error or "")


def test_add_margin_enforce_rejects_insufficient():
    mgr, mid = _mgr_with_market()
    sender = "0xPQ" + "a4" * 16
    mgr.enforce_collateral = True
    mgr.set_available_balance(sender, Decimal("1000000"))
    pid = mgr._op_open_position(_open_tx(sender, mid)).data["position_id"]
    res = mgr._op_add_margin(_add_margin_tx(sender, pid, "999999999"))
    assert not res.success and "insufficient" in (res.error or "")


# --- Phase E (c): PnL settlement + margin release on close ------------------

def _close_tx(sender, position_id, price="30000"):
    return SimpleNamespace(sender=sender, params={
        "position_id": position_id, "price": price,
    })


def _partial_close_tx(sender, position_id, close_size, price="30000"):
    return SimpleNamespace(sender=sender, params={
        "position_id": position_id, "close_size": close_size, "price": price,
    })


def _open_and_get(mgr, mid, sender, **kw):
    mgr.set_available_balance(sender, Decimal("1000000"))
    res = mgr._op_open_position(_open_tx(sender, mid, **kw))
    return res.data["position_id"], Decimal(res.data["margin"])


def test_close_at_breakeven_releases_full_margin():
    """Closing at entry price returns exactly the locked margin (net delta 0)."""
    mgr, mid = _mgr_with_market()
    sender = "0xPQ" + "88" * 16
    pid, margin = _open_and_get(mgr, mid, sender)  # entry 30000
    res = mgr._op_close_position(_close_tx(sender, pid, price="30000"))
    assert res.success
    assert Decimal(res.data["pnl"]) == Decimal("0")
    assert Decimal(res.data["settled"]) == margin
    # Net over open(-margin) + close(+margin) == 0.
    assert mgr.balance_deltas()[sender] == Decimal("0")


def test_close_at_profit_settles_margin_plus_pnl():
    mgr, mid = _mgr_with_market()
    sender = "0xPQ" + "99" * 16
    pid, margin = _open_and_get(mgr, mid, sender, size="1", price="30000")
    # long 1 @ 30000 closed at 31000 → pnl +1000.
    res = mgr._op_close_position(_close_tx(sender, pid, price="31000"))
    assert Decimal(res.data["pnl"]) == Decimal("1000")
    assert Decimal(res.data["settled"]) == margin + Decimal("1000")
    assert mgr.balance_deltas()[sender] == Decimal("1000")  # net = +pnl


def test_close_at_loss_within_margin():
    mgr, mid = _mgr_with_market()
    sender = "0xPQ" + "ab" * 16
    pid, margin = _open_and_get(mgr, mid, sender, size="1", price="30000")
    # long closed at 29000 → pnl -1000 (within margin).
    res = mgr._op_close_position(_close_tx(sender, pid, price="29000"))
    assert Decimal(res.data["pnl"]) == Decimal("-1000")
    assert Decimal(res.data["settled"]) == margin - Decimal("1000")
    assert mgr.balance_deltas()[sender] == Decimal("-1000")  # net = pnl


def test_close_at_loss_exceeding_margin_clamps_at_zero():
    """A loss deeper than the locked margin never debits beyond it (clamp at 0)."""
    mgr, mid = _mgr_with_market()
    sender = "0xPQ" + "cd" * 16
    pid, margin = _open_and_get(mgr, mid, sender, size="1", price="30000")
    # long closed at 26000 → pnl -4000 < margin(~3000) → settle clamped to 0.
    res = mgr._op_close_position(_close_tx(sender, pid, price="26000"))
    assert Decimal(res.data["settled"]) == Decimal("0")
    # Net = -margin (trader forfeits the full locked margin, no more).
    assert mgr.balance_deltas()[sender] == -margin


def test_partial_close_releases_proportional_margin_plus_pnl():
    mgr, mid = _mgr_with_market()
    sender = "0xPQ" + "ef" * 16
    pid, margin = _open_and_get(mgr, mid, sender, size="2", price="30000")
    # Close half (1 of 2) at 31000 → pnl +1000 on the closed half, half margin freed.
    res = mgr._op_partial_close(_partial_close_tx(sender, pid, close_size="1", price="31000"))
    assert Decimal(res.data["pnl"]) == Decimal("1000")
    expected = margin / 2 + Decimal("1000")
    assert Decimal(res.data["settled"]) == expected
    # Net = +(margin/2 freed) + 1000 - margin(open) = 1000 - margin/2.
    assert mgr.balance_deltas()[sender] == Decimal("1000") - margin / 2
