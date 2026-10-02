"""
The exchange judges time by the BLOCK, never the node's wall clock.

Three consensus rules read ``time.time()``: the perp funding cadence, the perp oracle-
staleness guard on OPEN_POSITION, and the swap deadline. Nodes process a block at different
wall times, and a rebuild or catching-up sync replays hours of blocks in seconds, so each
rule could decide differently on different nodes, or on the same node forward vs rebuilt:

* a position opened >2 min after the last oracle update was rejected live but ACCEPTED by
  any fast replay (a margin debit on one side only);
* a swap carrying a deadline was accepted live but REJECTED by any later replay;
* funding settled every 8 wall-clock hours, so a fast replay skipped settlements forward
  application had made — different margins on every rebuilt node. (That engine is retired;
  the clearinghouse's funding is pinned to block time the same way.)

With the startup rebuild, every restart is such a replay. Each test below pins the wall
clock to a misleading value; only a decision taken from the block timestamp passes.
"""
import time
from decimal import Decimal

import pytest

from qrdx.exchange import ExchangeStateManager
from qrdx.exchange import block_processor as BP
from qrdx.exchange.perpetual import ORACLE_STALENESS_SECONDS

T = 1_700_000_000.0
MARKET = "BTC-QRDX-PERP"


@pytest.fixture
def mgr():
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.perp_engine.create_market("BTC", "QRDX")
    yield m
    ExchangeStateManager.reset_instance()


def _wall(monkeypatch, value):
    monkeypatch.setattr(time, "time", lambda: value)


def _price_at(mgr, height, ts):
    mgr.begin_block(height, ts)
    mgr.perp_engine.update_price(MARKET, Decimal("30000"))


def _stale(mgr):
    try:
        mgr.perp_engine._check_oracle_staleness(mgr.perp_engine.get_market(MARKET))
        return False
    except ValueError:
        return True


def test_oracle_staleness_is_judged_by_block_time(mgr, monkeypatch):
    _price_at(mgr, 1, T)

    # Block time says stale; the wall clock (a fast replay) says one second has passed.
    _wall(monkeypatch, T + 1)
    mgr.begin_block(2, T + ORACLE_STALENESS_SECONDS + 60)
    assert _stale(mgr)

    # Block time says fresh; the wall clock (a node catching up hours later) says stale.
    _wall(monkeypatch, T + 10 * 3600)
    mgr.begin_block(2, T + 30)
    assert not _stale(mgr)


def test_swap_deadline_is_judged_by_block_time(mgr, monkeypatch):
    """Only the deadline gate is under test; with no liquidity the swap fails afterwards."""
    def error_at(block_ts, wall):
        _wall(monkeypatch, wall)
        mgr.begin_block(5, block_ts)
        with pytest.raises(Exception) as exc:
            mgr.router.execute("0xAAA", "0xBBB", Decimal("1"), "0xPQsender", deadline=T + 10)
        return str(exc.value)

    # A replay long after the deadline must still accept a block from before it.
    assert "deadline" not in error_at(T + 5, wall=T + 10 * 3600)
    # A block after the deadline rejects it, whatever the wall clock says.
    assert "deadline expired" in error_at(T + 20, wall=T)


def _perps_with_positions(mgr):
    """A clearinghouse market with one long and one short open (funding needs positions)."""
    ch = mgr.clearinghouse
    ch.create_market("qBTC")
    ch.set_oracle_price("qBTC-QRDX-PERP", Decimal("30000"))
    for who in ("long", "short"):
        ch.deposit(who, Decimal("100000"))
    ch.place_order("short", "qBTC-QRDX-PERP", "s", "sell", Decimal("1"), Decimal("30000"), 0)
    ch.place_order("long", "qBTC-QRDX-PERP", "b", "buy", Decimal("1"), Decimal("30000"), 0)
    return ch


def _settlements(mgr, monkeypatch, wall, heights_and_times):
    """Run empty blocks through the block processor; count funding payments."""
    _wall(monkeypatch, wall)
    ch, paid = mgr.clearinghouse, 0
    for height, ts in heights_and_times:
        before = ch.accounts["long"].collateral
        ok, err, _ = BP.process_exchange_transactions(height, ts, [], mgr)
        assert ok, err
        mgr.commit_block()
        paid += ch.accounts["long"].collateral != before
    return paid


def test_funding_cadence_is_judged_by_block_time(mgr, monkeypatch):
    """Two interval boundaries apart in block time: both pay, even when the replay happens
    within one wall-clock second."""
    from qrdx import constants
    _perps_with_positions(mgr)
    iv = constants.PERP_FUNDING_INTERVAL_SECONDS
    start = (int(T) // iv) * iv + 1
    assert _settlements(mgr, monkeypatch, T, [(1, start), (2, start + iv), (3, start + 2 * iv)]) == 2


def test_funding_does_not_settle_early_by_block_time(mgr, monkeypatch):
    """And the converse: blocks close together in block time pay nothing, even when the wall
    clock claims a day has passed."""
    from qrdx import constants
    _perps_with_positions(mgr)
    iv = constants.PERP_FUNDING_INTERVAL_SECONDS
    start = (int(T) // iv) * iv + 1
    assert _settlements(mgr, monkeypatch, T + 24 * 3600,
                        [(1, start), (2, start + 60), (3, start + 120)]) == 0


def test_standalone_engines_keep_the_wall_clock():
    """Only the consensus manager rewires the clock; a bare engine (tools, tests) is unchanged."""
    from qrdx.exchange.perpetual import PerpEngine
    from qrdx.exchange.router import UnifiedRouter
    assert PerpEngine().clock is time.time
    assert UnifiedRouter().clock is time.time
