"""
Trading controls Hyperliquid's protocol has (docs/HYPERLIQUID_PARITY.md): action expiry
(``expires_at``), isolated margin added and removed, the dead man's switch (SCHEDULE_CANCEL), and
builder codes (APPROVE_BUILDER_FEE, an order's ``builder``).
"""
from decimal import Decimal as D

import pytest

from qrdx.exchange import ExchangeOpType as Op
from qrdx.exchange import ExchangeStateManager, ExchangeTransaction
from qrdx.exchange.trading import BUILDER_FEE_MAX_PERP, CANCEL_TRIGGERS_PER_DAY

MID = "BTC-QRDX-PERP"
T0 = 1_700_000_000
ALICE, BOB, FRONT = "0xPQ" + "a" * 64, "0xPQ" + "b" * 64, "0xPQ" + "f" * 64
_nonces = {}


@pytest.fixture
def m():
    _nonces.clear()
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.begin_block(1, float(T0))
    ch = mgr.clearinghouse
    ch.create_market("BTC")
    ch.set_oracle_price(MID, D(30000), now=T0)
    for who in (ALICE, BOB):
        ch.deposit(who, D(1_000_000))
    yield mgr
    ExchangeStateManager.reset_instance()


def _tx(m, who, op, **params):
    n = _nonces.get(who, 0)
    t = ExchangeTransaction(op_type=op, sender=who, nonce=n, params=params, gas_limit=10 ** 6)
    r = m.process_transaction(t)
    if m._nonces.get(who, 0) != n:
        _nonces[who] = n + 1
    return r


def _at(m, t):
    m.begin_block(int(t) - T0 + 1, float(t))
    m.clearinghouse.set_oracle_price(MID, D(30000), now=t)


# ── expiry ──────────────────────────────────────────────────────────────────

def test_an_expired_action_is_not_includable_and_costs_nothing(m):
    r = _tx(m, ALICE, Op.PERP_SET_LEVERAGE, market_id=MID, leverage="5", expires_at=T0 - 1)
    assert not r.success and "expired" in r.error and r.gas_used == 0
    assert m.get_nonce(ALICE) == 0                                  # nonce untouched
    assert _tx(m, ALICE, Op.PERP_SET_LEVERAGE, market_id=MID, leverage="5",
               expires_at=T0 + 10).success
    r = _tx(m, ALICE, Op.PERP_SET_LEVERAGE, market_id=MID, leverage="5", expires_at="soon")
    assert not r.success and "block time" in r.error


# ── isolated margin ─────────────────────────────────────────────────────────

def _isolated_long(m):
    assert _tx(m, ALICE, Op.PERP_SET_LEVERAGE, market_id=MID, leverage="10",
               mode="isolated").success
    assert _tx(m, BOB, Op.PERP_ORDER, market_id=MID, side="sell", size="1",
               price="30000").success
    assert _tx(m, ALICE, Op.PERP_ORDER, market_id=MID, side="buy", size="1",
               price="30000").success
    return m.clearinghouse.accounts[ALICE].positions[MID]


def test_margin_moves_into_and_out_of_an_isolated_position(m):
    pos = _isolated_long(m)
    start = pos.isolated_margin
    r = _tx(m, ALICE, Op.PERP_ISOLATED_MARGIN, market_id=MID, amount="1000")
    assert r.success and pos.isolated_margin == start + 1000
    r = _tx(m, ALICE, Op.PERP_ISOLATED_MARGIN, market_id=MID, amount="-1000")
    assert r.success and pos.isolated_margin == start
    r = _tx(m, ALICE, Op.PERP_ISOLATED_MARGIN, market_id=MID, amount="-1")
    assert not r.success and "initial margin" in r.error            # below 10x: refused
    assert m.clearinghouse.identity_gap() == 0


def test_only_an_isolated_position_takes_margin(m):
    r = _tx(m, ALICE, Op.PERP_ISOLATED_MARGIN, market_id=MID, amount="10")
    assert not r.success and "no isolated position" in r.error


# ── the dead man's switch ───────────────────────────────────────────────────

def test_a_scheduled_cancel_pulls_every_order_when_it_comes(m):
    assert _tx(m, ALICE, Op.PERP_ORDER, market_id=MID, side="buy", size="1",
               price="29000").success
    r = _tx(m, ALICE, Op.SCHEDULE_CANCEL, time=T0 + 2)
    assert not r.success and "ahead" in r.error
    assert _tx(m, ALICE, Op.SCHEDULE_CANCEL, time=T0 + 10).success
    m.run_scheduled_cancels(D(T0 + 9))
    assert any(meta.owner == ALICE for meta in m.clearinghouse.markets[MID].orders.values())
    (event,) = m.run_scheduled_cancels(D(T0 + 10))
    assert event["owner"] == ALICE and event["cancelled"] == 1
    assert not any(meta.owner == ALICE for meta in m.clearinghouse.markets[MID].orders.values())
    assert m.run_scheduled_cancels(D(T0 + 20)) == []                # it fires once


def test_a_switch_can_be_cleared_and_fires_at_most_ten_times_a_day(m):
    assert _tx(m, ALICE, Op.SCHEDULE_CANCEL, time=T0 + 10).success
    assert _tx(m, ALICE, Op.SCHEDULE_CANCEL).success                # cleared
    assert m.run_scheduled_cancels(D(T0 + 60)) == []
    for i in range(CANCEL_TRIGGERS_PER_DAY):
        t = T0 + 100 * (i + 1)
        _at(m, t)
        assert _tx(m, ALICE, Op.SCHEDULE_CANCEL, time=t + 10).success
        assert len(m.run_scheduled_cancels(D(t + 10))) == 1
    _at(m, T0 + 5000)
    r = _tx(m, ALICE, Op.SCHEDULE_CANCEL, time=T0 + 5010)
    assert not r.success and "a day" in r.error


# ── builder codes ───────────────────────────────────────────────────────────

def test_a_builder_is_paid_its_rate_of_what_the_order_takes(m):
    r = _tx(m, ALICE, Op.PERP_ORDER, market_id=MID, side="buy", size="1", price="30000",
            builder={"b": FRONT, "f": "0.0005"})
    assert not r.success and "not approved" in r.error             # no approval yet
    assert _tx(m, ALICE, Op.APPROVE_BUILDER_FEE, builder=FRONT, max_fee_rate="0.0005").success
    assert _tx(m, BOB, Op.PERP_ORDER, market_id=MID, side="sell", size="2",
               price="30000").success
    r = _tx(m, ALICE, Op.PERP_ORDER, market_id=MID, side="buy", size="2", price="30000",
            builder={"b": FRONT, "f": "0.0005"})
    assert r.success and D(r.data["builder_fee"]["amount"]) == D(60000) * D("0.0005")
    assert m.clearinghouse.accounts[FRONT].collateral == D(30)
    assert m.clearinghouse.identity_gap() == 0


def test_builder_fees_are_capped_and_revocable(m):
    assert _tx(m, ALICE, Op.APPROVE_BUILDER_FEE, builder=FRONT, max_fee_rate="0.0005").success
    r = _tx(m, ALICE, Op.PERP_ORDER, market_id=MID, side="buy", size="1", price="30000",
            builder={"b": FRONT, "f": "0.0006"})
    assert not r.success                                            # above the approval
    r = _tx(m, ALICE, Op.PERP_ORDER, market_id=MID, side="buy", size="1", price="30000",
            builder={"b": FRONT, "f": str(BUILDER_FEE_MAX_PERP * 2)})
    assert not r.success and "at most" in r.error                   # above the perps cap
    assert _tx(m, ALICE, Op.APPROVE_BUILDER_FEE, builder=FRONT, max_fee_rate="0").success
    r = _tx(m, ALICE, Op.PERP_ORDER, market_id=MID, side="buy", size="1", price="30000",
            builder={"b": FRONT, "f": "0.0001"})
    assert not r.success and "not approved" in r.error


def test_an_agent_cannot_approve_a_builder(m):
    from qrdx.exchange.trading import AgentGrant

    bot = "0xPQ" + "c" * 64
    m.trading.agents[ALICE] = (AgentGrant(agent=bot, valid_until=D(0), name="bot"),)
    r = m.process_transaction(ExchangeTransaction(
        op_type=Op.APPROVE_BUILDER_FEE, sender=ALICE, signer=bot, nonce=0,
        params={"builder": FRONT, "max_fee_rate": "0.001"}, gas_limit=10 ** 6))
    assert not r.success
