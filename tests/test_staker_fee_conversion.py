"""
The stakers' fee share in assets other than QRDX (docs/CONSENSUS_ROADMAP.md 6): it waits at the
fee holder and the tick sells it for QRDX — through the best route, never below its QRDX pool's
TWAP by more than STAKER_FEE_CONVERT_SLIPPAGE — and the QRDX it brings is staker income, shared
by the epoch transition like any.
"""
from decimal import Decimal

import pytest

from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange.state_manager import (
    STAKER_FEE_CONVERT_SECONDS,
    STAKER_FEE_TWAP_SECONDS,
)
from qrdx.validator.epoch_state import STAKER_FEE_HOLDER

D = Decimal
ALICE, BOB = "0xPQ" + "a" * 64, "0xPQ" + "b" * 64
TOK = "0x" + "11" * 20                    # sorts before QRDX: token0, priced in QRDX per TOK
T0 = 1_700_000_000
_nonces = {}


def _tx(m, who, op, params):
    n = _nonces.get(who, 0)
    _nonces[who] = n + 1
    r = m.process_transaction(ExchangeTransaction(
        op_type=op, sender=who, nonce=n, params=params, gas_limit=10_000_000))
    assert r.success, r.error
    return r


@pytest.fixture
def m():
    _nonces.clear()
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.enforce_spot_settlement = True
    mgr.begin_block(1, float(T0))
    for who in (ALICE, BOB):
        mgr.set_available_balance(who, D(10_000_000))
        mgr.set_available_token_balance(who, TOK, D(10_000_000))
    pid = _tx(mgr, ALICE, ExchangeOpType.CREATE_POOL, {
        "token0": TOK, "token1": "QRDX", "fee_tier": 3000, "pool_type": "STANDARD",
        "initial_price": "2", "stake_amount": "10000"}).data["pool_id"]
    for t in (TOK, "QRDX"):
        mgr.set_available_token_balance(mgr.pool_holder_address(pid), t, D(0))
    _tx(mgr, ALICE, ExchangeOpType.ADD_LIQUIDITY, {
        "pool_id": pid, "tick_lower": -60000, "tick_upper": 60000, "amount": "1000000"})
    yield mgr
    ExchangeStateManager.reset_instance()


def _later(m, seconds):
    now = T0 + seconds
    m.begin_block(1 + seconds, float(now))
    return D(now)


def test_the_share_is_sold_for_qrdx_at_the_twap_and_becomes_staker_income(m):
    m.fee_tokens[TOK] = (D(10), D(0))
    now = _later(m, STAKER_FEE_TWAP_SECONDS + 100)
    events = m.convert_staker_fees(now)
    assert len(events) == 1 and events[0]["token"] == TOK
    proceeds = D(events[0]["proceeds"])
    assert D(19) < proceeds < D(20)                       # ~2 QRDX a TOK, less the pool's fee
    assert m.block_staker_fees() == proceeds
    assert not len(m.fee_tokens)
    assert m.token_balance_deltas()[(STAKER_FEE_HOLDER, TOK)] == -10
    assert m.balance_deltas()[STAKER_FEE_HOLDER] == proceeds


def test_without_a_twap_it_waits(m):
    m.fee_tokens[TOK] = (D(10), D(0))
    now = _later(m, 30)                                   # the pool is 30 s old
    assert m.convert_staker_fees(now) == []
    assert m.fee_tokens.peek(TOK) == (D(10), now + STAKER_FEE_CONVERT_SECONDS)
    assert m.convert_staker_fees(now + 1) == []           # not due again yet


def test_a_price_pushed_below_the_twap_is_not_sold_into(m):
    """A sandwich: the pool is pushed down in the block the sale would run; the TWAP is not."""
    m.fee_tokens[TOK] = (D(10), D(0))
    now = _later(m, STAKER_FEE_TWAP_SECONDS + 100)
    _tx(m, BOB, ExchangeOpType.SWAP, {"token_in": TOK, "token_out": "QRDX",
                                      "amount_in": "200000"})
    assert m.convert_staker_fees(now) == []
    assert m.fee_tokens.peek(TOK)[0] == 10 and m.block_staker_fees() == 0


def test_perps_fees_in_a_stablecoin_reach_the_stakers_as_qrdx(m, monkeypatch):
    """The share of a perps fee settled in a token is withheld in it, moved to the fee holder at
    the block's end and sold for QRDX when due."""
    from qrdx import constants

    monkeypatch.setattr(constants, "PERP_COLLATERAL_TOKEN", TOK)
    ch = m.clearinghouse
    ch.create_market("BTC")
    ch.set_oracle_price("BTC-QRDX-PERP", D(30000))
    for who in ("0xPQs", "0xPQl"):
        ch.deposit(who, D(100_000))
    ch.place_order("0xPQs", "BTC-QRDX-PERP", "s", "sell", D(1), D(30000), 0)
    ch.place_order("0xPQl", "BTC-QRDX-PERP", "b", "buy", D(1), D(30000), 0)
    withheld = ch.staker_fees
    assert withheld > 0
    m.move_perps_staker_fees()
    assert m.fee_tokens.peek(TOK)[0] == withheld
    assert m.token_balance_deltas()[(STAKER_FEE_HOLDER, TOK)] == withheld
    now = _later(m, STAKER_FEE_TWAP_SECONDS + 100)
    (event,) = m.convert_staker_fees(now)
    assert D(event["sold"]) == withheld and m.block_staker_fees() == D(event["proceeds"]) > 0
