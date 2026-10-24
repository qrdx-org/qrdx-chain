"""
The free trading lane (docs/TOKENOMICS.md, chain-spec ``EXCHANGE_FREE_TRADING``). Trading pays no
gas, as on Hyperliquid, and spam is stopped by a per-account budget instead:

* a trading operation sent at gas price 0 pays nothing while its account has free actions —
  FREE_ACTIONS_INITIAL plus FREE_ACTIONS_PER_VOLUME per unit it has traded; past them one every
  FREE_ACTION_REFILL_SECONDS (cancels: up to twice the budget);
* only an account with a holding (QRDX or perps equity), at most FREE_ACTIONS_PER_BLOCK of an
  account's in a block;
* while blocks run full — the exchange base fee above FREE_TRADING_MAX_BASE_FEE_BPS of its floor —
  only cancels go free: everyone else pays until blocks clear;
* everything else pays gas, as before; and an account past its budget may always pay.
"""
import pickle
from decimal import Decimal as D

import pytest

from qrdx import constants
from qrdx import fee_market as F
from qrdx.exchange import ExchangeOpType as Op
from qrdx.exchange import ExchangeStateManager, ExchangeTransaction
from qrdx.exchange.mempool import ExchangeMempool

T0 = 1_700_000_000
BTC = "BTC-QRDX-PERP"
ALICE, BOB, EMPTY = "0xPQ" + "a" * 64, "0xPQ" + "b" * 64, "0xPQ" + "e" * 64
FLOOR = constants.EXCHANGE_MIN_GAS_PRICE_WEI


@pytest.fixture
def m(monkeypatch, no_risk_limits):
    monkeypatch.setattr(constants, "FREE_ACTIONS_INITIAL", 3)
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.enforce_fees = True
    mgr.begin_block(1, float(T0))
    mgr.clearinghouse.create_market("BTC")
    mgr.clearinghouse.set_oracle_price(BTC, D(30000), now=T0)
    for who in (ALICE, BOB):
        mgr.clearinghouse.deposit(who, D(1_000_000))
        mgr.set_available_balance(who, D(100))
    yield mgr
    ExchangeStateManager.reset_instance()


def _tx(m, who, op, gas=0, **params):
    return ExchangeTransaction(op_type=op, sender=who, nonce=m.get_nonce(who), params=params,
                               gas_limit=10 ** 6, gas_price=gas)


def _order(m, who=ALICE, gas=0, px="29000"):
    return m.process_transaction(_tx(m, who, Op.PERP_ORDER, gas, market_id=BTC, side="buy",
                                     size="0.01", price=px))


def _at(m, t):
    m.begin_block(int(t) - T0 + 1, float(t))


def test_a_trading_operation_at_price_zero_is_free(m):
    r = _order(m)
    assert r.success, r.error
    assert m.balance_deltas().get(ALICE, 0) == 0                         # no gas taken
    assert m.trading.action_budgets[ALICE][0] == 1
    with pytest.raises(ValueError, match="positive"):                   # not a trading op
        ExchangeTransaction(op_type=Op.PERP_DEPOSIT, sender=ALICE, nonce=0,
                            params={"amount": "1"}, gas_price=0).validate_basic()


def test_free_trading_needs_a_holding(m):
    m.set_available_balance(EMPTY, D(0))
    r = _order(m, who=EMPTY)
    assert not r.success and "holding" in r.error and m.get_nonce(EMPTY) == 0


def test_the_budget_runs_out_then_refills_one_at_a_time(m):
    for _ in range(3):
        assert _order(m).success
    r = _order(m)
    assert not r.success and "free actions" in r.error
    assert m.get_nonce(ALICE) == 3                                       # refused: nothing spent
    _at(m, T0 + constants.FREE_ACTION_REFILL_SECONDS)
    assert _order(m).success                                             # one refill
    r = _order(m)
    assert not r.success and "free actions" in r.error
    r = _order(m, gas=FLOOR)                                             # paying always works
    assert r.success and m.balance_deltas()[ALICE] < 0


def test_cancels_go_free_up_to_twice_the_budget(m):
    for _ in range(3):
        assert _order(m).success
    oids = [oid for oid, meta in m.clearinghouse.markets[BTC].orders.items()]
    for oid in oids:                                                      # 3 more, as cancels
        r = m.process_transaction(_tx(m, ALICE, Op.PERP_CANCEL, market_id=BTC, order_id=oid))
        assert r.success, r.error
    r = m.process_transaction(_tx(m, ALICE, Op.CANCEL_ALL))
    assert not r.success and "free actions" in r.error


def test_trading_earns_free_actions(m):
    assert m.free_action_budget(ALICE) == 3
    m.process_transaction(_tx(m, BOB, Op.PERP_ORDER, FLOOR, market_id=BTC, side="sell",
                              size="1", price="30000"))
    assert m.process_transaction(_tx(m, ALICE, Op.PERP_ORDER, FLOOR, market_id=BTC, side="buy",
                                     size="1", price="30000")).success
    assert m.free_action_budget(ALICE) == 3 + 30000 * constants.FREE_ACTIONS_PER_VOLUME


def test_at_most_so_many_free_actions_of_an_account_a_block(m, monkeypatch):
    monkeypatch.setattr(constants, "FREE_ACTIONS_INITIAL", 100)
    monkeypatch.setattr(constants, "FREE_ACTIONS_PER_BLOCK", 2)
    assert _order(m).success and _order(m).success
    r = _order(m)
    assert not r.success and "a block" in r.error
    _at(m, T0 + 1)
    assert _order(m).success


def test_a_batch_counts_each_of_its_actions(m):
    actions = [{"op": "PERP_ORDER", "params": {"market_id": BTC, "side": "buy", "size": "0.01",
                                               "price": "29000"}}] * 4
    r = m.process_transaction(_tx(m, ALICE, Op.BATCH, actions=actions))
    assert not r.success and "free actions" in r.error                  # 4 > 3


def test_when_blocks_run_full_only_cancels_go_free(m):
    assert _order(m).success
    oid = next(iter(m.clearinghouse.markets[BTC].orders))
    m.exchange_base_fee = FLOOR * 3                                      # above 2× the floor
    assert not m.free_lane_open()
    r = _order(m)
    assert not r.success and "running full" in r.error
    r = m.process_transaction(_tx(m, ALICE, Op.PERP_CANCEL, market_id=BTC, order_id=oid))
    assert r.success, r.error
    assert _order(m, gas=FLOOR * 3).success                              # or pay the base fee


def test_a_block_may_carry_free_lane_operations_at_price_zero():
    free = _tx(ExchangeStateManager(), ALICE, Op.PERP_CANCEL, market_id=BTC, order_id="x")
    paid_op_free = ExchangeTransaction(op_type=Op.PERP_DEPOSIT, sender=ALICE, nonce=0,
                                       params={"amount": "1"}, gas_price=FLOOR)
    paid_op_free.gas_price = 0
    block = {"base_fee": FLOOR, "exchange_base_fee": FLOOR}
    assert F.block_fee_error(block, [free.to_dict()], [], (FLOOR, FLOOR)) == ""
    assert "under the base fee" in F.block_fee_error(block, [paid_op_free.to_dict()], [],
                                                     (FLOOR, FLOOR))


def test_the_mempool_takes_free_operations_only_while_they_would_go_free(m):
    pool = ExchangeMempool(nonce_provider=lambda lane: m.get_nonce(lane),
                           signer_check=lambda tx: "")
    import qrdx.exchange.mempool as MP

    ok_verify = MP.verify_exchange_tx
    MP.verify_exchange_tx = lambda tx: (True, "")
    try:
        tx = _tx(m, ALICE, Op.PERP_ORDER, market_id=BTC, side="buy", size="0.01", price="29000")
        assert pool.admit(tx) == (True, "")
        assert pool.select_for_block(min_price=FLOOR) == [tx]               # free: goes in
        m.trading.action_budgets[ALICE] = (3, D(T0))
        tx2 = ExchangeTransaction(op_type=Op.PERP_ORDER, sender=ALICE, nonce=1,
                                  params=dict(tx.params), gas_limit=10 ** 6, gas_price=0)
        ok, err = pool.admit(tx2)
        assert not ok and "free actions" in err
    finally:
        MP.verify_exchange_tx = ok_verify


def test_budgets_are_committed(m):
    root = m.compute_state_root()
    assert _order(m).success
    assert m.compute_state_root() != root
    copy = pickle.loads(pickle.dumps(m.trading))
    assert copy.commitment() == m.trading.commitment()


def test_turned_off_every_operation_pays(m, monkeypatch):
    monkeypatch.setattr(constants, "EXCHANGE_FREE_TRADING", 0)
    with pytest.raises(ValueError, match="positive"):
        _tx(m, ALICE, Op.PERP_ORDER, market_id=BTC, side="buy", size="0.01",
            price="29000").validate_basic()
