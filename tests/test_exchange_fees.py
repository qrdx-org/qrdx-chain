"""
Exchange fees (docs/KNOWN_ISSUES.md, "Exchange operations were free").

Gas is priced in wei (1 QRDX = 10^18 wei) at no less than EXCHANGE_MIN_GAS_PRICE_WEI. Every
executed operation — success or failure — pays gas_used × gas_price in QRDX, burned like EVM
gas; gas_limit × gas_price is reserved before the operation runs (so it cannot spend it) and
the rest refunded. An operation priced under the floor, or whose sender cannot cover the
reservation, is refused before it executes and consumes nothing — not even its nonce.
"""
from decimal import Decimal

import pytest

from exchange_fees import fee_of
from qrdx import constants
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import ExchangeMempool, ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import block_processor as BP

D = Decimal
GWEI = 10 ** 9
ALICE, BOB = "0xPQ" + "a" * 64, "0xPQ" + "b" * 64


@pytest.fixture
def mgr():
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    BP.apply_enforcement(m)
    m.begin_block(1, 1_700_000_000.0)
    yield m
    ExchangeStateManager.reset_instance()


def _tx(op, params, sender=ALICE, nonce=0, gas_price=GWEI, gas_limit=1_000_000):
    return ExchangeTransaction(op_type=op, sender=sender, nonce=nonce, params=params,
                               gas_limit=gas_limit, gas_price=gas_price)


def _deploy(m, nonce=0, **kw):
    return m.process_transaction(_tx(ExchangeOpType.TOKEN_DEPLOY, {
        "name": "T", "symbol": "TTT", "total_supply": "100"}, nonce=nonce, **kw))


def test_an_executed_operation_pays_its_gas_and_the_fee_is_burned(mgr):
    mgr.set_available_balance(ALICE, D(10))
    r = _deploy(mgr)
    assert r.success
    fee = fee_of(ExchangeOpType.TOKEN_DEPLOY)
    assert fee == D("0.00012") and r.fee == fee
    assert mgr.balance_deltas() == {ALICE: -fee}          # debited, credited to no one
    assert mgr.available_balance(ALICE) == D(10) - fee    # the reservation came back
    assert mgr.block_fees == fee


def test_a_failed_operation_pays_too_and_consumes_its_nonce(mgr):
    mgr.set_available_balance(ALICE, D(10))
    r = mgr.process_transaction(_tx(ExchangeOpType.TOKEN_TRANSFER, {
        "token_address": "0x" + "00" * 20, "to": BOB, "amount": "1"}))
    assert not r.success and "unknown token" in r.error
    assert r.fee == fee_of(ExchangeOpType.TOKEN_TRANSFER)
    assert mgr.balance_deltas() == {ALICE: -r.fee}
    assert mgr.get_nonce(ALICE) == 1


@pytest.mark.parametrize("price,why", [(GWEI - 1, "below the minimum"), (D("1000000000.5"), "whole number")])
def test_an_underpriced_operation_is_refused_before_it_runs(mgr, price, why):
    mgr.set_available_balance(ALICE, D(10))
    r = _deploy(mgr, gas_price=price)
    assert not r.success and why in r.error
    assert mgr.balance_deltas() == {} and mgr.get_nonce(ALICE) == 0 and not mgr.tokens.tokens


def test_a_sender_who_cannot_cover_the_gas_limit_is_refused(mgr):
    mgr.set_available_balance(ALICE, D("0.0009"))           # under 1,000,000 gas × 1 gwei
    r = _deploy(mgr)
    assert not r.success and "insufficient QRDX for gas" in r.error
    assert mgr.balance_deltas() == {} and mgr.get_nonce(ALICE) == 0
    r = _deploy(mgr, gas_limit=200_000)                     # 0.0002 reserved: affordable
    assert r.success


def test_an_operation_cannot_spend_its_own_gas(mgr):
    """The reservation is taken first: holding exactly the stake leaves nothing for gas."""
    from qrdx.exchange.amm import POOL_STAKE_REQUIREMENTS, PoolType
    stake = POOL_STAKE_REQUIREMENTS[PoolType.STANDARD]
    mgr.set_available_balance(ALICE, stake)
    r = mgr.process_transaction(_tx(ExchangeOpType.CREATE_POOL, {
        "token0": "A", "token1": "B", "fee_tier": 3000, "pool_type": "STANDARD",
        "initial_price": "1", "stake_amount": str(stake)}))
    assert not r.success and "insufficient balance for pool stake" in r.error
    assert mgr.balance_deltas() == {ALICE: -r.fee}           # only its gas


def test_without_the_gate_nothing_is_charged():
    ExchangeStateManager.reset_instance()
    try:
        m = ExchangeStateManager.get_instance()
        m.begin_block(1, 1_700_000_000.0)
        assert _deploy(m, gas_price=1).success                # unit-test default: no fees
        assert m.balance_deltas() == {}
    finally:
        ExchangeStateManager.reset_instance()


def test_the_price_is_whole_wei_and_hashes_the_same_however_it_is_written():
    a = _tx(ExchangeOpType.CANCEL_ORDER, {"order_id": "x"}, gas_price=GWEI)
    b = _tx(ExchangeOpType.CANCEL_ORDER, {"order_id": "x"}, gas_price=D("1000000000"))
    c = ExchangeTransaction.from_dict({**a.to_dict(), "gas_price": "1000000000"})
    assert a.gas_price == b.gas_price == c.gas_price == GWEI and isinstance(c.gas_price, int)
    assert a.tx_hash() == b.tx_hash() == c.tx_hash()
    assert ExchangeTransaction(op_type=ExchangeOpType.CANCEL_ORDER, sender=ALICE, nonce=0,
                               params={}).gas_price == constants.EXCHANGE_MIN_GAS_PRICE_WEI


def test_the_mempool_refuses_an_underpriced_transaction():
    key = PQPrivateKey.generate()
    addr = key.public_key.to_address()
    pool = ExchangeMempool(nonce_provider=lambda a: 0)
    for price, ok in ((GWEI - 1, False), (GWEI, True)):
        tx = ExchangeTransaction(op_type=ExchangeOpType.CANCEL_ORDER, sender=addr, nonce=0,
                                 params={"order_id": "x"}, gas_limit=100_000, gas_price=price)
        tx.public_key = key.public_key.to_bytes()
        tx.signature = key.sign(tx.signing_bytes()).to_bytes()
        admitted, err = pool.admit(tx)
        assert admitted == ok, err
        if not ok:
            assert "below the minimum" in err


def test_the_receipt_reports_the_fee(mgr):
    mgr.set_available_balance(ALICE, D(10))
    tx = _tx(ExchangeOpType.TOKEN_DEPLOY, {"name": "T", "symbol": "TTT", "total_supply": "1"})
    mgr.process_transaction(tx)
    mgr.commit_block()
    receipt = mgr.journal.receipt(tx.tx_hash())
    assert receipt["fee"] == str(fee_of(ExchangeOpType.TOKEN_DEPLOY))
    assert receipt["gas_price"] == GWEI
