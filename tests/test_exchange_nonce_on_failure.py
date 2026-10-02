"""
An exchange operation consumes its nonce once it EXECUTES — whether it succeeds or fails.

The nonce used to advance only on success, so a failing operation could be re-submitted and
re-included at the same nonce indefinitely: one signed transaction, unlimited block space at
no cost. (Exchange fees are not yet charged at all — see docs/KNOWN_ISSUES.md — so this was
the only thing that could have bounded it.) Transactions rejected BEFORE execution —
malformed, wrong nonce, under-gassed — are not includable and must still consume nothing.
"""
from decimal import Decimal

import pytest

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange.mempool import ExchangeMempool

KEY = PQPrivateKey.generate()
SENDER = KEY.public_key.to_address()


@pytest.fixture
def mgr():
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.begin_block(1, 1_700_000_000.0)
    yield m
    ExchangeStateManager.reset_instance()


def _failing_close(nonce, gas_limit=1_000_000):
    """Closing a position that does not exist: well-formed and signed, fails in execution."""
    tx = ExchangeTransaction(op_type=ExchangeOpType.CLOSE_POSITION, sender=SENDER, nonce=nonce,
                             params={"position_id": "nope", "price": "1"},
                             gas_limit=gas_limit, gas_price=Decimal("1"))
    tx.public_key = KEY.public_key.to_bytes()
    tx.signature = KEY.sign(tx.signing_bytes()).to_bytes()
    return tx


def test_a_failed_execution_consumes_the_nonce(mgr):
    result = mgr.process_transaction(_failing_close(0))
    assert not result.success
    assert mgr.get_nonce(SENDER) == 1

    # The same signed transaction cannot be included again.
    again = mgr.process_transaction(_failing_close(0))
    assert not again.success and "nonce" in again.error.lower()


def test_the_mempool_refuses_the_replay_and_admits_the_next_nonce(mgr):
    mgr.process_transaction(_failing_close(0))
    pool = ExchangeMempool(nonce_provider=mgr.get_nonce)
    ok, why = pool.admit(_failing_close(0))
    assert not ok and "nonce too low" in why
    ok, why = pool.admit(_failing_close(1))
    assert ok, why


@pytest.mark.parametrize("nonce, gas_limit, why", [
    (5, 1_000_000, "nonce"),      # wrong nonce
    (0, 1, "gas"),                # under-gassed
], ids=["wrong-nonce", "under-gassed"])
def test_rejections_before_execution_consume_nothing(mgr, nonce, gas_limit, why):
    result = mgr.process_transaction(_failing_close(nonce, gas_limit=gas_limit))
    assert not result.success and why in result.error.lower()
    assert mgr.get_nonce(SENDER) == 0
