"""
No price anyone names can create QRDX through perps.

History: closing a perp position settled PnL into the owner's real balance at the price the
closing transaction named, so a 3,000-margin long "closed" at 1,000,000,000 was credited
~999,973,000 QRDX; anyone could also set oracle prices. A first fix executed at the oracle
price, but the engine still had no counterparty — it minted on every win and burned on every
loss even at honest prices. Perps now trade on the clearinghouse order book
(docs/PERPS_CLEARINGHOUSE.md): a trade at any price moves value between its two accounts, and
only configured reporters may set oracle prices.
"""
from decimal import Decimal
from types import SimpleNamespace

import pytest

from qrdx import constants
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction

D = Decimal
BTC = "BTC-QRDX-PERP"
REPORTER, ATTACKER_A, ATTACKER_B, STRANGER = "0xPQrep", "0xPQaaa", "0xPQbbb", "0xPQzzz"


@pytest.fixture
def mgr(monkeypatch):
    monkeypatch.setattr(constants, "ORACLE_REPORTERS", (REPORTER,))
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.begin_block(1, 1_700_000_000.0)
    assert m._op_create_market(SimpleNamespace(params={"base_token": "BTC"})).success
    yield m
    ExchangeStateManager.reset_instance()


def _tx(mgr, op, sender, params):
    return mgr.process_transaction(ExchangeTransaction(
        op_type=op, sender=sender, nonce=mgr._nonces.get(sender, 0), params=params,
        gas_limit=2_000_000, gas_price=10**9))


def _oracle(mgr, sender, price):
    return _tx(mgr, ExchangeOpType.UPDATE_ORACLE, sender, {"pair": "BTC:QRDX", "price": str(price)})


def _order(mgr, sender, side, size, price, **extra):
    return _tx(mgr, ExchangeOpType.PERP_ORDER, sender,
               {"market_id": BTC, "side": side, "size": str(size), "price": str(price), **extra})


def test_the_original_attack_is_refused(mgr):
    """OPEN_POSITION / CLOSE_POSITION at a self-chosen price — both ops are retired."""
    assert _oracle(mgr, REPORTER, 30000).success
    opened = _tx(mgr, ExchangeOpType.OPEN_POSITION, ATTACKER_A,
                 {"market_id": BTC, "side": "long", "size": "1", "leverage": "10", "price": "30000"})
    closed = _tx(mgr, ExchangeOpType.CLOSE_POSITION, ATTACKER_A,
                 {"position_id": "p", "price": "1000000000"})
    assert not opened.success and not closed.success
    assert "retired" in opened.error and "retired" in closed.error


def test_two_colluding_accounts_cannot_create_value_at_any_price(mgr):
    """The strongest form: one person on both sides of a trade at an absurd price. The buyer
    must be able to carry the loss it is taking on — and if it can, the value just moves."""
    assert _oracle(mgr, REPORTER, 30000).success
    for who in (ATTACKER_A, ATTACKER_B):
        assert _tx(mgr, ExchangeOpType.PERP_DEPOSIT, who, {"amount": "10000"}).success
    assert _order(mgr, ATTACKER_A, "sell", 1, 1_000_000_000).success   # rests
    refused = _order(mgr, ATTACKER_B, "buy", 1, 1_000_000_000)
    assert not refused.success and "margin" in refused.error

    # Funded well enough to carry it, the trade goes through — and is a pure transfer.
    assert _tx(mgr, ExchangeOpType.PERP_DEPOSIT, ATTACKER_B, {"amount": "1100000000"}).success
    assert _order(mgr, ATTACKER_B, "buy", 1, 1_000_000_000).success
    ch = mgr.clearinghouse
    assert ch.identity_gap() == 0 and ch.net_size(BTC) == 0
    # Real QRDX moved only on the deposits: what left the attackers sits in the holder.
    assert sum(mgr.balance_deltas().values()) == 0
    # Equity at the oracle price: A is up ~1e9 exactly where B is down ~1e9.
    a_eq, b_eq = ch.cross_equity(ATTACKER_A), ch.cross_equity(ATTACKER_B)
    assert a_eq + b_eq + ch.vault_collateral == D("1100020000")


def test_only_configured_reporters_may_set_prices(mgr):
    refused = _oracle(mgr, STRANGER, 1_000_000_000)
    assert not refused.success and "authorized oracle reporter" in refused.error
    assert mgr.clearinghouse.markets[BTC].mark_price == 0
    assert _oracle(mgr, REPORTER, 30000).success
    assert mgr.clearinghouse.markets[BTC].mark_price == D("30000")


def test_no_reporters_configured_means_no_trading(mgr, monkeypatch):
    monkeypatch.setattr(constants, "ORACLE_REPORTERS", ())
    assert not _oracle(mgr, REPORTER, 30000).success
    assert _tx(mgr, ExchangeOpType.PERP_DEPOSIT, ATTACKER_A, {"amount": "10000"}).success
    unpriced = _order(mgr, ATTACKER_A, "buy", 1, 30000)
    assert not unpriced.success and "no price" in unpriced.error
