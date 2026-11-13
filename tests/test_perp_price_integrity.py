"""
No price anyone names can create QRDX through perps.

History: closing a perp position settled PnL into the owner's real balance at the price the
closing transaction named, so a 3,000-margin long "closed" at 1,000,000,000 was credited
~999,973,000 QRDX; anyone could also set oracle prices. A first fix executed at the oracle
price, but the engine still had no counterparty — it minted on every win and burned on every
loss even at honest prices. Perps now trade on the clearinghouse order book
(docs/PERPS_CLEARINGHOUSE.md): a trade at any price moves value between its two accounts, and
no single key sets an oracle price — only the validators' stake-weighted votes (or, a token
perp, its token's spot market).
"""
from decimal import Decimal

import pytest

from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction

D = Decimal
BTC = "BTC-QRDX-PERP"
ATTACKER_A, ATTACKER_B, STRANGER = "0xPQaaa", "0xPQbbb", "0xPQzzz"


@pytest.fixture
def mgr(monkeypatch):
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.begin_block(1, 1_700_000_000.0)
    m.clearinghouse.create_market("BTC")
    yield m
    ExchangeStateManager.reset_instance()


def _tx(mgr, op, sender, params):
    return mgr.process_transaction(ExchangeTransaction(
        op_type=op, sender=sender, nonce=mgr._nonces.get(sender, 0), params=params,
        gas_limit=2_000_000, gas_price=10**9))


def _oracle(mgr, price):
    """The price the validators' votes set (their aggregation: tests/test_validator_oracle.py)."""
    mgr.clearinghouse.set_oracle_price(BTC, D(price), now=mgr._block_clock())


def _order(mgr, sender, side, size, price, **extra):
    return _tx(mgr, ExchangeOpType.PERP_ORDER, sender,
               {"market_id": BTC, "side": side, "size": str(size), "price": str(price), **extra})


def test_the_original_attack_is_refused(mgr):
    """OPEN_POSITION / CLOSE_POSITION at a self-chosen price — both ops are retired."""
    _oracle(mgr, 30000)
    opened = _tx(mgr, ExchangeOpType.OPEN_POSITION, ATTACKER_A,
                 {"market_id": BTC, "side": "long", "size": "1", "leverage": "10", "price": "30000"})
    closed = _tx(mgr, ExchangeOpType.CLOSE_POSITION, ATTACKER_A,
                 {"position_id": "p", "price": "1000000000"})
    assert not opened.success and not closed.success
    assert "retired" in opened.error and "retired" in closed.error


def test_two_colluding_accounts_cannot_create_value_at_any_price(mgr, no_risk_limits, no_staker_fees):
    """The strongest form: one person on both sides of a trade at an absurd price. The buyer
    must be able to carry the loss it is taking on — and if it can, the value just moves."""
    _oracle(mgr, 30000)
    for who in (ATTACKER_A, ATTACKER_B):
        assert _tx(mgr, ExchangeOpType.PERP_DEPOSIT, who, {"amount": "10000"}).success
    # Resting a sell at 1e9 reserves its margin at that price (1e8 at 10x): it once rested
    # against 10,000, the fill check alone valuing it at the gap to mark.
    unfunded = _order(mgr, ATTACKER_A, "sell", 1, 1_000_000_000)
    assert not unfunded.success and "margin" in unfunded.error
    assert _tx(mgr, ExchangeOpType.PERP_DEPOSIT, ATTACKER_A, {"amount": "100000000"}).success
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
    assert a_eq + b_eq + ch.vault_collateral == D("1200020000")


def test_no_single_key_sets_a_price(mgr, oracle_committee):
    """No operation sets a price but the validators' vote, and a vote counts only from the
    committee — and only aggregated (tests/test_validator_oracle.py, test_oracle_hardening.py)."""
    assert not hasattr(ExchangeOpType, "UPDATE_ORACLE")
    refused = _tx(mgr, ExchangeOpType.ORACLE_VOTE, STRANGER,
                  {"prices": {"BTC": "1000000000"}})
    assert not refused.success and "not in the oracle committee" in refused.error
    oracle_committee.load(mgr)
    assert mgr.process_transaction(oracle_committee.vote({"BTC": "30000"})).success
    assert mgr.clearinghouse.markets[BTC].mark_price == 0         # not until the block's tick
    mgr.apply_oracle_votes(mgr._block_clock())
    assert mgr.clearinghouse.markets[BTC].oracle_price == D("30000")


def test_no_price_means_no_trading(mgr):
    assert _tx(mgr, ExchangeOpType.PERP_DEPOSIT, ATTACKER_A, {"amount": "10000"}).success
    unpriced = _order(mgr, ATTACKER_A, "buy", 1, 30000)
    assert not unpriced.success and "no price" in unpriced.error
