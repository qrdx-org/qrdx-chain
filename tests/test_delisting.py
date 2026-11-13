"""
Delisting a perp market (docs/CONSENSUS_ROADMAP.md 4): governance's ``delist_market`` settles
every position at one price — zero-sum — cancels the market's orders, triggers and TWAPs, ends
its liquidity vault's quoting and lockup, and the market refuses everything after.
"""
from decimal import Decimal

import pytest
from test_governance import HOLDER, Chain, _passed

from qrdx.exchange.clearinghouse import Clearinghouse, ClearinghouseError, market_maker_address
from qrdx.exchange.governance import EXECUTED, PASSED
from qrdx.exchange.transactions import ExchangeOpType

D = Decimal
BTC = "BTC-QRDX-PERP"
T0 = D(1_700_000_000)


def _market(ch):
    ch.create_market("BTC")
    ch.set_oracle_price(BTC, D(30000))
    ch.new_block(T0)
    for who in ("alice", "bob", "carol", "mm"):
        ch.deposit(who, D(1_000_000))
    ch.set_leverage("carol", BTC, D(5), True)                         # isolated
    ch.place_order("bob", BTC, "s1", "sell", D(2), D(30000), 0)
    ch.place_order("alice", BTC, "b1", "buy", D(1), D(30000), 0)
    ch.place_order("carol", BTC, "b2", "buy", D(1), D(30000), 0)
    ch.place_order("mm", BTC, "rest", "buy", D(1), D(29000), 0)      # a resting order
    ch.place_trigger("alice", BTC, "sl", "sell", "sl", D(25000), size=D(1))
    return ch


def test_every_position_settles_at_one_price_and_value_is_conserved():
    ch = _market(Clearinghouse())
    total = sum((a.collateral for a in ch.accounts.values()), D(0)) + sum(
        (p.isolated_margin for a in ch.accounts.values() for p in a.positions.values()), D(0))
    out = ch.delist(BTC, D(33000))
    assert D(out["settled_price"]) == 33000
    assert {c["owner"] for c in out["closed"]} == {"alice", "bob", "carol"}
    realized = {c["owner"]: D(c["realized"]) for c in out["closed"]}
    assert realized["alice"] == 3000 and realized["carol"] == 3000 and realized["bob"] == -6000
    m = ch.markets[BTC]
    assert m.open_interest == 0 and ch.net_size(BTC) == 0 and not len(m.orders)
    assert not m.triggers and ch.identity_gap() == 0
    after = sum((a.collateral for a in ch.accounts.values()), D(0)) + sum(
        (p.isolated_margin for a in ch.accounts.values() for p in a.positions.values()), D(0))
    assert after == total                                            # zero-sum
    assert all(BTC not in a.positions for a in ch.accounts.values())


def test_a_delisted_market_refuses_everything_and_its_tick_stops():
    ch = _market(Clearinghouse())
    ch.delist(BTC)                                                    # at the oracle
    assert ch.markets[BTC].settled_price == 30000
    with pytest.raises(ClearinghouseError, match="delisted"):
        ch.place_order("alice", BTC, "x", "buy", D(1), D(30000), 2)
    with pytest.raises(ClearinghouseError, match="delisted"):
        ch.place_trigger("alice", BTC, "t", "sell", "sl", D(25000), size=D(1))
    with pytest.raises(ClearinghouseError, match="already delisted"):
        ch.delist(BTC)
    before = ch.state_hash()
    ch.set_oracle_price(BTC, D(31000))
    ch.tick(T0 + 3600 * 8)                                            # no mark, no funding
    m = ch.markets[BTC]
    assert m.funding_time == 0 or m.mark_price == 30000
    assert ch.state_hash() != before                                  # (the oracle field moved)


def test_the_liquidity_vault_stops_and_its_lockup_ends():
    ch = Clearinghouse()
    ch.create_market("BTC")
    ch.set_oracle_price(BTC, D(30000))
    ch.new_block(T0)
    ch.deposit("lister", D(100_000))
    vault = market_maker_address(BTC)
    ch.create_user_vault("lister", vault, "liquidity", D(50_000), D(0), T0, managed=BTC,
                         lockup=D(30 * 86400))
    assert ch._holding(vault, "lister").unlock > T0
    ch.tick(T0 + 2)
    assert ch.markets[BTC].mm_time > 0                                # quoting
    ch.delist(BTC)
    assert not len(ch.markets[BTC].orders)
    assert ch._holding(vault, "lister").unlock <= T0 + 2
    ch.new_block(T0 + 10)
    ch.tick(T0 + 10)
    assert not len(ch.markets[BTC].orders)                            # quotes no more


def test_governance_delists_through_proposal_vote_timelock_and_execution():
    c = Chain()
    ch = c.m.clearinghouse
    _market(ch)
    pid = _passed(c, action="delist_market", market_id=BTC, price="31000")
    p = c.gov.proposals[pid]
    assert p.status == PASSED and p.params == {"market_id": BTC, "price": "31000"}
    run = c.tx(HOLDER, ExchangeOpType.GOV_EXECUTE, proposal_id=pid)
    c.block(run, height=p.timelock_ends)
    assert run.success, run.error
    assert run.result["status"] == EXECUTED and D(run.result["settled_price"]) == 31000
    assert ch.markets[BTC].settled_price == 31000


def test_delisting_a_missing_market_fails_and_can_be_retried_in_the_window():
    c = Chain()
    pid = _passed(c, action="delist_market", market_id="NOPE-QRDX-PERP")
    p = c.gov.proposals[pid]
    run = c.tx(HOLDER, ExchangeOpType.GOV_EXECUTE, proposal_id=pid)
    c.block(run, height=p.timelock_ends)
    assert not run.success and "not found" in run.error
    assert c.gov.proposals[pid].status == PASSED                     # rolled back: retryable


def test_a_bad_delisting_proposal_is_refused():
    c = Chain()
    ok, err = c.propose(action="delist_market", market_id="has space")
    assert not ok and "market id" in err
    ok, err = c.propose(action="delist_market", market_id=BTC, price="-1")
    assert not ok and "price" in err
