"""
Attacks on a token perp (docs/HYPERLIQUID_PARITY.md 13), block by block on the exchange's full
block path. Its price is its token's spot market's, and nothing else's: no key and no vote sets
it. What an attacker can reach, and what stops it:

* a crash of the token reaches only that market's isolated positions — not a trader's cross
  margin, not the shared backstop vault, not another market;
* a price pushed for a moment barely moves the oracle — the TWAP must be moved for its window;
* a lister cannot pin the market to a thin pool of its own: the deepest pool with a TWAP's
  history prices it, whoever listed it;
* votes and governance cannot price it.
"""
from decimal import Decimal as D

import pytest
from test_token_perps import WINDOW, Net

from qrdx import constants
from qrdx.exchange import ExchangeOpType as Op
from qrdx.exchange import ExchangeStateManager
from qrdx.exchange.clearinghouse import VAULT

T0 = 1_700_000_000
DEP, ALICE, BOB, CAROL, DAVE, EVE = ("0xPQ" + c * 64 for c in "deabcf")
BTC = "BTC-USD-PERP"


@pytest.fixture
def net(monkeypatch, no_risk_limits):
    monkeypatch.setattr(constants, "PERP_COLLATERAL_TOKEN", "QRDX")
    monkeypatch.setattr(constants, "PERP_QUOTE", "USD")
    ExchangeStateManager.reset_instance()
    n = Net()
    mgr, ch = n.mgr, n.mgr.clearinghouse
    mgr.begin_block(1, float(T0))
    mgr.set_available_balance(DEP, D(10_000_000))
    mgr.set_available_balance(EVE, D(10_000_000))
    (r,) = n.block(n.tx(DEP, Op.TOKEN_DEPLOY, name="Gold", symbol="GOLD",
                        total_supply="100000000"))
    n.gold = r.data["token_address"]
    n.pool_id = n.pool(n.gold, "QRDX", 2, 1_000_000, who=DEP)
    ch.create_market("BTC", "USD")
    for who in (DEP, ALICE, BOB, CAROL, DAVE):
        ch.deposit(who, D(200_000))
    n.wait(WINDOW + 60)
    yield n
    ExchangeStateManager.reset_instance()


def _open(n):
    """BTC at 30,000 (validator-priced); GOLD listed with a liquidity vault. Carol: a cross BTC
    position, and a small GOLD one (isolated, as every GOLD position is)."""
    ch = n.mgr.clearinghouse
    r = n.list(who=DEP, liquidity="20000")
    assert r.success, r.error
    n.wait(60)
    ch.set_oracle_price(BTC, D(30000), now=n.time)
    gold = n.market.id
    px = str(n.market.oracle_price.quantize(D("0.01")))
    r = n.block(n.tx(DAVE, Op.PERP_ORDER, market_id=BTC, side="sell", size="1", price="30000"),
                n.tx(CAROL, Op.PERP_ORDER, market_id=BTC, side="buy", size="1", price="30000"),
                n.tx(BOB, Op.PERP_ORDER, market_id=gold, side="sell", size="6000", price=px),
                n.tx(ALICE, Op.PERP_ORDER, market_id=gold, side="buy", size="5000", price=px,
                     leverage="10"),
                n.tx(CAROL, Op.PERP_ORDER, market_id=gold, side="buy", size="1000", price=px,
                     leverage="10"))
    assert all(x.success for x in r), [x.error for x in r]
    return gold


def test_a_crash_of_the_token_stays_in_its_perp(net):
    gold = _open(net)
    ch = net.mgr.clearinghouse
    carol_cross = ch.accounts[CAROL].collateral
    vault_before = ch.account(VAULT).collateral
    btc_carol, btc_dave = (ch.accounts[w].positions[BTC].size for w in (CAROL, DAVE))
    start = net.market.oracle_price
    # The token's creator dumps it: the pool falls ~30 % and stays there for the TWAP's window.
    (r,) = net.block(net.tx(DEP, Op.SWAP, token_in=net.gold, token_out="QRDX",
                            amount_in="140000"))
    assert r.success, r.error
    ch.set_oracle_price(BTC, D(30000), now=net.time)
    net.wait(WINDOW + 60)
    assert net.market.oracle_price < start * D("0.8")
    assert ALICE not in [o for o, a in ch.accounts.peek_items()
                         if gold in a.positions and a.positions[gold].size > 0]
    # Carol's cross margin never paid for GOLD; her GOLD margin was all GOLD could take.
    assert ch.accounts[CAROL].collateral >= carol_cross
    assert ch.accounts[CAROL].positions[BTC].size == btc_carol
    assert ch.accounts[DAVE].positions[BTC].size == btc_dave
    # The shared backstop took nothing over and lost nothing.
    vault = ch.accounts.peek(VAULT)
    assert gold not in vault.positions
    assert vault.collateral >= vault_before
    assert ch.identity_gap() == 0 and ch.net_size(gold) == 0 and ch.net_size(BTC) == 0


def test_a_price_pushed_for_a_moment_barely_moves_it(net):
    _open(net)
    m = net.market
    before = m.oracle_price
    pool = net.mgr.pool_manager.get_pool(net.pool_id)
    (r,) = net.block(net.tx(EVE, Op.SWAP, token_in="QRDX", token_out=net.gold,
                            amount_in="600000"))
    assert r.success, r.error
    assert pool.state.price > before * D("1.3")
    bought = D(r.data["amount_out"])
    (r,) = net.block(net.tx(EVE, Op.SWAP, token_in=net.gold, token_out="QRDX",
                            amount_in=str(bought)))                # and back
    assert r.success, r.error
    assert D(r.data["amount_out"]) < 600_000                       # it paid for the push
    net.wait(60)
    assert abs(m.oracle_price - before) < before * D("0.01")


def test_a_lister_cannot_pin_its_perp_to_a_thin_pool(net):
    """A squatter lists GOLD's perp while the only pool is a thin one, just over the depth
    floor; an honest pool five times deeper takes over once it has a TWAP's history. The thin
    pool then no longer matters: emptied, it leaves the perp priced."""
    r = net.list(who=EVE)
    assert r.success, r.error
    honest = net.pool(net.gold, "QRDX", 2, 5_000_000, fee_tier=500, who=DEP)
    net.wait(WINDOW + 60)
    assert net.market.spot_pools == (honest,)
    thin = net.mgr.pool_manager.get_pool(net.pool_id)
    (r,) = net.block(net.tx(DEP, Op.REMOVE_LIQUIDITY, pool_id=net.pool_id,
                            position_id=next(iter(thin.state.positions)),
                            liquidity=str(thin.state.liquidity)))
    assert r.success, r.error
    priced = net.market.oracle_time
    net.wait(60)
    assert net.market.oracle_time > priced
    assert abs(net.market.oracle_price - 2) < D("0.02")


def test_no_vote_and_no_proposal_prices_it(net, oracle_committee):
    _open(net)
    oracle_committee.load(net.mgr)
    m = net.market
    before = m.oracle_price
    for _ in range(5):
        (r,) = net.block(oracle_committee.vote({net.gold: "1", "BTC": "30000"}))
        assert r.success and r.data["ignored"] == [net.gold]
    assert abs(m.oracle_price - before) < before * D("0.01")
    ch = net.mgr.clearinghouse
    assert ch.markets[BTC].oracle_price == 30000                   # the votes price BTC alone
