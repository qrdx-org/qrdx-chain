"""
Perps on native tokens (docs/HYPERLIQUID_PARITY.md 13). No validator votes price them: the oracle
is the token's own spot market — the TWAP over SPOT_ORACLE_TWAP_SECONDS along pools governance
pinned when it listed the market — and the market is contained as a deployer's is (isolated
margin only, no shared backstop, no margin priced by it). Its open interest is capped by the
pools' depth, which rises only gradually, so a moment's liquidity raises no cap and moving the
price costs about what the open interest could gain.
"""
from decimal import Decimal as D

import pytest

from qrdx import constants
from qrdx.exchange import ExchangeOpType as Op
from qrdx.exchange import ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import block_processor as BP
from qrdx.exchange.clearinghouse import VAULT
from qrdx.exchange.governance import Governance, GovernanceError

T0 = 1_700_000_000
ALICE, BOB, CAROL = ("0xPQ" + c * 64 for c in "abc")
GOLD = "GOLD-USD-PERP"
WINDOW = constants.SPOT_ORACLE_TWAP_SECONDS


class Net:
    def __init__(self):
        self.mgr = ExchangeStateManager.get_instance()
        self.height, self.time = 1, T0
        self.nonces = {}

    def tx(self, who, op, **params):
        n = self.nonces.get(who, 0)
        self.nonces[who] = n + 1
        return ExchangeTransaction(op_type=op, sender=who, nonce=n, params=params,
                                   gas_limit=10 ** 7)

    def block(self, *txs, dt=10):
        self.height += 1
        self.time += dt
        ok, err, _ = BP.process_exchange_transactions(self.height, float(self.time), list(txs),
                                                      self.mgr)
        assert ok, err
        results = list(self.mgr._block_results)
        self.mgr.commit_block()
        return results

    def wait(self, seconds, dt=10):
        for _ in range(int(seconds) // dt):
            self.block(dt=dt)


@pytest.fixture
def net(monkeypatch, no_risk_limits):
    monkeypatch.setattr(constants, "PERP_COLLATERAL_TOKEN", "QRDX")
    monkeypatch.setattr(constants, "PERP_QUOTE", "USD")
    ExchangeStateManager.reset_instance()
    n = Net()
    mgr = n.mgr
    mgr.begin_block(1, float(T0))
    mgr.set_available_balance(ALICE, D(10_000_000))
    (r,) = n.block(n.tx(ALICE, Op.TOKEN_DEPLOY, name="Gold", symbol="GOLD",
                        total_supply="100000000"))
    n.gold = r.data["token_address"]
    (r,) = n.block(n.tx(ALICE, Op.TICKER_CLAIM, token_address=n.gold))
    assert r.success, r.error
    (r,) = n.block(n.tx(ALICE, Op.CREATE_POOL, token0=n.gold, token1="QRDX", fee_tier=3000,
                        pool_type="STANDARD", initial_price="2", stake_amount="10000"))
    assert r.success, r.error
    n.pool = r.data["pool_id"]
    (r,) = n.block(n.tx(ALICE, Op.ADD_LIQUIDITY, pool_id=n.pool, tick_lower=-60000,
                        tick_upper=60000, amount="1000000"))
    assert r.success, r.error
    for who in (ALICE, BOB, CAROL):
        mgr.clearinghouse.deposit(who, D(1_000_000))
    yield n
    ExchangeStateManager.reset_instance()


def _px(m):
    """The oracle, on the market's grid (sz_decimals 4: prices in 2 decimals)."""
    return str(m.oracle_price.quantize(D("0.01")))


def _list(n, **extra):
    return n.mgr._list_market({"base_token": "GOLD", "spot_token": n.gold,
                               "spot_pools": [n.pool], **extra})


# ── listing ─────────────────────────────────────────────────────────────────

def test_governance_lists_a_native_token_market_by_its_ticker_and_pools(net):
    gov = Governance()
    listing = gov._check_action("list_market", {"base_token": "GOLD", "spot_token": net.gold,
                                                "spot_pools": [net.pool]}, 1)
    assert listing["spot_pools"] == [net.pool]
    with pytest.raises(GovernanceError):
        gov._check_action("list_market", {"base_token": "GOLD", "spot_token": net.gold}, 1)
    mgr = net.mgr
    with pytest.raises(GovernanceError, match="ticker"):
        mgr._list_market({"base_token": "AU", "spot_token": net.gold, "spot_pools": [net.pool]})
    with pytest.raises(GovernanceError, match="lead"):
        _list(net, spot_pools=["nope"])
    with pytest.raises(GovernanceError, match="at most 10"):
        _list(net, max_leverage=20)
    assert _list(net)["market_id"] == GOLD
    m = mgr.clearinghouse.markets[GOLD]
    assert m.spot_token == net.gold and m.max_leverage == 10 and m.oracle_price == 0


# ── the oracle ──────────────────────────────────────────────────────────────

def test_the_oracle_waits_for_history_and_depth_then_follows_the_twap(net):
    _list(net)
    m = net.mgr.clearinghouse.markets[GOLD]
    net.wait(60)
    assert m.oracle_price == 0                           # no WINDOW of history yet
    net.wait(WINDOW + 600)
    assert abs(m.oracle_price - 2) < D("0.01")           # QRDX per GOLD
    assert m.spot_depth >= constants.SPOT_ORACLE_MIN_DEPTH
    votes = net.mgr.oracle_votes
    assert GOLD not in votes                              # no one votes it


def test_a_big_swap_barely_moves_the_oracle(net):
    _list(net)
    net.wait(WINDOW + 600)
    m = net.mgr.clearinghouse.markets[GOLD]
    before = m.oracle_price
    pool = net.mgr.pool_manager.get_pool(net.pool)
    (r,) = net.block(net.tx(CAROL, Op.SWAP, token_in="QRDX", token_out=net.gold,
                            amount_in="800000"))
    assert r.success, r.error
    spot = pool.twap_price(1, net.time + 1)
    assert spot > before * D("1.3")                       # the pool moved a lot
    net.block()
    assert m.oracle_price < before * D("1.02")            # the oracle, a sliver of it


def test_open_interest_is_capped_by_the_pools_depth(net, monkeypatch):
    _list(net)
    net.wait(WINDOW + 600)
    m = net.mgr.clearinghouse.markets[GOLD]
    cap = net.mgr.clearinghouse.oi_cap(m)
    assert cap == m.spot_depth
    monkeypatch.setattr(constants, "SPOT_OI_DEPTH_BPS", 1)          # a tiny cap: 0.01 %
    size = (m.spot_depth / 10_000 / m.mark_price * 2).quantize(D("0.0001"))
    r = net.block(net.tx(BOB, Op.PERP_ORDER, market_id=GOLD, side="sell", size=str(size),
                         price=_px(m)),
                  net.tx(ALICE, Op.PERP_ORDER, market_id=GOLD, side="buy", size=str(size),
                         price=_px(m)))
    assert r[0].success, r[0].error
    assert not r[1].success and "capped" in r[1].error, r[1].error


def test_liquidity_added_for_a_moment_raises_no_cap(net):
    _list(net)
    net.wait(WINDOW + 600)
    m = net.mgr.clearinghouse.markets[GOLD]
    before = m.spot_depth
    (r,) = net.block(net.tx(ALICE, Op.ADD_LIQUIDITY, pool_id=net.pool, tick_lower=-60000,
                            tick_upper=60000, amount="100000000"))         # 100× the depth
    assert r.success, r.error
    net.block()
    assert m.spot_depth < before * D("1.5")                # rises only gradually


# ── contained ───────────────────────────────────────────────────────────────

def test_it_is_contained_like_a_deployer_market(net):
    _list(net)
    net.wait(WINDOW + 600)
    ch = net.mgr.clearinghouse
    m = ch.markets[GOLD]
    price = _px(m)
    (r,) = net.block(net.tx(ALICE, Op.PERP_ORDER, market_id=GOLD, side="buy", size="1",
                            price=price, margin_mode="cross"))
    assert not r.success and "isolated margin only" in r.error
    r = net.block(net.tx(BOB, Op.PERP_ORDER, market_id=GOLD, side="sell", size="10",
                         price=price),
                  net.tx(ALICE, Op.PERP_ORDER, market_id=GOLD, side="buy", size="10",
                         price=price, leverage="5"))
    assert all(x.success for x in r), [x.error for x in r]
    assert ch.accounts[ALICE].isolated[GOLD] and ch.accounts[BOB].isolated[GOLD]
    assert ch.contained(m) and VAULT not in [o for o, a in ch.accounts.peek_items()
                                             if GOLD in a.positions]


def test_without_depth_its_oracle_goes_stale_and_it_only_reduces(net):
    _list(net)
    net.wait(WINDOW + 600)
    m = net.mgr.clearinghouse.markets[GOLD]
    pool = net.mgr.pool_manager.get_pool(net.pool)
    position = next(iter(pool.state.positions))
    (r,) = net.block(net.tx(ALICE, Op.REMOVE_LIQUIDITY, pool_id=net.pool,
                            position_id=position, liquidity=str(pool.state.liquidity)))
    assert r.success, r.error
    net.block()
    assert m.spot_depth == 0                              # down at once
    priced = m.oracle_time
    net.wait(constants.PERP_ORACLE_STALE_SECONDS + 20)
    assert m.oracle_time == priced                        # no reading to set it
    price = _px(m)
    (r,) = net.block(net.tx(BOB, Op.PERP_ORDER, market_id=GOLD, side="sell", size="1",
                            price=price))
    assert not r.success and "stale" in r.error


def test_qrdx_itself_lists_off_its_stablecoin_pool(monkeypatch):
    """QRDX may be priced off its own spot market too — against a stablecoin settlement asset
    (settling in QRDX, it has no price in itself)."""
    monkeypatch.setattr(constants, "PERP_QUOTE", "USD")
    ExchangeStateManager.reset_instance()
    n = Net()
    mgr = n.mgr
    mgr.begin_block(1, float(T0))
    (r,) = n.block(n.tx(ALICE, Op.TOKEN_DEPLOY, name="Dollar", symbol="QUSD",
                        total_supply="100000000"))
    usd = r.data["token_address"]
    monkeypatch.setattr(constants, "PERP_COLLATERAL_TOKEN", usd)
    (r,) = n.block(n.tx(ALICE, Op.CREATE_POOL, token0="QRDX", token1=usd, fee_tier=3000,
                        pool_type="STANDARD", initial_price="400", stake_amount="25"))
    assert r.success, r.error
    pool = r.data["pool_id"]
    with pytest.raises(GovernanceError, match="listed as QRDX"):
        mgr._list_market({"base_token": "ETH", "spot_token": "qrdx", "spot_pools": [pool]})
    out = mgr._list_market({"base_token": "QRDX", "spot_token": "qrdx", "spot_pools": [pool]})
    m = mgr.clearinghouse.markets[out["market_id"]]
    assert m.spot_token == "QRDX" and m.spot_pools == (pool,)
    monkeypatch.setattr(constants, "PERP_COLLATERAL_TOKEN", "QRDX")
    with pytest.raises(GovernanceError, match="no price in itself"):
        mgr._list_market({"base_token": "QRDX", "spot_token": "QRDX", "spot_pools": [pool]})
    ExchangeStateManager.reset_instance()
