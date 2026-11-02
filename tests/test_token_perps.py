"""
Token perps (docs/HYPERLIQUID_PARITY.md 13): a perp on an on-chain token, named by the token's
address, listed by anyone (CREATE_MARKET) and priced by nothing but the token's own spot market —
the TWAP over SPOT_ORACLE_TWAP_SECONDS along the deepest path of pools to the settlement asset. No
validator vote and no key sets its price. It is contained (isolated margin only, no shared
backstop, never a margin price). Its open interest is capped by the spot market's depth — what
moving the price SPOT_ORACLE_DEPTH_BAND_BPS takes, so liquidity concentrated at the price counts
as the capital it holds — and that depth rises only gradually.
"""
from decimal import Decimal as D

import pytest

from qrdx import constants
from qrdx.exchange import ExchangeOpType as Op
from qrdx.exchange import ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import block_processor as BP
from qrdx.exchange.amm import Q96
from qrdx.exchange.clearinghouse import VAULT
from qrdx.exchange.governance import Governance, GovernanceError

T0 = 1_700_000_000
ALICE, BOB, CAROL = ("0xPQ" + c * 64 for c in "abc")
WINDOW = constants.SPOT_ORACLE_TWAP_SECONDS


class Net:
    def __init__(self):
        self.mgr = ExchangeStateManager.get_instance()
        self.height, self.time = 1, T0
        self.nonces = {}

    def tx(self, who, op, **params):
        """(An oracle vote carries its own sequence, not the account's nonce.)"""
        lane = (who, op == Op.ORACLE_VOTE)
        n = self.nonces.get(lane, 1 if op == Op.ORACLE_VOTE else 0)
        self.nonces[lane] = n + 1
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

    def pool(self, token0, token1, price, liquidity, fee_tier=3000, who=ALICE):
        (r,) = self.block(self.tx(who, Op.CREATE_POOL, token0=token0, token1=token1,
                                  fee_tier=fee_tier, pool_type="STANDARD",
                                  initial_price=str(price), stake_amount="25"))
        assert r.success, r.error
        pid = r.data["pool_id"]
        (r,) = self.block(self.tx(who, Op.ADD_LIQUIDITY, pool_id=pid, tick_lower=-60000,
                                  tick_upper=60000, amount=str(liquidity)))
        assert r.success, r.error
        return pid

    def list(self, who=BOB, **params):
        (r,) = self.block(self.tx(who, Op.CREATE_MARKET, **{"token": self.gold, **params}))
        return r

    @property
    def market(self):
        return self.mgr.clearinghouse.markets[f"{self.gold}-USD-PERP"]


def _net(monkeypatch, *, history=True):
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
    n.pool_id = n.pool(n.gold, "QRDX", 2, 1_000_000)   # ~14,000 QRDX of depth within 2 %
    for who in (ALICE, BOB, CAROL):
        mgr.clearinghouse.deposit(who, D(1_000_000))
    if history:
        n.wait(WINDOW + 60)
    return n


@pytest.fixture
def net(monkeypatch, no_risk_limits):
    yield _net(monkeypatch)
    ExchangeStateManager.reset_instance()


@pytest.fixture
def listed(net):
    r = net.list()
    assert r.success, r.error
    net.wait(60)
    return net


def _px(m):
    """The oracle, on the market's grid (sz_decimals 4: prices in 2 decimals)."""
    return str(m.oracle_price.quantize(D("0.01")))


# ── listing ─────────────────────────────────────────────────────────────────

def test_anyone_lists_a_tokens_perp_by_its_address(net):
    r = net.list(who=CAROL)                       # not the token's creator, no ticker needed
    assert r.success, r.error
    m = net.market
    assert r.data["market_id"] == m.id == f"{net.gold}-USD-PERP"
    assert m.base == m.spot_token == net.gold
    assert m.max_leverage == constants.PERP_SPOT_MAX_LEVERAGE
    assert net.mgr.clearinghouse.contained(m)
    r = net.list(who=ALICE)
    assert not r.success and "already has its perp" in r.error


@pytest.mark.parametrize("token, error", [
    ("GOLD", "by address"),                       # a symbol is not an address
    ("0x" + "9" * 40, "no on-chain token"),
    ("QRDX", "no price in itself"),               # the settlement asset
])
def test_only_an_on_chain_token_by_its_address(net, token, error):
    (r,) = net.block(net.tx(BOB, Op.CREATE_MARKET, token=token))
    assert not r.success and error in r.error, r.error


def test_its_leverage_is_capped(net):
    r = net.list(max_leverage="20")
    assert not r.success and "at most" in r.error
    r = net.list(max_leverage="3", sz_decimals=2)
    assert r.success, r.error
    assert net.market.max_leverage == 3 and net.market.sz_decimals == 2


def test_it_lists_only_on_a_spot_market_with_history_and_depth(monkeypatch, no_risk_limits):
    n = _net(monkeypatch, history=False)
    r = n.list()
    assert not r.success and "no spot market" in r.error          # no TWAP history yet
    (r,) = n.block(n.tx(ALICE, Op.TOKEN_DEPLOY, name="Thin", symbol="THIN",
                        total_supply="100000000"))
    thin = r.data["token_address"]
    n.pool(thin, "QRDX", 2, 100_000)                              # ~1,400 of depth
    n.wait(WINDOW + 60)
    (r,) = n.block(n.tx(BOB, Op.CREATE_MARKET, token=thin))
    assert not r.success and "no spot market" in r.error
    assert n.list().success                                        # GOLD's pool is deep enough
    ExchangeStateManager.reset_instance()


def test_governance_lists_only_off_chain_assets_by_symbol(net):
    gov = Governance()
    assert gov._check_action("list_market", {"base_token": "AVAX"}, 1) == {"base_token": "AVAX"}
    for base in (net.gold, "0xabc", "QRDX", "qrdx", "dex:XAU", "A-B"):
        with pytest.raises(GovernanceError):
            gov._check_action("list_market", {"base_token": base}, 1)
    with pytest.raises(GovernanceError):                           # no spot variant any more:
        net.mgr._list_market({"base_token": "AVAX", "max_leverage": 99})   # (bounds)
    out = net.mgr._list_market({"base_token": "AVAX", "spot_token": net.gold})
    assert not net.mgr.clearinghouse.contained(net.mgr.clearinghouse.markets[out["market_id"]])


# ── the oracle ──────────────────────────────────────────────────────────────

def test_the_oracle_follows_the_twap_and_no_vote_prices_it(listed, oracle_committee):
    m = listed.market
    assert abs(m.oracle_price - 2) < D("0.01")                     # QRDX per GOLD
    assert m.spot_pools == (listed.pool_id,)
    assert m.spot_depth >= constants.SPOT_ORACLE_MIN_DEPTH
    oracle_committee.load(listed.mgr)
    price = m.oracle_price
    (r,) = listed.block(oracle_committee.vote({listed.gold: "100"}))
    assert r.success and r.data["ignored"] == [listed.gold]
    listed.block()
    assert m.oracle_price == price and m.id not in listed.mgr.oracle_votes


def test_a_big_swap_barely_moves_the_oracle(listed):
    m = listed.market
    before = m.oracle_price
    pool = listed.mgr.pool_manager.get_pool(listed.pool_id)
    (r,) = listed.block(listed.tx(CAROL, Op.SWAP, token_in="QRDX", token_out=listed.gold,
                                  amount_in="800000"))
    assert r.success, r.error
    assert pool.state.price > before * D("1.3")                    # the pool moved a lot
    listed.block()
    assert m.oracle_price < before * D("1.02")                     # the oracle, a sliver of it


def test_the_deepest_pool_prices_it_once_it_has_history(listed):
    """No one picks the pools: a perp listed while its token traded thinly follows the token to
    a deeper pool — but a new pool counts only once it has a TWAP's history."""
    deep = listed.pool(listed.gold, "QRDX", 2, 5_000_000, fee_tier=500)
    listed.wait(60)
    assert listed.market.spot_pools == (listed.pool_id,)            # no history yet
    listed.wait(WINDOW)
    assert listed.market.spot_pools == (deep,)
    assert abs(listed.market.oracle_price - 2) < D("0.01")


def test_liquidity_at_the_price_counts_as_the_capital_it_holds(listed):
    """A narrow range at the price has enormous active liquidity for little capital. Its depth
    is what moving the price 2 % through it takes — at most the capital it holds — not the
    virtual reserves of that liquidity, which would count it as if spread over every price."""
    mgr = listed.mgr
    pool = mgr.pool_manager.get_pool(listed.pool_id)
    band = D(constants.SPOT_ORACLE_DEPTH_BAND_BPS) / 10_000
    up0, down0 = pool.band_depth(band)
    virtual0 = pool.state.liquidity * pool.state.sqrt_price / Q96
    lower = pool.state.tick // 60 * 60
    (r,) = listed.block(listed.tx(ALICE, Op.ADD_LIQUIDITY, pool_id=listed.pool_id,
                                  tick_lower=lower, tick_upper=lower + 60,
                                  amount="50000000"))
    assert r.success, r.error
    capital = D(r.data["amount0"]) * 2 + D(r.data["amount1"])      # in QRDX
    up1, down1 = pool.band_depth(band)
    virtual1 = pool.state.liquidity * pool.state.sqrt_price / Q96
    assert virtual1 - virtual0 > 20 * capital                      # what the old measure saw
    assert up1 - up0 <= capital and (down1 - down0) * 2 <= capital * D("1.01")


def test_open_interest_is_capped_by_the_depth(listed, monkeypatch):
    m = listed.market
    cap = listed.mgr.clearinghouse.oi_cap(m)
    assert cap == m.spot_depth * constants.SPOT_OI_DEPTH_BPS / 10_000
    monkeypatch.setattr(constants, "SPOT_OI_DEPTH_BPS", 1)          # a tiny cap: 0.01 %
    size = (m.spot_depth / 10_000 / m.mark_price * 2).quantize(D("0.0001"))
    r = listed.block(listed.tx(BOB, Op.PERP_ORDER, market_id=m.id, side="sell", size=str(size),
                               price=_px(m)),
                     listed.tx(ALICE, Op.PERP_ORDER, market_id=m.id, side="buy", size=str(size),
                               price=_px(m)))
    assert r[0].success, r[0].error
    assert not r[1].success and "capped" in r[1].error, r[1].error


def test_liquidity_added_for_a_moment_raises_no_cap(listed):
    m = listed.market
    before = m.spot_depth
    (r,) = listed.block(listed.tx(ALICE, Op.ADD_LIQUIDITY, pool_id=listed.pool_id,
                                  tick_lower=-60000, tick_upper=60000, amount="100000000"))
    assert r.success, r.error
    listed.block()
    assert m.spot_depth < before * D("1.1")                        # rises only gradually


# ── contained ───────────────────────────────────────────────────────────────

def test_it_is_contained(listed):
    ch = listed.mgr.clearinghouse
    m = listed.market
    price = _px(m)
    (r,) = listed.block(listed.tx(ALICE, Op.PERP_ORDER, market_id=m.id, side="buy", size="1",
                                  price=price, margin_mode="cross"))
    assert not r.success and "isolated margin only" in r.error
    r = listed.block(listed.tx(BOB, Op.PERP_ORDER, market_id=m.id, side="sell", size="10",
                               price=price),
                     listed.tx(ALICE, Op.PERP_ORDER, market_id=m.id, side="buy", size="10",
                               price=price, leverage="5"))
    assert all(x.success for x in r), [x.error for x in r]
    assert ch.accounts[ALICE].isolated[m.id] and ch.accounts[BOB].isolated[m.id]
    assert VAULT not in [o for o, a in ch.accounts.peek_items() if m.id in a.positions]


def test_without_depth_its_oracle_goes_stale_and_it_only_reduces(listed):
    m = listed.market
    pool = listed.mgr.pool_manager.get_pool(listed.pool_id)
    position = next(iter(pool.state.positions))
    (r,) = listed.block(listed.tx(ALICE, Op.REMOVE_LIQUIDITY, pool_id=listed.pool_id,
                                  position_id=position, liquidity=str(pool.state.liquidity)))
    assert r.success, r.error
    listed.block()
    assert m.spot_depth == 0                                       # down at once
    priced = m.oracle_time
    listed.wait(constants.PERP_ORACLE_STALE_SECONDS + 20)
    assert m.oracle_time == priced                                 # no reading to set it
    (r,) = listed.block(listed.tx(BOB, Op.PERP_ORDER, market_id=m.id, side="sell", size="1",
                                  price=_px(m)))
    assert not r.success and "stale" in r.error


# ── other settlement assets ─────────────────────────────────────────────────

def test_through_qrdx_to_a_stablecoin_and_qrdx_itself(monkeypatch, no_risk_limits):
    """Settling in a stablecoin, a token with a pool only against QRDX is priced through QRDX's
    own pool — and QRDX itself may have its perp, priced off that pool."""
    monkeypatch.setattr(constants, "PERP_QUOTE", "USD")
    ExchangeStateManager.reset_instance()
    n = Net()
    mgr = n.mgr
    mgr.begin_block(1, float(T0))
    mgr.set_available_balance(ALICE, D(10_000_000))
    (r,) = n.block(n.tx(ALICE, Op.TOKEN_DEPLOY, name="Dollar", symbol="QUSD",
                        total_supply="1000000000"))
    usd = r.data["token_address"]
    (r,) = n.block(n.tx(ALICE, Op.TOKEN_DEPLOY, name="Gold", symbol="GOLD",
                        total_supply="100000000"))
    n.gold = r.data["token_address"]
    monkeypatch.setattr(constants, "PERP_COLLATERAL_TOKEN", usd)
    hub = n.pool(usd, "QRDX", "0.0025", 200_000)   # (priced as the sorted pair: QRDX per USD)
    n.pool(n.gold, "QRDX", 2, 1_000_000)
    n.wait(WINDOW + 60)
    price, depth, path = mgr.spot_reading(n.gold, D(n.time))
    assert len(path) == 2 and path[1] == hub
    assert abs(price - 800) < 2 and depth >= constants.SPOT_ORACLE_MIN_DEPTH
    (r,) = n.block(n.tx(BOB, Op.CREATE_MARKET, token=n.gold))
    assert r.success, r.error
    (r,) = n.block(n.tx(BOB, Op.CREATE_MARKET, token="qrdx"))
    assert r.success, r.error
    m = mgr.clearinghouse.markets[r.data["market_id"]]
    assert m.id == "QRDX-USD-PERP" and m.spot_token == "QRDX"
    (r,) = n.block(n.tx(BOB, Op.CREATE_MARKET, token=usd))
    assert not r.success and "no price in itself" in r.error
    ExchangeStateManager.reset_instance()
