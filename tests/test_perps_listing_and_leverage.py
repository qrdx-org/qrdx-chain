"""
Perps settings no outside actor chooses, and leverage chosen per trade (docs/HYPERLIQUID_PARITY.md
9–10).

* Each trade carries its own leverage and margin mode (``leverage`` / ``margin_mode`` on an
  order, a trigger or a TWAP): the market's setting for the account becomes it inside the
  operation, all or nothing. Every market's position keeps its own; a resting order keeps the
  leverage it was placed at, through a modify too; an open isolated position may change leverage,
  topped up from free cross margin when it goes down.
* A market's maximum leverage is bounded (PERP_MARKET_MAX_LEVERAGE): far beyond it, liquidations
  come too late and the backstop pays.
* A validator-priced market — its name, its leverage, its grid — is listed by governance
  (``list_market``), not by whoever lists it first.
* A deployer market is isolated-margin only, never backstopped by the shared vault, and never
  prices anyone's margin: its deployer's oracle reaches no one outside it.
"""
from decimal import Decimal as D

import pytest

from qrdx import constants
from qrdx.exchange import ExchangeOpType as Op
from qrdx.exchange import ExchangeStateManager, ExchangeTransaction
from qrdx.exchange.clearinghouse import VAULT, Clearinghouse, ClearinghouseError

T0 = 1_700_000_000
BTC, ETH = "BTC-QRDX-PERP", "ETH-QRDX-PERP"
ALICE, BOB, CAROL = "0xPQ" + "a" * 64, "0xPQ" + "b" * 64, "0xPQ" + "c" * 64
_nonces = {}


@pytest.fixture
def m(no_risk_limits):
    _nonces.clear()
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.begin_block(1, float(T0))
    ch = mgr.clearinghouse
    for base, price in (("BTC", 30000), ("ETH", 2000)):
        ch.create_market(base)
        ch.set_oracle_price(f"{base}-QRDX-PERP", D(price), now=T0)
    for who in (ALICE, BOB, CAROL):
        ch.deposit(who, D(100_000))
    yield mgr
    ExchangeStateManager.reset_instance()


def _tx(m, who, op, **params):
    n = _nonces.get(who, 0)
    t = ExchangeTransaction(op_type=op, sender=who, nonce=n, params=params, gas_limit=10 ** 7)
    r = m.process_transaction(t)
    if m._nonces.get(who, 0) != n:
        _nonces[who] = n + 1
    return r


def _lev(m, who, mid):
    a = m.clearinghouse.accounts[who]
    return a.leverage.get(mid), a.isolated.get(mid, False)


# ── leverage per trade ──────────────────────────────────────────────────────

def test_each_trade_sets_its_markets_leverage_and_each_market_keeps_its_own(m):
    assert _tx(m, BOB, Op.PERP_ORDER, market_id=BTC, side="sell", size="1", price="30000").success
    r = _tx(m, ALICE, Op.PERP_ORDER, market_id=BTC, side="buy", size="1", price="30000",
            leverage="20")
    assert r.success and r.data["fills"]
    assert _lev(m, ALICE, BTC) == (20, False)
    assert _tx(m, BOB, Op.PERP_ORDER, market_id=ETH, side="sell", size="1", price="2000").success
    r = _tx(m, ALICE, Op.PERP_ORDER, market_id=ETH, side="buy", size="1", price="2000",
            leverage="3", margin_mode="isolated")
    assert r.success
    assert _lev(m, ALICE, ETH) == (3, True) and _lev(m, ALICE, BTC) == (20, False)
    a = m.clearinghouse.accounts[ALICE]
    assert a.positions[ETH].isolated_margin == D(2000) / 3 or abs(
        a.positions[ETH].isolated_margin - D(2000) / 3) < D("1e-15")
    # BTC's requirement is at 20x, not ETH's 3x
    assert m.clearinghouse.cross_requirement(ALICE) == D(30000) / 20


def test_a_refused_order_leaves_the_leverage_as_it_was(m):
    assert _tx(m, ALICE, Op.PERP_SET_LEVERAGE, market_id=BTC, leverage="5").success
    r = _tx(m, ALICE, Op.PERP_ORDER, market_id=BTC, side="buy", size="1000", price="30000",
            leverage="2")                                          # far beyond its margin
    assert not r.success
    assert _lev(m, ALICE, BTC) == (5, False)
    r = _tx(m, ALICE, Op.PERP_ORDER, market_id=BTC, side="buy", size="1", price="30000",
            leverage="21")                                         # above the market's 20
    assert not r.success and "between 1 and 20" in r.error
    for bad in ("0", "abc", True):
        r = _tx(m, ALICE, Op.PERP_ORDER, market_id=BTC, side="buy", size="1", price="30000",
                leverage=bad)
        assert not r.success


def test_a_resting_order_keeps_its_own_leverage_through_a_modify(m):
    r = _tx(m, ALICE, Op.PERP_ORDER, market_id=BTC, side="buy", size="1", price="29000",
            leverage="2")
    oid = r.data["order_id"]
    assert _tx(m, ALICE, Op.PERP_SET_LEVERAGE, market_id=BTC, leverage="20").success
    market = m.clearinghouse.markets[BTC]
    assert market.orders[oid].leverage == 2
    r = _tx(m, ALICE, Op.PERP_MODIFY, market_id=BTC, order_id=oid, price="29500")
    assert r.success
    assert market.orders[r.data["order_id"]].leverage == 2          # not the account's 20
    assert m.clearinghouse.open_order_margin(ALICE) == D(29500) / 2


def test_an_open_isolated_positions_leverage_can_change_funded_from_cross(m):
    assert _tx(m, BOB, Op.PERP_ORDER, market_id=BTC, side="sell", size="1", price="30000").success
    assert _tx(m, ALICE, Op.PERP_ORDER, market_id=BTC, side="buy", size="1", price="30000",
               leverage="10", margin_mode="isolated").success
    a = m.clearinghouse.accounts[ALICE]
    before, cross = a.positions[BTC].isolated_margin, a.collateral
    r = _tx(m, ALICE, Op.PERP_SET_LEVERAGE, market_id=BTC, leverage="5", mode="isolated")
    assert r.success
    moved = D(r.data["margin_moved"])
    assert a.positions[BTC].isolated_margin == before + moved and a.collateral == cross - moved
    assert m.clearinghouse._iso_equity(a, BTC) >= D(30000) / 5
    assert _tx(m, ALICE, Op.PERP_SET_LEVERAGE, market_id=BTC, leverage="20",
               mode="isolated").success                           # higher: nothing moves
    assert a.positions[BTC].isolated_margin == before + moved
    r = _tx(m, ALICE, Op.PERP_SET_LEVERAGE, market_id=BTC, leverage="5", mode="cross")
    assert not r.success and "margin mode" in r.error              # not with a position


def test_lowering_an_isolated_positions_leverage_needs_the_free_margin(m):
    ch = m.clearinghouse
    assert _tx(m, BOB, Op.PERP_ORDER, market_id=BTC, side="sell", size="3", price="30000").success
    assert _tx(m, ALICE, Op.PERP_ORDER, market_id=BTC, side="buy", size="3", price="30000",
               leverage="20", margin_mode="isolated").success
    assert _tx(m, ALICE, Op.PERP_WITHDRAW, amount=str(ch.withdrawable(ALICE))).success
    r = _tx(m, ALICE, Op.PERP_SET_LEVERAGE, market_id=BTC, leverage="1", mode="isolated")
    assert not r.success and "free" in r.error
    assert _lev(m, ALICE, BTC) == (20, True)


# ── what no one but governance chooses ──────────────────────────────────────

def test_a_markets_maximum_leverage_is_bounded():
    ch = Clearinghouse()
    with pytest.raises(ClearinghouseError, match="at most"):
        ch.create_market("BTC", max_leverage=D(constants.PERP_MARKET_MAX_LEVERAGE + 1))
    for bad in ("NaN", "Infinity", "0.5"):
        with pytest.raises(Exception):
            ch.create_market("ETH", max_leverage=D(bad))
    assert ch.create_market("BTC", max_leverage=D(constants.PERP_MARKET_MAX_LEVERAGE))


def test_validator_priced_markets_are_listed_by_governance_only(m):
    r = _tx(m, ALICE, Op.CREATE_MARKET, base_token="SOL", liquidity="20000")
    assert not r.success and "governance" in r.error
    assert "SOL-QRDX-PERP" not in m.clearinghouse.markets
    from qrdx.exchange.governance import Governance, GovernanceError

    gov = Governance()
    listing = gov._check_action("list_market", {"base_token": "SOL", "max_leverage": 10,
                                                "sz_decimals": 2}, 1)
    assert listing == {"base_token": "SOL", "max_leverage": 10, "sz_decimals": 2}
    for bad in ({"base_token": "gold:XAU"}, {"base_token": "SOL", "max_leverage": "x"},
                {"base_token": "SOL", "sz_decimals": 9}):
        with pytest.raises(GovernanceError):
            gov._check_action("list_market", bad, 1)
    monkey_quote = constants.PERP_QUOTE
    out = m._list_market(listing)
    market = m.clearinghouse.markets[out["market_id"]]
    assert market.base == "SOL" and market.quote == monkey_quote
    assert market.max_leverage == 10 and market.sz_decimals == 2 and not market.deployer
    with pytest.raises(GovernanceError):
        m._list_market(listing)                                    # listed once
    with pytest.raises(GovernanceError):
        m._list_market({"base_token": "AVAX", "max_leverage": 1000})


def test_open_listing_is_a_dev_networks_setting(m, open_listing):
    assert _tx(m, ALICE, Op.CREATE_MARKET, base_token="SOL", liquidity="20000").success


def test_no_one_changes_another_accounts_leverage_or_orders(m):
    r = _tx(m, ALICE, Op.PERP_ORDER, market_id=BTC, side="buy", size="1", price="29000")
    oid = r.data["order_id"]
    assert _tx(m, BOB, Op.PERP_SET_LEVERAGE, market_id=BTC, leverage="20").success
    assert m.clearinghouse.accounts[ALICE].leverage.get(BTC) is None  # Bob changed his own
    r = _tx(m, BOB, Op.PERP_CANCEL, market_id=BTC, order_id=oid)
    assert not r.success
    r = _tx(m, BOB, Op.PERP_MODIFY, market_id=BTC, order_id=oid, price="1")
    assert not r.success
    assert oid in m.clearinghouse.markets[BTC].orders


def test_an_order_id_already_live_is_refused():
    ch = Clearinghouse()
    ch.create_market("BTC")
    ch.set_oracle_price(BTC, D(30000))
    ch.deposit("alice", D(100_000))
    ch.deposit("bob", D(100_000))
    ch.place_order("alice", BTC, "same", "buy", D(1), D(29000), 0)
    with pytest.raises(ClearinghouseError, match="duplicate"):
        ch.place_order("bob", BTC, "same", "buy", D(1), D(28000), 0)
    assert ch.markets[BTC].orders["same"].owner == "alice"


# ── deployer markets reach no one outside them ──────────────────────────────

def _deployer_market():
    ch = Clearinghouse()
    gold = ch.create_market("gold:XAU", deployer="dep", deployer_fee_share=D("0.5")).id
    ch.set_oracle_price(gold, D(30000))
    return ch, gold


def test_a_deployer_market_is_isolated_margin_only():
    ch, gold = _deployer_market()
    ch.deposit("alice", D(100_000))
    with pytest.raises(ClearinghouseError, match="isolated margin only"):
        ch.set_leverage("alice", gold, D(5), isolated=False)
    ch.place_order("alice", gold, "a1", "buy", D(1), D(29000), 0)   # cross by default: isolated
    assert ch.accounts["alice"].isolated[gold] is True


def test_the_shared_vault_never_backstops_a_deployer_market(no_risk_limits):
    """The case where a validator-priced market's liquidation goes to the backstop vault
    (tests/test_clearinghouse_liquidation.py): the only bid is below bankruptcy. In a deployer
    market the loss stays there — auto-deleveraging against its own counterparty."""
    ch, gold = _deployer_market()
    ch.deposit("alice", D(3500))
    ch.deposit("bob", D(10_000_000))
    ch.place_order("bob", gold, "s1", "sell", D(1), D(30000), 0)
    ch.place_order("alice", gold, "b1", "buy", D(1), D(30000), 0)
    ch.deposit("carol", D(1_000_000))
    ch.place_order("carol", gold, "c1", "buy", D(1), D(20000), 0)
    ch.set_oracle_price(gold, D(26900))
    events = ch.tick(D(T0))
    stages = [e["stage"] for e in events if e["type"] == "liquidation"]
    assert stages and "backstop" not in stages
    vault = ch.accounts.peek(VAULT)
    assert vault is None or gold not in vault.positions
    assert ch.identity_gap() == 0 and ch.net_size(gold) == 0


def test_a_deployer_market_never_prices_anyones_margin(monkeypatch):
    ch, gold = _deployer_market()
    from qrdx.exchange import clearinghouse as C

    monkeypatch.setattr(C, "portfolio_assets", lambda: {"0xtok": (gold, D("0.2"))})
    assert ch.asset_price("0xtok") == 0


# ── vault shares are priced at everything the vault holds ───────────────────

def test_a_vaults_isolated_margin_is_in_its_share_price(no_risk_limits, no_staker_fees):
    """A leader moving the vault's margin into an isolated position used to drop its share price
    (its cross equity) — anyone joining then took the other holders' value once the margin came
    back."""
    from qrdx.exchange.clearinghouse import USER_VAULT_LOCKUP_SECONDS, user_vault_address

    ch = Clearinghouse()
    ch.create_market("BTC")
    ch.set_oracle_price(BTC, D(30000))
    for who in ("leader", "bob", "carol"):
        ch.deposit(who, D(1_000_000))
    vault = user_vault_address("leader", "v")
    ch.create_user_vault("leader", vault, "v", D(100_000), D("0.1"), D(T0))
    ch.set_leverage(vault, BTC, D(5), isolated=True)
    ch.place_order("bob", BTC, "s1", "sell", D(1), D(30000), 0)
    ch.place_order(vault, BTC, "b1", "buy", D(1), D(30000), 0)
    margin = ch.accounts[vault].positions[BTC].isolated_margin
    assert margin > 0
    assert ch.total_equity(vault) - ch.cross_equity(vault) == margin
    nav = ch.total_equity(vault)
    ch.user_vault_deposit("carol", vault, D(10_000), D(T0))
    ch.place_order("bob", BTC, "b2", "buy", D(1), D(30000), 0)
    ch.place_order(vault, BTC, "s2", "sell", D(1), D(30000), 0)   # the margin comes back
    held = ch._holding(vault, "carol").shares
    paid, _fee = ch.user_vault_withdraw("carol", vault, held, D(T0) + USER_VAULT_LOCKUP_SECONDS)
    # Carol gets back what she put in, less her share of the vault's closing fee — not a cut
    # of the margin that was out of sight when she joined.
    assert paid <= D(10_000)
    assert paid > D(10_000) * (1 - D("0.001"))
    assert nav > 0 and ch.identity_gap() == 0


def test_an_isolated_order_may_cross_the_spread_but_not_open_liquidatable(m):
    """An isolated buy filling a little above mark used to be refused: it needed its full
    initial margin at mark after the fill, while its margin is sized at the fill price."""
    assert _tx(m, BOB, Op.PERP_ORDER, market_id=BTC, side="sell", size="1",
               price="30100").success                                   # 0.33 % above mark
    r = _tx(m, ALICE, Op.PERP_ORDER, market_id=BTC, side="buy", size="1", price="30100",
            leverage="10", margin_mode="isolated")
    assert r.success and r.data["fills"], r.error
    assert _tx(m, BOB, Op.PERP_ORDER, market_id=BTC, side="sell", size="1",
               price="33000").success                                   # 10 % above mark
    r = _tx(m, CAROL, Op.PERP_ORDER, market_id=BTC, side="buy", size="1", price="33000",
            leverage="20", margin_mode="isolated")
    assert not r.success and "insufficient margin" in r.error          # would open liquidatable
