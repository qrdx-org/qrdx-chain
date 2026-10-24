"""
Deployer markets (docs/HYPERLIQUID_PARITY.md, Hyperliquid's HIP-3): a deployer bonds QRDX under a
namespace of its own, lists perp markets there (``dex:ASSET``), runs their oracle within a bound,
takes a share of the protocol's fees on them, and may settle them. The validators may freeze one
with two thirds of their stake — reduce-only, its oracle theirs — and governance may slash the
bond and settle the deployer's markets.
"""
import pickle
from decimal import Decimal as D

import pytest
from test_bridge import Key, _genesis

from qrdx import constants
from qrdx.exchange import ExchangeOpType as Op
from qrdx.exchange import ExchangeStateManager, ExchangeTransaction
from qrdx.exchange.clearinghouse import VAULT

T0 = 1_700_000_000
DEP, ALICE, BOB = "0xPQ" + "d" * 64, "0xPQ" + "a" * 64, "0xPQ" + "b" * 64
GOLD = "gold:XAU-USD-PERP"
_nonces = {}


@pytest.fixture
def m(monkeypatch):
    monkeypatch.setattr(constants, "PERP_QUOTE", "USD")
    _nonces.clear()
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.begin_block(1, float(T0))
    for who in (DEP, ALICE, BOB):
        mgr.clearinghouse.deposit(who, D(1_000_000))
        mgr.set_available_balance(who, D(1_000_000))
    yield mgr
    ExchangeStateManager.reset_instance()


def _tx(m, who, op, **params):
    n = _nonces.get(who, 0)
    t = ExchangeTransaction(op_type=op, sender=who, nonce=n, params=params, gas_limit=10 ** 7)
    r = m.process_transaction(t)
    if m._nonces.get(who, 0) != n:
        _nonces[who] = n + 1
    return r


def _at(m, t):
    m.begin_block(int(t) - T0 + 1, float(t))


def _list_gold(m, **extra):
    assert _tx(m, DEP, Op.DEPLOYER_BOND, dex="gold", amount="150000").success
    params = dict(base_token="gold:XAU", oracle_price="2000", liquidity="20000",
                  fee_share_bps=5000, **extra)
    return _tx(m, DEP, Op.CREATE_MARKET, **params)


# ── bonds and namespaces ────────────────────────────────────────────────────

def test_a_first_bond_names_a_namespace_that_stays_its_own(m):
    r = _tx(m, DEP, Op.DEPLOYER_BOND, amount="1000")
    assert not r.success and "namespace" in r.error
    assert _tx(m, DEP, Op.DEPLOYER_BOND, dex="gold", amount="1000").success
    assert m._balance_deltas[m.deployer_bond_address()] == 1000
    assert not _tx(m, ALICE, Op.DEPLOYER_BOND, dex="gold", amount="1000").success   # taken
    assert not _tx(m, DEP, Op.DEPLOYER_BOND, dex="silver", amount="1").success      # its own
    assert _tx(m, DEP, Op.DEPLOYER_BOND, amount="500").success
    assert m.trading.deployers[DEP].bond == 1500
    r = _tx(m, BOB, Op.DEPLOYER_BOND, dex="x", amount="2000000")
    assert not r.success and "insufficient" in r.error


def test_only_the_namespaces_bonded_deployer_lists_in_it(m):
    assert _tx(m, DEP, Op.DEPLOYER_BOND, dex="gold", amount="1000").success
    r = _tx(m, DEP, Op.CREATE_MARKET, base_token="gold:XAU", oracle_price="2000",
            liquidity="20000")
    assert not r.success and "bonded" in r.error                       # under the minimum
    r = _tx(m, ALICE, Op.CREATE_MARKET, base_token="gold:XAU", oracle_price="2000",
            liquidity="20000")
    assert not r.success and "namespace gold" in r.error
    assert _tx(m, DEP, Op.DEPLOYER_BOND, amount="149000").success
    r = _tx(m, DEP, Op.CREATE_MARKET, base_token="gold:XAU", oracle_price="2000",
            liquidity="20000", fee_share_bps=6000)
    assert not r.success and "fee_share_bps" in r.error                # above the cap
    r = _tx(m, DEP, Op.CREATE_MARKET, base_token="gold:XAU", oracle_price="2000",
            liquidity="20000", fee_share_bps=5000)
    assert r.success and r.data["market_id"] == GOLD
    market = m.clearinghouse.markets[GOLD]
    assert market.deployer == DEP and market.oracle_price == 2000
    assert market.deployer_fee_share == D("0.5")


# ── the deployer's oracle ───────────────────────────────────────────────────

def test_the_deployer_moves_its_oracle_within_the_bound(m):
    assert _list_gold(m).success
    r = _tx(m, DEP, Op.DEPLOYER_SET_ORACLE, market_id=GOLD, price="2100")
    assert not r.success and "once a block time" in r.error
    _at(m, T0 + 1)
    r = _tx(m, DEP, Op.DEPLOYER_SET_ORACLE, market_id=GOLD, price="2100")
    assert r.success and D(r.data["price"]) == 2020                     # 1 % in a second
    _at(m, T0 + 100)
    r = _tx(m, DEP, Op.DEPLOYER_SET_ORACLE, market_id=GOLD, price="5000")
    assert D(r.data["price"]) == D(2020) * D("1.1")                    # 10 seconds at most
    r = _tx(m, ALICE, Op.DEPLOYER_SET_ORACLE, market_id=GOLD, price="1")
    assert not r.success and "not a market this account deployed" in r.error


def test_validators_cannot_price_a_deployer_market_until_they_freeze_it(m):
    v1, v2, v3 = Key(), Key(), Key()
    m.load_oracle_committee(_genesis([(v1.addr, 100), (v2.addr, 100), (v3.addr, 100)]))
    assert _list_gold(m).success
    vote = v1.tx(Op.ORACLE_VOTE, {"prices": {"gold:XAU": "1"}, "freeze": ["BTC-USD-PERP"]})
    r = m.process_transaction(vote)
    assert r.success and r.data["ignored"] == ["gold:XAU", "freeze:BTC-USD-PERP"]
    assert GOLD not in m.oracle_votes                                   # skipped, not refused


# ── fees ───────────────────────────────────────────────────────────────────

def test_the_deployer_takes_its_share_of_the_fees_the_protocol_keeps(m, no_risk_limits):
    assert _list_gold(m).success
    dep_before = m.clearinghouse.accounts[DEP].collateral
    vault_before = m.clearinghouse.account(VAULT).collateral
    assert _tx(m, BOB, Op.PERP_ORDER, market_id=GOLD, side="sell", size="10",
               price="2000").success
    r = _tx(m, ALICE, Op.PERP_ORDER, market_id=GOLD, side="buy", size="10", price="2000")
    assert r.success and r.data["fills"]
    dep_gain = m.clearinghouse.accounts[DEP].collateral - dep_before
    vault_gain = m.clearinghouse.account(VAULT).collateral - vault_before
    assert dep_gain > 0 and abs(dep_gain - vault_gain) <= D("1e-18") * 4   # half each
    assert m.clearinghouse.identity_gap() == 0


# ── the validators' freeze ──────────────────────────────────────────────────

def test_two_thirds_of_the_stake_freeze_a_market_and_take_its_oracle(m):
    v1, v2, v3 = Key(), Key(), Key()
    m.load_oracle_committee(_genesis([(v1.addr, 100), (v2.addr, 100), (v3.addr, 100)]))
    assert _list_gold(m).success
    _at(m, T0 + 1)
    for who in (v1, v2):
        assert m.process_transaction(who.tx(Op.ORACLE_VOTE, {"freeze": [GOLD]})).success
    m.apply_oracle_votes(D(T0 + 1))                                    # 200 of 300: not > 2/3
    assert m.clearinghouse.markets[GOLD].frozen_until == 0
    assert m.process_transaction(v3.tx(Op.ORACLE_VOTE, {"freeze": [GOLD]})).success
    m.apply_oracle_votes(D(T0 + 1))
    market = m.clearinghouse.markets[GOLD]
    assert market.frozen_until > T0 + 1
    _at(m, T0 + 2)
    r = _tx(m, ALICE, Op.PERP_ORDER, market_id=GOLD, side="buy", size="1", price="2000")
    assert not r.success and "frozen" in r.error
    r = _tx(m, DEP, Op.DEPLOYER_SET_ORACLE, market_id=GOLD, price="2010")
    assert not r.success and "frozen" in r.error
    assert not _tx(m, DEP, Op.DEPLOYER_HALT, market_id=GOLD).success   # governance settles
    for who in (v1, v2, v3):                                            # the oracle is theirs
        r = m.process_transaction(who.tx(Op.ORACLE_VOTE, {"prices": {"gold:XAU": "1990"}}))
        assert r.success, r.error
    m.apply_oracle_votes(D(T0 + 2))
    assert market.oracle_price == 1990
    later = T0 + 2 + constants.PERP_ORACLE_VOTE_MAX_AGE * 3            # the votes lapse
    _at(m, later)
    m.apply_oracle_votes(D(later))
    assert len(m.trading.freeze_votes) == 0
    assert _tx(m, DEP, Op.DEPLOYER_SET_ORACLE, market_id=GOLD, price="1995").success


# ── unbonding, halting, slashing ────────────────────────────────────────────

def test_a_deployer_with_markets_keeps_the_minimum_and_unbonds_with_a_delay(m):
    assert _list_gold(m).success                                   # 150,000 bonded
    keep = constants.DEPLOYER_MIN_BOND
    r = _tx(m, DEP, Op.DEPLOYER_UNBOND, amount=str(150_000 - keep + 1))
    assert not r.success and "keeps" in r.error
    assert _tx(m, DEP, Op.DEPLOYER_UNBOND, amount="50000").success
    r = _tx(m, DEP, Op.DEPLOYER_UNBOND, claim=True)
    assert not r.success and "claimable" in r.error
    _at(m, T0 + constants.DEPLOYER_UNBOND_SECONDS)
    r = _tx(m, DEP, Op.DEPLOYER_UNBOND, claim=True)
    assert r.success and D(r.data["claimed"]) == 50000
    assert m._balance_deltas[DEP] == 50000
    assert m._balance_deltas[m.deployer_bond_address()] == -50000


def test_the_deployer_settles_its_market_at_its_oracle_price(m, no_risk_limits):
    assert _list_gold(m).success
    assert _tx(m, BOB, Op.PERP_ORDER, market_id=GOLD, side="sell", size="1",
               price="2000").success
    assert _tx(m, ALICE, Op.PERP_ORDER, market_id=GOLD, side="buy", size="1",
               price="2000").success
    r = _tx(m, DEP, Op.DEPLOYER_HALT, market_id=GOLD)
    assert r.success and D(r.data["settled_price"]) == 2000
    assert m.clearinghouse.markets[GOLD].open_interest == 0
    assert m.deployer_markets(DEP) == []
    assert _tx(m, DEP, Op.DEPLOYER_UNBOND, amount="150000").success    # no markets: all of it


def test_governance_slashes_the_bond_and_settles_the_markets(m):
    from qrdx.exchange.governance import Governance, GovernanceError

    assert _list_gold(m).success
    assert _tx(m, DEP, Op.DEPLOYER_UNBOND, amount="50000").success
    out = m._slash_deployer(DEP, 5000, halt=True)
    assert D(out["burned"]) == 75000 and out["settled"] == [GOLD]
    d = m.trading.deployers[DEP]
    assert d.bond == 50000 and d.unbonding == 25000
    assert m._balance_deltas[m.deployer_bond_address()] == 150000 - 75000
    gov = Governance()
    assert gov._check_action("slash_deployer", {"deployer": DEP, "bps": 10_000}, 1) == {
        "deployer": DEP, "bps": 10_000, "halt": False}
    with pytest.raises(GovernanceError):
        gov._check_action("slash_deployer", {"deployer": DEP, "bps": 0}, 1)


def test_deployer_state_is_committed_and_old_markets_load(m):
    root = m.compute_state_root()
    assert _tx(m, DEP, Op.DEPLOYER_BOND, dex="gold", amount="1000").success
    assert m.compute_state_root() != root
    copy = pickle.loads(pickle.dumps(m.trading))
    assert copy.commitment() == m.trading.commitment()
    old = m.clearinghouse.create_market("ETH", "USD")
    state = dict(old.__dict__)
    for f in ("deployer", "deployer_fee_share", "frozen_until"):
        state.pop(f, None)
    loaded = object.__new__(type(old))
    loaded.__setstate__(state)
    assert loaded.deployer == "" and loaded.frozen_until == 0
