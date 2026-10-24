"""
Liquidity for a new perp market (docs/TRADING_FEATURES.md §14).

CREATE_MARKET takes ``liquidity`` — at least the chain-spec PERP_MARKET_MIN_LIQUIDITY of the
creator's perps collateral — into the market's liquidity vault, which the protocol quotes on the
market's book in the tick: a post-only ladder around the mark, sized to the vault's equity and
leaning away from the inventory it holds, re-quoted every few seconds or when the mark moves,
pulled while the oracle is stale. No one signs for the vault; anyone may add to it at NAV; the
creator's shares are locked.
"""
import copy
import random
from decimal import Decimal as D

import pytest

from qrdx import constants
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction, undo
from qrdx.exchange import clearinghouse as CH
from qrdx.exchange.block_processor import _execute_block_boundary_duties

pytestmark = pytest.mark.usefixtures("open_listing")  # lists markets with CREATE_MARKET

MID = "BTC-QRDX-PERP"
T0 = 1_700_000_000


def _tx(m, who, op, params, signer=""):
    lane = f"{who}|{signer}" if signer else who
    return m.process_transaction(ExchangeTransaction(
        op_type=op, sender=who, signer=signer, nonce=m.get_nonce(lane), params=params,
        gas_limit=10 ** 6))


@pytest.fixture
def m(monkeypatch):
    monkeypatch.setattr(constants, "PERP_MARKET_MIN_LIQUIDITY", 10_000)
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.begin_block(1, float(T0))
    for who in ("lister", "taker", "lp"):
        mgr.clearinghouse.deposit(who, D(1_000_000))
    yield mgr
    ExchangeStateManager.reset_instance()


def _list(m, liquidity="20000"):
    r = _tx(m, "lister", ExchangeOpType.CREATE_MARKET, {"base_token": "BTC",
                                                         "liquidity": liquidity})
    assert r.success, r.error
    m.clearinghouse.set_oracle_price(MID, D(100), now=T0)
    return r.data["liquidity_vault"]


def _tick(m, t):
    m.begin_block(int(t), float(t))
    _execute_block_boundary_duties(m, int(t), float(t))
    return m._block_tick_events


def test_a_market_is_listed_with_liquidity_or_not_at_all(m):
    r = _tx(m, "lister", ExchangeOpType.CREATE_MARKET, {"base_token": "BTC"})
    assert not r.success and "at least 10000" in r.error
    vault = _list(m)
    ch = m.clearinghouse
    assert ch.accounts["lister"].collateral == 1_000_000 - 20_000
    assert ch.cross_equity(vault) == 20_000
    assert ch.user_vaults[vault].managed == MID


def test_the_protocol_quotes_a_ladder_around_the_mark(m):
    vault = _list(m)
    _tick(m, T0 + 1)
    book = m.clearinghouse.markets[MID].book
    bids, asks = book.get_bids(10), book.get_asks(10)
    assert len(bids) == len(asks) == CH.MARKET_MAKER_LEVELS
    assert bids[0][0] == D("99.9") and asks[0][0] == D("100.1")      # 0.1 % from the mark
    assert bids[-1][0] == D("99.5") and asks[-1][0] == D("100.5")
    per_level = D(20_000) * CH.MARKET_MAKER_DEPTH / CH.MARKET_MAKER_LEVELS
    assert bids[0][1] == (per_level / D("99.9")).quantize(D("1e-18"), rounding="ROUND_DOWN")
    assert all(meta.owner == vault for meta in m.clearinghouse.markets[MID].orders.values())


def test_a_taker_trades_with_it_and_its_quotes_lean_away_from_its_inventory(m):
    vault = _list(m)
    _tick(m, T0 + 1)
    r = _tx(m, "taker", ExchangeOpType.PERP_ORDER, {
        "market_id": MID, "side": "sell", "size": "150", "price": "99"})
    assert r.success and sum(D(f["amount"]) for f in r.data["fills"]) == 150
    assert m.clearinghouse.accounts[vault].positions[MID].size == 150   # the vault is long
    _tick(m, T0 + 1 + int(CH.MARKET_MAKER_REQUOTE_SECONDS))
    book = m.clearinghouse.markets[MID].book
    bid, ask = sum(a for _p, a in book.get_bids(10)), sum(a for _p, a in book.get_asks(10))
    assert bid < ask                                                    # leaning away
    assert m.clearinghouse.identity_gap() == 0


def test_quotes_are_pulled_while_the_oracle_is_stale(m):
    _list(m)
    _tick(m, T0 + 1)
    events = _tick(m, T0 + 2 + constants.PERP_ORACLE_STALE_SECONDS)
    quotes = [e for e in events if e["type"] == "market_quotes"]
    assert quotes and quotes[0]["levels"] == 0
    assert not m.clearinghouse.markets[MID].orders


def test_it_requotes_on_time_or_when_the_mark_moves(m):
    _list(m)
    _tick(m, T0 + 1)
    assert not [e for e in _tick(m, T0 + 2) if e["type"] == "market_quotes"]
    m.clearinghouse.set_oracle_price(MID, D(101), now=T0 + 3)
    assert [e for e in _tick(m, T0 + 3) if e["type"] == "market_quotes"]
    market = m.clearinghouse.markets[MID]
    assert market.mm_mark > 100                                         # quoted around the new mark
    assert market.book.best_bid == (market.mm_mark * D("0.999")).quantize(
        D("1e-18"), rounding="ROUND_FLOOR")


def test_no_one_signs_for_it_and_its_creators_shares_are_locked(m):
    vault = _list(m)
    r = _tx(m, vault, ExchangeOpType.PERP_ORDER, {
        "market_id": MID, "side": "buy", "size": "1", "price": "99"}, signer="lister")
    assert not r.success and "no one signs" in r.error
    r = _tx(m, "lister", ExchangeOpType.VAULT_WITHDRAW, {"vault": vault, "shares": "1"})
    assert not r.success and "locked" in r.error
    r = _tx(m, "lp", ExchangeOpType.VAULT_DEPOSIT, {"vault": vault, "amount": "5000"})
    assert r.success and D(r.data["shares"]) == 5000                   # anyone adds, at NAV


@pytest.mark.parametrize("seed", range(6))
def test_quoting_rolls_back_exactly_and_replays_identically(m, seed):
    _list(m)
    rng = random.Random(seed)

    def run(mgr, start, count):
        for k in range(count):
            t = start + k * rng.randint(1, 8)
            if rng.random() < 0.3:
                mgr.clearinghouse.set_oracle_price(MID, D(rng.randint(95, 105)), now=t)
            if rng.random() < 0.5:
                mgr.process_transaction(ExchangeTransaction(
                    op_type=ExchangeOpType.PERP_ORDER, sender="taker",
                    nonce=mgr.get_nonce("taker"), gas_limit=10 ** 6,
                    params={"market_id": MID, "side": rng.choice(["buy", "sell"]),
                            "size": str(rng.randint(1, 60)), "price": str(rng.randint(95, 105)),
                            "tif": "ioc"}))
            _execute_block_boundary_duties(mgr, int(t), float(t))

    run(m, T0 + 1, 20)
    twin_state = copy.deepcopy(m.clearinghouse)
    root = m.clearinghouse.commitment()
    with pytest.raises(KeyError):
        with undo.atomic():
            run(m, T0 + 500, 15)
            raise KeyError()
    assert m.clearinghouse.commitment() == root
    assert m.clearinghouse.canonical() == twin_state.canonical()
    m.clearinghouse.verify_commitment()
    assert m.clearinghouse.identity_gap() == 0
