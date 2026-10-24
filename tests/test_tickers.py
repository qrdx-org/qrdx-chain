"""
Unique tickers (docs/HYPERLIQUID_PARITY.md 11, Hyperliquid's HIP-1 deploy auction). Anyone may
deploy a token called USDC; only one token holds the ticker USDC. Its creator buys it in a
continuous Dutch auction, the price burned: the first sells at the opening price, each sale opens
the next at twice its price, falling linearly to the floor. The native asset's, the perps quote's
and the bridged assets' tickers are reserved; a bridged token takes its own when it is created.
"""
import pickle
from decimal import Decimal as D

import pytest
from test_bridge import ASSET, _attest, _deposit, _usdc
from test_bridge import setup as bridge_setup  # noqa: F401  (fixture)

from qrdx import constants
from qrdx.exchange import ExchangeOpType as Op
from qrdx.exchange import ExchangeStateManager, ExchangeTransaction

T0 = 1_700_000_000
ALICE, BOB = "0xPQ" + "a" * 64, "0xPQ" + "b" * 64
SPAN = constants.TICKER_AUCTION_SECONDS
_nonces = {}


@pytest.fixture
def m(monkeypatch):
    monkeypatch.setattr(constants, "BRIDGE_ASSETS", (ASSET,))
    _nonces.clear()
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.begin_block(1, float(T0))
    for who in (ALICE, BOB):
        mgr.set_available_balance(who, D(1_000_000))
    yield mgr
    ExchangeStateManager.reset_instance()


def _tx(m, who, op, **params):
    n = _nonces.get(who, 0)
    r = m.process_transaction(ExchangeTransaction(op_type=op, sender=who, nonce=n, params=params,
                                                  gas_limit=10 ** 6))
    if m._nonces.get(who, 0) != n:
        _nonces[who] = n + 1
    return r


def _token(m, who, symbol):
    r = _tx(m, who, Op.TOKEN_DEPLOY, name=symbol, symbol=symbol, total_supply="1000")
    assert r.success, r.error
    return r.data["token_address"]


def _at(m, t):
    m.begin_block(int(t) - T0 + 1, float(t))


def test_one_token_holds_a_ticker_and_its_creator_buys_it(m):
    real = _token(m, ALICE, "Gold")
    copy = _token(m, BOB, "GOLD")
    r = _tx(m, BOB, Op.TICKER_CLAIM, token_address=real)
    assert not r.success and "creator" in r.error
    r = _tx(m, ALICE, Op.TICKER_CLAIM, token_address=real)
    assert r.success and r.data["ticker"] == "GOLD"
    assert D(r.data["price"]) == constants.TICKER_OPENING_PRICE
    assert m._balance_deltas[ALICE] == -constants.TICKER_OPENING_PRICE      # burned
    r = _tx(m, BOB, Op.TICKER_CLAIM, token_address=copy)
    assert not r.success and "taken" in r.error
    assert m.ticker_of(real) == "GOLD" and m.ticker_of(copy) is None
    from qrdx.exchange import views

    assert views.ticker(m, "gold")["token_address"] == real
    assert {t["token_address"]: t["ticker"] for t in views.tokens(m)}[copy] is None


def test_reserved_and_malformed_tickers_are_not_for_sale(m):
    for symbol in ("QRDX", "usdc", constants.PERP_QUOTE):
        r = _tx(m, ALICE, Op.TICKER_CLAIM, token_address=_token(m, ALICE, symbol))
        assert not r.success and "reserved" in r.error
    r = _tx(m, ALICE, Op.TICKER_CLAIM, token_address=_token(m, ALICE, "a.b"))
    assert not r.success and "letters and digits" in r.error


def test_the_price_doubles_after_a_sale_and_falls_to_the_floor(m):
    floor = D(constants.TICKER_MIN_PRICE)
    assert m.ticker_price(D(T0)) == constants.TICKER_OPENING_PRICE
    assert _tx(m, ALICE, Op.TICKER_CLAIM, token_address=_token(m, ALICE, "ONE")).success
    p0 = D(constants.TICKER_OPENING_PRICE)
    assert m.ticker_price(D(T0)) == 2 * p0
    assert m.ticker_price(D(T0) + D(SPAN) / 2) == floor + (2 * p0 - floor) / 2
    assert m.ticker_price(D(T0) + SPAN) == floor and m.ticker_price(D(T0) + 10 * SPAN) == floor
    _at(m, T0 + SPAN)
    second = _token(m, BOB, "TWO")
    r = _tx(m, BOB, Op.TICKER_CLAIM, token_address=second, max_price=str(floor - 1))
    assert not r.success and "max_price" in r.error
    r = _tx(m, BOB, Op.TICKER_CLAIM, token_address=second, max_price=str(floor))
    assert r.success and D(r.data["price"]) == floor
    assert m.ticker_price(D(T0 + SPAN)) == 2 * floor                  # the next opens at 2×
    r = _tx(m, BOB, Op.TICKER_CLAIM, token_address=second)
    assert not r.success and "taken" in r.error                      # once


def test_a_ticker_needs_the_qrdx_to_pay_for_it(m):
    m.set_available_balance(BOB, D(10))
    r = _tx(m, BOB, Op.TICKER_CLAIM, token_address=_token(m, BOB, "POOR"))
    assert not r.success and "costs" in r.error
    assert len(m.trading.tickers) == 0


def test_tickers_are_committed_and_survive_a_checkpoint(m):
    root = m.compute_state_root()
    assert _tx(m, ALICE, Op.TICKER_CLAIM, token_address=_token(m, ALICE, "ROOT")).success
    assert m.compute_state_root() != root
    copy = pickle.loads(pickle.dumps(m.trading))
    assert copy.commitment() == m.trading.commitment()
    state = dict(m.trading.__dict__)
    state.pop("tickers")
    state.pop("ticker_auction")
    old = object.__new__(type(m.trading))
    old.__setstate__(state)
    assert len(old.tickers) == 0 and len(old.ticker_auction) == 0


def test_a_bridged_token_takes_its_reserved_ticker(bridge_setup):
    mgr, v1, _v2, v3, user = bridge_setup
    for who in (v1, v3):
        r = _attest(mgr, who, _deposit(user.addr))
        assert r.success, r.error
    assert mgr.trading.tickers["USDC"] == _usdc()
    assert mgr.ticker_of(_usdc()) == "USDC"


def test_a_tickers_token_keeps_its_symbol(m):
    gold = _tx(m, ALICE, Op.TOKEN_DEPLOY, name="Gold", symbol="GOLD", total_supply="1000",
               metadata_authority=ALICE)
    assert gold.success, gold.error
    address = gold.data["token_address"]
    assert _tx(m, ALICE, Op.TICKER_CLAIM, token_address=address).success
    r = _tx(m, ALICE, Op.TOKEN_UPDATE_METADATA, token_address=address, symbol="USDT")
    assert not r.success and "symbol stays" in r.error
    r = _tx(m, ALICE, Op.TOKEN_UPDATE_METADATA, token_address=address, name="Gold, renamed",
            symbol="gold")
    assert r.success, r.error                                       # same ticker, other case
