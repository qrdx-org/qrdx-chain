"""
Where perp markets come from (docs/HYPERLIQUID_PARITY.md 1, 13):

* the markets every network starts with (PERP_GENESIS_MARKETS — BTC, ETH and SOL, with
  Hyperliquid's leverage and size decimals), made by the first block on every path and priced by
  the validators' votes;
* more validator-priced markets by governance (``list_market``: tests/test_perps_listing_and_
  leverage.py);
* a perp on an on-chain token, by its address, listed by anyone (CREATE_MARKET:
  tests/test_token_perps.py).

No key prices a market: there is no operation that sets a price but the validators' vote.
"""
from decimal import Decimal as D

import pytest

from qrdx import chain_spec, constants
from qrdx.exchange import ExchangeOpType as Op
from qrdx.exchange import ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import block_processor as BP

T0 = 1_700_000_000
ALICE, BOB = "0xPQ" + "a" * 64, "0xPQ" + "b" * 64


@pytest.fixture
def genesis_markets(monkeypatch):
    """The release's default genesis markets."""
    monkeypatch.setattr(constants, "PERP_GENESIS_MARKETS",
                        tuple(chain_spec.PARAMS["PERP_GENESIS_MARKETS"].default))
    ExchangeStateManager.reset_instance()
    yield
    ExchangeStateManager.reset_instance()


def _block(mgr, height, txs=()):
    ok, err, root = BP.process_exchange_transactions(height, float(T0 + height), list(txs), mgr)
    assert ok, err
    mgr.commit_block()
    return root


def test_the_genesis_markets_are_hyperliquids_majors(genesis_markets):
    assert chain_spec.PARAMS["PERP_GENESIS_MARKETS"].default == ["BTC:40:5", "ETH:25:4",
                                                                  "SOL:20:2"]
    mgr = ExchangeStateManager()
    _block(mgr, 1)
    q = constants.PERP_QUOTE
    got = {m.base: (m.max_leverage, m.sz_decimals, m.spot_token)
           for m in mgr.clearinghouse.markets.values()}
    assert got == {"BTC": (40, 5, ""), "ETH": (25, 4, ""), "SOL": (20, 2, "")}
    assert set(mgr.clearinghouse.markets) == {f"{b}-{q}-PERP" for b in ("BTC", "ETH", "SOL")}


def test_every_path_makes_them_with_the_first_block(genesis_markets):
    """The proposer, an importer and a rebuild from genesis all run the same block path: the
    same markets, the same root — and a block with transactions makes them first."""
    a, b = ExchangeStateManager(), ExchangeStateManager()
    tx = ExchangeTransaction(op_type=Op.CANCEL_ALL, sender=ALICE, nonce=0, params={},
                             gas_limit=10 ** 6)
    roots_a = [_block(a, 1, [tx]), _block(a, 2)]
    roots_b = [_block(b, 1, [tx]), _block(b, 2)]
    assert roots_a == roots_b
    before = a.compute_state_root()
    assert a.create_genesis_markets() == []                       # made once
    assert a.compute_state_root() == before


def test_a_delisted_genesis_market_stays_settled(genesis_markets):
    mgr = ExchangeStateManager()
    _block(mgr, 1)
    btc = f"BTC-{constants.PERP_QUOTE}-PERP"
    mgr.clearinghouse.set_oracle_price(btc, D(30000), now=T0)
    mgr._delist_market(btc, None)
    _block(mgr, 2)
    assert mgr.clearinghouse.markets[btc].settled_price == 30000  # not made again


def test_their_bases_are_reserved_tickers(genesis_markets):
    assert {"BTC", "ETH", "SOL", "QRDX"} <= ExchangeStateManager.reserved_tickers()


def test_no_operation_sets_a_price_but_the_validators_vote(genesis_markets):
    """Neither CREATE_MARKET (a token's perp only) nor any retired operation (UPDATE_ORACLE, the
    deployer markets') can name a validator-priced market's price."""
    mgr = ExchangeStateManager()
    _block(mgr, 1)
    mgr.set_available_balance(ALICE, D(1_000_000))
    r = mgr.process_transaction(ExchangeTransaction(
        op_type=Op.CREATE_MARKET, sender=ALICE, nonce=0, params={"token": "BTC"},
        gas_limit=10 ** 6))
    assert not r.success and "no on-chain token" in r.error
    for retired in (11, 79, 80, 81, 82):
        with pytest.raises(ValueError):
            ExchangeTransaction.from_dict({"op_type": retired, "sender": ALICE, "nonce": 0,
                                           "params": {"market_id": "BTC-USD-PERP",
                                                      "price": "1"}})
    assert all(m.oracle_price == 0 for m in mgr.clearinghouse.markets.values())


def test_create_market_names_a_token():
    with pytest.raises(ValueError, match="token"):
        ExchangeTransaction(op_type=Op.CREATE_MARKET, sender=ALICE, nonce=0,
                            params={"base_token": "ETH"}, gas_limit=10 ** 6).validate_basic()
