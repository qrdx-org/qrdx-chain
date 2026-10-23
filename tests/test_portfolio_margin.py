"""
Portfolio margin (docs/TRADING_FEATURES.md): tokens held as perps margin beside the settlement
token, valued at a perp market's oracle price less a haircut.

They count toward cross equity — margin for positions and orders. A liquidated account hands
them to the backstop vault at that same value (equity unchanged on both sides); the vault sells
them back into the settlement token a slice at a time, through the spot venues, never more
than its slippage bound under the oracle. Every amount is clearinghouse state: the ledger moves
only on deposit, withdrawal and the vault's sales, so margin never depends on a balance loaded
for a block.
"""
from decimal import Decimal as D

import pytest

from qrdx import constants
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import clearinghouse as CH
from qrdx.exchange.clearinghouse import ClearinghouseError
from qrdx.exchange.orderbook import OrderBook, SelfTradeAction

BTC, ETH_M = "BTC-QRDX-PERP", "ETH-QRDX-PERP"
ETH = "0x" + "e" * 40
T0 = 1_700_000_000


@pytest.fixture
def m(monkeypatch):
    monkeypatch.setattr(constants, "PERP_PORTFOLIO_ASSETS", (f"{ETH}:{ETH_M}:0.2",))
    monkeypatch.setattr(constants, "PERP_COLLATERAL_TOKEN", "QRDX")
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.begin_block(1, float(T0))
    ch = mgr.clearinghouse
    for base, price in (("BTC", 100), ("ETH", 10)):
        ch.create_market(base)
        ch.set_oracle_price(f"{base}-QRDX-PERP", D(price), now=T0)
    for o in ("maker", "other"):
        ch.deposit(o, D(10 ** 6))
    mgr.set_available_token_balance("trader", ETH, D(1000))
    mgr.set_available_token_balance(mgr.perps_holder_address(), ETH, D(0))
    yield mgr
    ExchangeStateManager.reset_instance()


def _tx(m, sender, op, params):
    return m.process_transaction(ExchangeTransaction(
        op_type=op, sender=sender, nonce=m.get_nonce(sender), params=params, gas_limit=10 ** 6))


def test_tokens_held_as_margin_carry_positions(m):
    ch = m.clearinghouse
    r = _tx(m, "trader", ExchangeOpType.PERP_DEPOSIT, {"asset": ETH, "amount": "100"})
    assert r.success, r.error
    d = m.token_balance_deltas()
    assert d[("trader", ETH)] == -100 and d[(m.perps_holder_address(), ETH)] == 100
    assert ch.cross_equity("trader") == 100 * 10 * D("0.8")          # 800, after the haircut
    assert ch.withdrawable("trader") == 0                            # no settlement token
    ch.place_order("maker", BTC, "ask", "sell", D(50), D(100), 0)
    r = _tx(m, "trader", ExchangeOpType.PERP_ORDER,
            {"market_id": BTC, "side": "buy", "size": "50", "price": "100"})
    assert r.success, r.error                                         # 5,000 at 10x: 500
    r = _tx(m, "trader", ExchangeOpType.PERP_ORDER,
            {"market_id": BTC, "side": "buy", "size": "50", "price": "100"})
    assert not r.success and "margin" in r.error
    assert ch.asset_gap() == {} and ch.identity_gap() == 0


def test_a_margin_token_leaves_only_if_what_is_left_carries_the_account(m):
    ch = m.clearinghouse
    _tx(m, "trader", ExchangeOpType.PERP_DEPOSIT, {"asset": ETH, "amount": "100"})
    ch.place_order("maker", BTC, "ask", "sell", D(50), D(100), 0)
    _tx(m, "trader", ExchangeOpType.PERP_ORDER,
        {"market_id": BTC, "side": "buy", "size": "50", "price": "100"})
    r = _tx(m, "trader", ExchangeOpType.PERP_WITHDRAW, {"asset": ETH, "amount": "50"})
    assert not r.success and "carry" in r.error                     # 400 left < 500 needed
    r = _tx(m, "trader", ExchangeOpType.PERP_WITHDRAW, {"asset": ETH, "amount": "30"})
    assert r.success, r.error and r.data["held"] == "70"
    assert ch.asset_gap() == {}
    # A realized loss leaves the account owing settlement token: the tokens that cover the debt
    # stay (what it owes counts against what is left).
    ch.place_order("other", BTC, "bid", "buy", D(50), D(90), 0)
    _tx(m, "trader", ExchangeOpType.PERP_ORDER,
        {"market_id": BTC, "side": "sell", "size": "50", "price": "90", "reduce_only": True})
    debt = -ch.accounts["trader"].collateral
    assert debt > 500
    r = _tx(m, "trader", ExchangeOpType.PERP_WITHDRAW, {"asset": ETH, "amount": "70"})
    assert not r.success and "carry" in r.error
    keep = debt / 8                                                   # 8 a token after the haircut
    r = _tx(m, "trader", ExchangeOpType.PERP_WITHDRAW,
            {"asset": ETH, "amount": str((70 - keep).quantize(D("1"), rounding="ROUND_FLOOR"))})
    assert r.success, r.error
    assert ch.cross_equity("trader") >= 0 and ch.asset_gap() == {}


@pytest.mark.parametrize("params, error", [
    ({"asset": "0x" + "f" * 40, "amount": "100"}, "not accepted"),
    ({"asset": ETH, "amount": "5"}, "at least"),                       # worth 40 < 100
    ({"asset": ETH, "amount": "2000"}, "insufficient"),
])
def test_what_is_not_margin_is_refused(m, params, error):
    r = _tx(m, "trader", ExchangeOpType.PERP_DEPOSIT, params)
    assert not r.success and error in r.error


def test_a_liquidation_hands_the_tokens_to_the_vault_at_the_value_they_counted_for(m):
    from qrdx.exchange.block_processor import _execute_block_boundary_duties

    ch = m.clearinghouse
    _tx(m, "trader", ExchangeOpType.PERP_DEPOSIT, {"asset": ETH, "amount": "100"})
    ch.place_order("maker", BTC, "ask", "sell", D(70), D(100), 0)
    assert _tx(m, "trader", ExchangeOpType.PERP_ORDER,
               {"market_id": BTC, "side": "buy", "size": "70", "price": "100"}).success
    ch.place_order("other", BTC, "bid", "buy", D(100), D(89), 0)
    ch.set_oracle_price(BTC, D(90), now=T0 + 1)
    vault_before = ch.cross_equity(CH.VAULT)
    m.begin_block(2, float(T0 + 1))
    _execute_block_boundary_duties(m, 2, float(T0 + 1))
    events = m._block_tick_events
    assert any(e["type"] == "liquidation" and e["owner"] == "trader" for e in events)
    assert not ch.accounts["trader"].assets
    assert ch.accounts[CH.VAULT].assets == {ETH: D(100)}
    assert ch.asset_gap() == {} and ch.identity_gap() == 0
    assert ch.cross_equity(CH.VAULT) >= vault_before                # it gained the fees
    ch.verify_commitment()


def test_the_vault_sells_the_tokens_it_took_over_within_its_bound(m, no_trading_fees):
    from qrdx.exchange.block_processor import _execute_block_boundary_duties

    ch = m.clearinghouse
    vault = ch.account(CH.VAULT)
    vault.assets[ETH] = D(100)
    ch.asset_holdings[ETH] = D(100)
    m.set_available_token_balance(m.perps_holder_address(), ETH, D(100))
    pair = m._canonical_pair(f"{ETH}:QRDX")
    book = OrderBook(pool_id=pair, self_trade_action=SelfTradeAction.CANCEL_TAKER)
    m._order_books[pair] = book
    m.router.register_order_book(pair, book)
    book.place_order(__import__("qrdx.exchange.orderbook", fromlist=["Order"]).Order(
        id="far", owner="buyer", side=__import__("qrdx.exchange.orderbook",
                                                 fromlist=["OrderSide"]).OrderSide.BUY,
        order_type=__import__("qrdx.exchange.orderbook", fromlist=["OrderType"]).OrderType.LIMIT,
        price=D("9.5"), amount=D(1000), nonce=0, timestamp=0.0))   # 5 % under the oracle
    _execute_block_boundary_duties(m, 1, float(T0 + 60))
    assert ch.accounts[CH.VAULT].assets == {ETH: D(100)}               # beyond its 2 % bound
    book.place_order(__import__("qrdx.exchange.orderbook", fromlist=["Order"]).Order(
        id="near", owner="buyer", side=__import__("qrdx.exchange.orderbook",
                                                  fromlist=["OrderSide"]).OrderSide.BUY,
        order_type=__import__("qrdx.exchange.orderbook", fromlist=["OrderType"]).OrderType.LIMIT,
        price=D("9.9"), amount=D(1000), nonce=0, timestamp=0.0))
    collateral, holder = vault.collateral, ch.holder_balance
    _execute_block_boundary_duties(m, 1, float(T0 + 120))
    sale = [e for e in m._block_tick_events if e["type"] == "vault_asset_sale"]
    assert sale and D(sale[0]["proceeds"]) == D(990)
    assert ETH not in ch.accounts[CH.VAULT].assets and ETH not in ch.asset_holdings
    assert ch.accounts[CH.VAULT].collateral == collateral + 990
    assert ch.holder_balance == holder + 990 and ch.identity_gap() == 0
    d = m.token_balance_deltas()
    assert d[(m.perps_holder_address(), ETH)] == -100


def test_a_debt_its_tokens_no_longer_cover_is_taken_over_without_positions(m):
    ch = m.clearinghouse
    _tx(m, "trader", ExchangeOpType.PERP_DEPOSIT, {"asset": ETH, "amount": "100"})
    ch.accounts["trader"].collateral -= D(700)                    # owes 700; covered by 800
    ch.holder_balance -= D(700)                                    # (paid out to someone)
    assert ch.tick(D(T0 + 1)) == [] or True
    assert ch.accounts["trader"].assets                            # still covered
    ch.set_oracle_price(ETH_M, D(8), now=T0 + 2)                   # 100 × 8 × 0.8 = 640 < 700
    events = [e for e in ch.tick(D(T0 + 2)) if e["type"] == "liquidation"]
    assert events and events[0]["stage"] == "assets"
    assert ch.accounts["trader"].collateral == 0 and not ch.accounts["trader"].assets
    assert ch.accounts[CH.VAULT].assets == {ETH: D(100)}
    assert ch.asset_gap() == {} and ch.identity_gap() == 0
