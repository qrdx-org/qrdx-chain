"""
Spot order-book fees (docs/TRADING_FEATURES.md §10).

Each side of a spot fill pays its fee out of what it receives — the buyer in base, the seller in
quote — at its fee tier's rate (one tier an account, across perps and spot; a spot maker never
gets a rebate, since its fee and the taker's are in different assets), to the treasury, less a
referrer's share. Nothing changes for escrow: receiving less can never fail. The router quotes a
swap net of the taker's fee, fill by fill, so a quote is still exactly what executes.
"""
import random
from decimal import Decimal as D

import pytest

from qrdx import constants
from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction, views
from qrdx.exchange import clearinghouse as CH
from qrdx.exchange.orderbook import OrderBook, SelfTradeAction

T0 = 1_700_000_000
TOK = "0x" + "a" * 40
PAIR = f"{TOK}:QRDX"                          # quoted in QRDX: the tests' settlement asset
TREASURY = constants.SYSTEM_WALLET_ADDRESSES["TREASURY_MULTISIG"]
PEOPLE = ("0xPQm", "0xPQt", "0xPQr", "0xPQx")


@pytest.fixture
def m():
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    mgr.enforce_orderbook_settlement = mgr.enforce_spot_settlement = True
    book = OrderBook(pool_id=PAIR, self_trade_action=SelfTradeAction.CANCEL_TAKER)
    mgr._order_books[PAIR] = book
    mgr.router.register_order_book(PAIR, book)
    mgr.begin_block(1, float(T0))
    escrow = mgr.orderbook_escrow_address(PAIR)
    for who in PEOPLE:
        mgr.set_available_token_balance(who, TOK, D(10 ** 6))
        mgr.set_available_balance(who, D(10 ** 6))
    mgr.set_available_token_balance(escrow, TOK, D(0))
    mgr.set_available_balance(escrow, D(0))
    yield mgr
    ExchangeStateManager.reset_instance()


def _tx(m, who, op, params):
    return m.process_transaction(ExchangeTransaction(
        op_type=op, sender=who, nonce=m.get_nonce(who), params=params, gas_limit=10 ** 6))


def _order(m, who, side, price, amount):
    return _tx(m, who, ExchangeOpType.PLACE_ORDER, {
        "pair": PAIR, "side": side, "order_type": "limit", "price": str(price),
        "amount": str(amount)})


def _conserved(m):
    tokens, native = {}, D(0)
    for (_h, t), d in m.token_balance_deltas().items():
        tokens[t] = tokens.get(t, 0) + d
    for _a, d in m.balance_deltas().items():
        native += d
    assert all(v == 0 for v in tokens.values()) and native == 0


def test_each_side_pays_its_tiers_rate_out_of_what_it_receives(m):
    assert _order(m, "0xPQm", "sell", 2, 100).success          # the maker rests 100 TOK
    r = _order(m, "0xPQt", "buy", 2, 100)                       # the taker lifts them
    assert r.success
    fill = r.data["fills"][0]
    taker_fee = D(100) * CH.TAKER_FEE_RATE                       # in TOK, which it received
    maker_fee = D(200) * CH.MAKER_FEE_RATE                       # in QRDX, which it received
    assert D(fill["fees"]["0xPQt"]) == taker_fee and D(fill["fees"]["0xPQm"]) == maker_fee
    d, q = m.token_balance_deltas(), m.balance_deltas()
    # STAKER_FEE_SHARE_BPS of each fee to the stakers (docs/CONSENSUS_ROADMAP.md 6): in QRDX it is
    # this block's staker income; in another token it waits at the fee holder to be sold for QRDX.
    share = D(constants.STAKER_FEE_SHARE_BPS) / 10_000
    tok_staker, staker = taker_fee * share, maker_fee * share
    assert d[("0xPQt", TOK)] == 100 - taker_fee and d[(TREASURY, TOK)] == taker_fee - tok_staker
    assert d[(m.staker_fee_holder(), TOK)] == tok_staker
    assert m.fee_tokens.peek(TOK)[0] == tok_staker
    assert q["0xPQm"] == 200 - maker_fee and q[TREASURY] == maker_fee - staker
    assert q[m.staker_fee_holder()] == staker and m.block_staker_fees() == staker
    assert q["0xPQt"] == -200                                    # paid exactly the notional
    _conserved(m)


def test_a_spot_maker_never_gets_a_rebate(m):
    m.clearinghouse.new_block(T0)
    m.clearinghouse.volumes["0xPQm"] = ((T0 // 86400, D(10 ** 10)),)   # the rebate tier
    assert CH.FEE_TIERS[-1][2] < 0
    _order(m, "0xPQm", "sell", 2, 10)
    fill = _order(m, "0xPQt", "buy", 2, 10).data["fills"][0]
    assert D(fill["fees"]["0xPQm"]) == 0                         # not negative
    _conserved(m)


def test_spot_volume_quoted_in_the_settlement_asset_counts_toward_the_tier(m):
    _order(m, "0xPQm", "sell", 1000, 100)
    _order(m, "0xPQt", "buy", 1000, 100)                         # 100,000 of notional
    assert m.clearinghouse.volume("0xPQt") == 100_000 == m.clearinghouse.volume("0xPQm")


def test_a_referee_pays_less_and_its_referrer_shares_the_fee(m):
    m.clearinghouse.register_referral_code("0xPQr", "spot")
    m.clearinghouse.join_referral("0xPQt", "spot")
    _order(m, "0xPQm", "sell", 2, 100)
    fill = _order(m, "0xPQt", "buy", 2, 100).data["fills"][0]
    fee = (D(100) * CH.TAKER_FEE_RATE * (1 - CH.REFEREE_DISCOUNT)).quantize(D("1e-18"))
    reward = (fee * CH.REFERRER_SHARE).quantize(D("1e-18"))
    d = m.token_balance_deltas()
    staker = ((fee - reward) * D(constants.STAKER_FEE_SHARE_BPS) / 10_000).quantize(D("1e-18"))
    assert D(fill["fees"]["0xPQt"]) == fee
    assert d[("0xPQr", TOK)] == reward and d[(TREASURY, TOK)] == fee - reward - staker
    assert d[(m.staker_fee_holder(), TOK)] == staker
    _conserved(m)


@pytest.mark.parametrize("seed", range(12))
def test_a_swaps_quote_is_exactly_what_it_receives_after_fees(m, seed):
    rng = random.Random(seed)
    for i in range(30):
        who = rng.choice(("0xPQm", "0xPQx", "0xPQr"))
        side = rng.choice(("buy", "sell"))
        price = D(rng.randint(90, 110)) / 50
        _order(m, who, side, price if side == "sell" else price - 1, rng.randint(1, 50))
    for k in range(4):
        selling = rng.random() < 0.5
        token_in, token_out = (TOK, "QRDX") if selling else ("QRDX", TOK)
        amount = D(rng.randint(1, 200))
        quote = views.quote(m, token_in, token_out, amount, sender="0xPQt", venue="clob")
        before = (dict(m.token_balance_deltas()), dict(m.balance_deltas()))
        r = _tx(m, "0xPQt", ExchangeOpType.SWAP, {"token_in": token_in, "token_out": token_out,
                                                   "amount_in": str(amount), "venue": "clob"})
        if quote is None:
            assert not r.success
            continue
        assert r.success, r.error
        assert D(r.data["amount_out"]) == D(quote["amount_out"])
        received = (m.balance_deltas().get("0xPQt", 0) - before[1].get("0xPQt", 0)
                    if token_out == "QRDX"
                    else m.token_balance_deltas().get(("0xPQt", TOK), 0)
                    - before[0].get(("0xPQt", TOK), 0))
        assert received == D(quote["amount_out"]) and D(quote["fee"]) > 0
    _conserved(m)


def test_a_builder_takes_its_rate_of_what_a_spot_taker_receives(m):
    """Builder codes on spot (docs/HYPERLIQUID_PARITY.md): out of what the taker received — the
    base it bought — to the builder; value conserved."""
    front = "0xPQ" + "f" * 64
    assert _tx(m, "0xPQt", ExchangeOpType.APPROVE_BUILDER_FEE,
               {"builder": front, "max_fee_rate": "0.002"}).success
    _order(m, "0xPQm", "sell", 100, 10)
    r = _tx(m, "0xPQt", ExchangeOpType.PLACE_ORDER, {
        "pair": PAIR, "side": "buy", "order_type": "limit", "price": "100", "amount": "10",
        "builder": {"b": front, "f": "0.002"}})
    assert r.success, r.error
    assert D(r.data["builder_fee"][TOK]) == D(10) * D("0.002")
    assert m.token_balance_deltas()[(front, TOK)] == D("0.02")
    _conserved(m)
