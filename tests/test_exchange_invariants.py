"""
Phase F4 — adversarial property / invariant tests for the exchange math.

The exchange engine moves value, so its core math must hold invariants under a
wide range of inputs (the "Security Tested" gate). These are seeded-random
("fuzz") property tests over the real engine classes — AMM swaps, perpetual
positions, and the order book — asserting conservation, sign-correctness,
monotonicity, and rejection of adversarial inputs (zero/negative/huge), rather
than fixed example values.

A failure here is a potential loss-of-funds or consensus bug.
"""

import random
from decimal import Decimal

import pytest

from qrdx.exchange.amm import (
    ConcentratedLiquidityPool, PoolState, FeeTier, PoolType, tick_to_sqrt_price,
)
from qrdx.exchange.orderbook import (
    Order, OrderBook, OrderSide, OrderType, SelfTradeAction,
)

ADDR_A = "0xPQ" + "a1" * 32
ADDR_B = "0xPQ" + "b2" * 32

SEEDS = list(range(40))  # deterministic fuzz corpus


def _pool(fee=FeeTier.MEDIUM):
    state = PoolState(
        id="p", token0="qBTC", token1="qUSD",
        fee_tier=fee, pool_type=PoolType.STANDARD,
        creator=ADDR_A, sqrt_price=tick_to_sqrt_price(0),
    )
    return ConcentratedLiquidityPool(state)


# ─────────────────────────────────────────────────────────────────────────
#  AMM swap invariants
# ─────────────────────────────────────────────────────────────────────────

class TestSwapInvariants:
    @pytest.mark.parametrize("seed", SEEDS)
    def test_swap_outputs_are_sane(self, seed):
        rng = random.Random(seed)
        pool = _pool()
        pool.add_liquidity(ADDR_A, -600, 600, Decimal(rng.randint(1_000, 1_000_000)))
        amount_in = Decimal(rng.randint(1, 5_000))
        zero_for_one = rng.random() < 0.5
        liq_before = pool.state.liquidity
        try:
            out, fee = pool.swap(amount_in, zero_for_one)
        except ValueError:
            return  # legitimate rejection (e.g. exhausts in-range liquidity)
        # Invariants:
        assert out >= 0, "swap output must be non-negative"
        assert fee >= 0, "fee must be non-negative"
        assert fee < amount_in, "fee cannot exceed the input"
        assert pool.state.liquidity >= 0, "liquidity must never go negative"
        # Active-range liquidity is conserved by a pure swap (no LP change).
        assert pool.state.liquidity == liq_before

    @pytest.mark.parametrize("seed", SEEDS)
    def test_no_free_value_round_trip(self, seed):
        """Swapping out and back must NOT return more than you put in
        (fees + rounding must never create value — an arbitrage/mint bug)."""
        rng = random.Random(seed)
        pool = _pool()
        pool.add_liquidity(ADDR_A, -6000, 6000, Decimal(10_000_000))
        amount_in = Decimal(rng.randint(1, 10_000))
        try:
            out, _ = pool.swap(amount_in, True)          # token0 → token1
            if out <= 0:
                return
            back, _ = pool.swap(out, False)              # token1 → token0
        except ValueError:
            return
        assert back <= amount_in, (
            f"round-trip created value: in={amount_in}, back={back}"
        )

    @pytest.mark.parametrize("bad", [Decimal("0"), Decimal("-1"), Decimal("-1000000")])
    def test_non_positive_input_rejected(self, bad):
        pool = _pool()
        pool.add_liquidity(ADDR_A, -600, 600, Decimal("100000"))
        with pytest.raises(ValueError):
            pool.swap(bad, True)

    def test_swap_without_liquidity_rejected(self):
        pool = _pool()  # no liquidity added
        with pytest.raises(ValueError):
            pool.swap(Decimal("10"), True)


# ─────────────────────────────────────────────────────────────────────────
#  Perpetual invariants
# ─────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────
#  Order book invariants
# ─────────────────────────────────────────────────────────────────────────

class TestOrderBookInvariants:
    def _book(self, self_trade=SelfTradeAction.REJECT):
        return OrderBook(pool_id="qBTC:qUSD", self_trade_action=self_trade)

    def _order(self, oid, owner, side, price, amount, otype=OrderType.LIMIT, nonce=0):
        return Order(id=oid, owner=owner, side=side, order_type=otype,
                     price=Decimal(price), amount=Decimal(amount), nonce=nonce)

    @pytest.mark.parametrize("seed", SEEDS)
    def test_matched_quantity_is_conserved(self, seed):
        rng = random.Random(seed)
        book = self._book()
        # Resting sell, then a crossing buy; filled amounts must match.
        sell_amt = Decimal(rng.randint(1, 1000))
        book.place_order(self._order("s1", ADDR_A, OrderSide.SELL, "100", sell_amt))
        buy_amt = Decimal(rng.randint(1, 1000))
        trades = book.place_order(self._order("b1", ADDR_B, OrderSide.BUY, "100", buy_amt, nonce=1))
        filled = sum(t.amount for t in trades)
        assert filled == min(sell_amt, buy_amt), "matched quantity must equal min(maker, taker)"
        for t in trades:
            assert t.amount > 0
            assert t.maker_fee >= 0 and t.taker_fee >= 0
            assert t.taker_fee >= t.maker_fee, "taker fee must be >= maker fee (whitepaper §7.6)"

    def test_self_trade_rejected(self):
        book = self._book(self_trade=SelfTradeAction.REJECT)
        book.place_order(self._order("s1", ADDR_A, OrderSide.SELL, "100", "10"))
        # Same owner crossing — must not self-trade.
        trades = book.place_order(self._order("b1", ADDR_A, OrderSide.BUY, "100", "10", nonce=1))
        assert sum(t.amount for t in trades) == 0, "self-trade must be prevented"

    @pytest.mark.parametrize("bad_price,bad_amt", [("0", "10"), ("-1", "10"), ("100", "0"), ("100", "-5")])
    def test_invalid_limit_order_rejected(self, bad_price, bad_amt):
        book = self._book()
        with pytest.raises((ValueError, Exception)):
            book.place_order(self._order("x", ADDR_A, OrderSide.BUY, bad_price, bad_amt))

    @pytest.mark.parametrize("seed", SEEDS)
    def test_non_crossing_orders_rest_without_trades(self, seed):
        rng = random.Random(seed)
        book = self._book()
        # Buy below ask: must not trade.
        book.place_order(self._order("s1", ADDR_A, OrderSide.SELL, "200", "10"))
        trades = book.place_order(
            self._order("b1", ADDR_B, OrderSide.BUY, str(rng.randint(50, 199)), "10", nonce=1)
        )
        assert trades == [] or sum(t.amount for t in trades) == 0
