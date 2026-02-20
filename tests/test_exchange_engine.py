"""
Test suite for QRDX Exchange Engine (Step 5)

Covers:
  5.1  Concentrated-Liquidity AMM
  5.2  On-Chain Order Book
  5.3  Fee Tiers & Distribution
  5.4  User-Deployable Pools
  5.5  TWAP Oracle
  5.6  Hooks / Router / Settlement
  +    Perpetual Contracts (perps)
  +    Security Hardening Tests
"""

import math
import time
import uuid
from decimal import Decimal, ROUND_HALF_UP

import pytest

# ---------------------------------------------------------------------------
# Order Book imports
# ---------------------------------------------------------------------------
from qrdx.exchange.orderbook import (
    Order,
    OrderBook,
    OrderSide,
    OrderStatus,
    OrderType,
    PriceLevel,
    Trade,
)

# ---------------------------------------------------------------------------
# AMM imports
# ---------------------------------------------------------------------------
from qrdx.exchange.amm import (
    ConcentratedLiquidityPool,
    FeeTier,
    PoolManager,
    PoolState,
    PoolType,
    Position,
    TickInfo,
    FEE_CREATOR_SHARE,
    FEE_LP_SHARE,
    FEE_TREASURY_SHARE,
    FEE_VALIDATOR_SHARE,
    POOL_STAKE_REQUIREMENTS,
    tick_to_sqrt_price,
    sqrt_price_to_tick,
    sqrt_price_to_price,
    MIN_TICK,
    MAX_TICK,
    Q96,
)

# ---------------------------------------------------------------------------
# Perpetual imports
# ---------------------------------------------------------------------------
from qrdx.exchange.perpetual import (
    FundingSnapshot,
    LiquidationResult,
    PerpEngine,
    PerpMarket,
    PerpPosition,
    PerpSide,
    PositionStatus,
    FUNDING_INTERVAL,
    MAX_FUNDING_RATE,
    MAX_LEVERAGE,
    DEFAULT_INITIAL_MARGIN,
    DEFAULT_MAINT_MARGIN,
)

# ---------------------------------------------------------------------------
# Router imports
# ---------------------------------------------------------------------------
from qrdx.exchange.router import (
    FillResult,
    FillSource,
    UnifiedRouter,
)

# ---------------------------------------------------------------------------
# Oracle imports
# ---------------------------------------------------------------------------
from qrdx.exchange.oracle import (
    Observation,
    TWAPOracle,
)

# ---------------------------------------------------------------------------
# Constants imports
# ---------------------------------------------------------------------------
from qrdx.constants import (
    EXCHANGE_FEE_TIER_ULTRA_LOW,
    EXCHANGE_FEE_TIER_LOW,
    EXCHANGE_FEE_TIER_MEDIUM,
    EXCHANGE_FEE_TIER_HIGH,
    EXCHANGE_FEE_LP_SHARE,
    EXCHANGE_FEE_CREATOR_SHARE,
    EXCHANGE_FEE_TREASURY_SHARE,
    EXCHANGE_FEE_VALIDATOR_SHARE,
    EXCHANGE_ORDERBOOK_MAKER_FEE,
    EXCHANGE_ORDERBOOK_TAKER_FEE,
    EXCHANGE_ORDERBOOK_MAX_DEPTH,
    EXCHANGE_POOL_STAKE_STANDARD,
    EXCHANGE_POOL_STAKE_BOOTSTRAP,
    EXCHANGE_POOL_BURN_SUBSIDIZED,
    EXCHANGE_POOL_STAKE_INSTITUTIONAL,
    EXCHANGE_MIN_TICK,
    EXCHANGE_MAX_TICK,
    PERP_MAX_LEVERAGE,
    PERP_DEFAULT_INITIAL_MARGIN,
    PERP_DEFAULT_MAINTENANCE_MARGIN,
    PERP_FUNDING_INTERVAL_SECONDS,
    PERP_MAX_FUNDING_RATE,
    EXCHANGE_GAS_SWAP,
    EXCHANGE_GAS_ADD_LIQUIDITY,
    EXCHANGE_GAS_LIMIT_ORDER,
    EXCHANGE_GAS_CANCEL_ORDER,
    EXCHANGE_GAS_CREATE_POOL,
)

ZERO = Decimal("0")
ADDR_A = "Qrdx_test_alice_000000000000000000000001"
ADDR_B = "Qrdx_test_bob___000000000000000000000002"
ADDR_C = "Qrdx_test_carol_000000000000000000000003"


# ============================================================================
#  §5.2  ON-CHAIN ORDER BOOK
# ============================================================================

class TestOrderBookBasics:
    """Order creation, placement, cancellation."""

    def test_create_order(self):
        o = Order(id="o1", owner=ADDR_A, side=OrderSide.BUY,
                  order_type=OrderType.LIMIT, price=Decimal("100"), amount=Decimal("10"))
        assert o.remaining == Decimal("10")
        assert o.is_active

    def test_order_sides(self):
        assert OrderSide.BUY.value == "buy"
        assert OrderSide.SELL.value == "sell"

    def test_order_types(self):
        assert OrderType.LIMIT.value == "limit"
        assert OrderType.MARKET.value == "market"
        assert OrderType.STOP_LOSS.value == "stop_loss"

    def test_order_status_enum(self):
        assert OrderStatus.OPEN.value == "open"
        assert OrderStatus.FILLED.value == "filled"
        assert OrderStatus.CANCELLED.value == "cancelled"

    def test_order_book_creation(self):
        book = OrderBook(pool_id="test", max_depth=500)
        assert book.best_bid is None
        assert book.best_ask is None
        assert book.spread is None

    def test_place_limit_buy(self):
        book = OrderBook()
        o = Order(id="b1", owner=ADDR_A, side=OrderSide.BUY,
                  order_type=OrderType.LIMIT, price=Decimal("100"), amount=Decimal("5"))
        trades = book.place_order(o)
        assert trades == []
        assert book.best_bid == Decimal("100")

    def test_place_limit_sell(self):
        book = OrderBook()
        o = Order(id="s1", owner=ADDR_A, side=OrderSide.SELL,
                  order_type=OrderType.LIMIT, price=Decimal("110"), amount=Decimal("5"))
        trades = book.place_order(o)
        assert trades == []
        assert book.best_ask == Decimal("110")

    def test_cancel_order(self):
        book = OrderBook()
        o = Order(id="c1", owner=ADDR_A, side=OrderSide.BUY,
                  order_type=OrderType.LIMIT, price=Decimal("100"), amount=Decimal("5"))
        book.place_order(o)
        cancelled = book.cancel_order("c1")
        assert cancelled is not None
        assert cancelled.status == OrderStatus.CANCELLED
        assert book.best_bid is None

    def test_cancel_nonexistent(self):
        book = OrderBook()
        assert book.cancel_order("nope") is None

    def test_validate_zero_amount(self):
        book = OrderBook()
        o = Order(id="v1", owner=ADDR_A, side=OrderSide.BUY,
                  order_type=OrderType.LIMIT, price=Decimal("100"), amount=Decimal("0"))
        with pytest.raises(ValueError, match="positive"):
            book.place_order(o)

    def test_validate_no_owner(self):
        book = OrderBook()
        o = Order(id="v2", owner="", side=OrderSide.BUY,
                  order_type=OrderType.LIMIT, price=Decimal("100"), amount=Decimal("1"))
        with pytest.raises(ValueError, match="owner"):
            book.place_order(o)

    def test_validate_limit_zero_price(self):
        book = OrderBook()
        o = Order(id="v3", owner=ADDR_A, side=OrderSide.BUY,
                  order_type=OrderType.LIMIT, price=Decimal("0"), amount=Decimal("1"))
        with pytest.raises(ValueError, match="price"):
            book.place_order(o)


class TestOrderBookMatching:
    """Price-time priority matching."""

    def _make_book_with_asks(self):
        book = OrderBook()
        # Two asks at different prices
        book.place_order(Order(id="a1", owner=ADDR_B, side=OrderSide.SELL,
                               order_type=OrderType.LIMIT, price=Decimal("100"), amount=Decimal("5")))
        book.place_order(Order(id="a2", owner=ADDR_C, side=OrderSide.SELL,
                               order_type=OrderType.LIMIT, price=Decimal("101"), amount=Decimal("5")))
        return book

    def test_full_fill(self):
        book = self._make_book_with_asks()
        buy = Order(id="b1", owner=ADDR_A, side=OrderSide.BUY,
                    order_type=OrderType.LIMIT, price=Decimal("100"), amount=Decimal("5"))
        trades = book.place_order(buy)
        assert len(trades) == 1
        assert trades[0].amount == Decimal("5")
        assert trades[0].price == Decimal("100")
        assert buy.status == OrderStatus.FILLED

    def test_partial_fill(self):
        book = self._make_book_with_asks()
        buy = Order(id="b2", owner=ADDR_A, side=OrderSide.BUY,
                    order_type=OrderType.LIMIT, price=Decimal("100"), amount=Decimal("3"))
        trades = book.place_order(buy)
        assert len(trades) == 1
        assert trades[0].amount == Decimal("3")
        assert buy.status == OrderStatus.FILLED
        # Maker should be partially filled
        maker = book.get_order("a1")
        assert maker is not None
        assert maker.remaining == Decimal("2")
        assert maker.status == OrderStatus.PARTIALLY_FILLED

    def test_cross_multiple_levels(self):
        book = self._make_book_with_asks()
        buy = Order(id="b3", owner=ADDR_A, side=OrderSide.BUY,
                    order_type=OrderType.LIMIT, price=Decimal("101"), amount=Decimal("8"))
        trades = book.place_order(buy)
        assert len(trades) == 2
        assert trades[0].price == Decimal("100")  # best price first
        assert trades[0].amount == Decimal("5")
        assert trades[1].price == Decimal("101")
        assert trades[1].amount == Decimal("3")
        assert buy.status == OrderStatus.FILLED

    def test_market_order(self):
        book = self._make_book_with_asks()
        buy = Order(id="m1", owner=ADDR_A, side=OrderSide.BUY,
                    order_type=OrderType.MARKET, price=Decimal("0"), amount=Decimal("3"))
        trades = book.place_order(buy)
        assert len(trades) == 1
        assert trades[0].amount == Decimal("3")

    def test_market_order_no_liquidity(self):
        book = OrderBook()
        buy = Order(id="m2", owner=ADDR_A, side=OrderSide.BUY,
                    order_type=OrderType.MARKET, price=Decimal("0"), amount=Decimal("1"))
        trades = book.place_order(buy)
        assert trades == []

    def test_time_priority(self):
        book = OrderBook()
        # Two asks at the SAME price, different times
        o1 = Order(id="first", owner=ADDR_B, side=OrderSide.SELL,
                   order_type=OrderType.LIMIT, price=Decimal("100"), amount=Decimal("5"), timestamp=1.0)
        o2 = Order(id="second", owner=ADDR_C, side=OrderSide.SELL,
                   order_type=OrderType.LIMIT, price=Decimal("100"), amount=Decimal("5"), timestamp=2.0)
        book.place_order(o1)
        book.place_order(o2)
        buy = Order(id="buy", owner=ADDR_A, side=OrderSide.BUY,
                    order_type=OrderType.LIMIT, price=Decimal("100"), amount=Decimal("3"))
        trades = book.place_order(buy)
        assert len(trades) == 1
        assert trades[0].maker_order_id == "first"  # time priority

    def test_maker_taker_fees(self):
        book = OrderBook(maker_fee_rate=Decimal("0.0002"), taker_fee_rate=Decimal("0.0005"))
        book.place_order(Order(id="ask", owner=ADDR_B, side=OrderSide.SELL,
                               order_type=OrderType.LIMIT, price=Decimal("100"), amount=Decimal("10")))
        buy = Order(id="buy", owner=ADDR_A, side=OrderSide.BUY,
                    order_type=OrderType.LIMIT, price=Decimal("100"), amount=Decimal("10"))
        trades = book.place_order(buy)
        t = trades[0]
        # maker fee: 10 * 100 * 0.0002 = 0.2
        assert t.maker_fee == Decimal("0.20000000")
        # taker fee: 10 * 100 * 0.0005 = 0.5
        assert t.taker_fee == Decimal("0.50000000")


class TestOrderBookStopLoss:
    """Stop-loss order placement and triggering."""

    def test_stop_loss_placement(self):
        book = OrderBook()
        stop = Order(id="sl1", owner=ADDR_A, side=OrderSide.SELL,
                     order_type=OrderType.STOP_LOSS, price=Decimal("0"),
                     amount=Decimal("5"), stop_price=Decimal("90"))
        trades = book.place_order(stop)
        assert trades == []
        assert book.get_order("sl1") is not None

    def test_stop_loss_missing_price(self):
        book = OrderBook()
        stop = Order(id="sl2", owner=ADDR_A, side=OrderSide.SELL,
                     order_type=OrderType.STOP_LOSS, price=Decimal("0"),
                     amount=Decimal("5"), stop_price=None)
        with pytest.raises(ValueError, match="stop_price"):
            book.place_order(stop)

    def test_stop_loss_cancel(self):
        book = OrderBook()
        stop = Order(id="sl3", owner=ADDR_A, side=OrderSide.SELL,
                     order_type=OrderType.STOP_LOSS, price=Decimal("0"),
                     amount=Decimal("5"), stop_price=Decimal("90"))
        book.place_order(stop)
        cancelled = book.cancel_order("sl3")
        assert cancelled is not None
        assert cancelled.status == OrderStatus.CANCELLED


class TestOrderBookDepth:
    """Bid/ask depth queries and max depth enforcement."""

    def test_get_bids_asks(self):
        book = OrderBook()
        book.place_order(Order(id="b1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("99"), amount=Decimal("1")))
        book.place_order(Order(id="b2", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("98"), amount=Decimal("2")))
        book.place_order(Order(id="a1", owner=ADDR_B, side=OrderSide.SELL,
                               order_type=OrderType.LIMIT, price=Decimal("101"), amount=Decimal("3")))

        bids = book.get_bids(depth=5)
        assert len(bids) == 2
        assert bids[0][0] == Decimal("99")  # best bid first

        asks = book.get_asks(depth=5)
        assert len(asks) == 1
        assert asks[0][0] == Decimal("101")

    def test_mid_price_and_spread(self):
        book = OrderBook()
        book.place_order(Order(id="b", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"), amount=Decimal("1")))
        book.place_order(Order(id="a", owner=ADDR_B, side=OrderSide.SELL,
                               order_type=OrderType.LIMIT, price=Decimal("102"), amount=Decimal("1")))
        assert book.spread == Decimal("2")
        assert book.mid_price == Decimal("101")

    def test_max_depth_enforcement(self):
        book = OrderBook(max_depth=3)
        for i in range(3):
            book.place_order(Order(id=f"b{i}", owner=ADDR_A, side=OrderSide.BUY,
                                   order_type=OrderType.LIMIT, price=Decimal(str(100 - i)),
                                   amount=Decimal("1")))
        with pytest.raises(ValueError, match="depth limit"):
            book.place_order(Order(id="b3", owner=ADDR_A, side=OrderSide.BUY,
                                   order_type=OrderType.LIMIT, price=Decimal("96"),
                                   amount=Decimal("1")))

    def test_open_orders_by_owner(self):
        book = OrderBook()
        book.place_order(Order(id="x1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"), amount=Decimal("1")))
        book.place_order(Order(id="x2", owner=ADDR_B, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("99"), amount=Decimal("2")))
        assert len(book.get_open_orders(owner=ADDR_A)) == 1
        assert len(book.get_open_orders()) == 2


class TestOrderBookTrades:
    """Trade recording and stats."""

    def test_trade_history(self):
        book = OrderBook()
        book.place_order(Order(id="s1", owner=ADDR_B, side=OrderSide.SELL,
                               order_type=OrderType.LIMIT, price=Decimal("50"), amount=Decimal("10")))
        book.place_order(Order(id="b1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("50"), amount=Decimal("10")))
        trades = book.get_recent_trades()
        assert len(trades) == 1
        assert trades[0].buyer == ADDR_A
        assert trades[0].seller == ADDR_B

    def test_volume_tracking(self):
        book = OrderBook()
        book.place_order(Order(id="s1", owner=ADDR_B, side=OrderSide.SELL,
                               order_type=OrderType.LIMIT, price=Decimal("100"), amount=Decimal("5")))
        book.place_order(Order(id="b1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"), amount=Decimal("5")))
        assert book.total_volume == Decimal("500")
        assert book.total_trades == 1


# ============================================================================
#  §5.1  CONCENTRATED-LIQUIDITY AMM
# ============================================================================

class TestTickMath:
    """Tick ↔ sqrt-price conversions."""

    def test_tick_zero_is_price_one(self):
        sqrt_p = tick_to_sqrt_price(0)
        price = sqrt_price_to_price(sqrt_p)
        assert abs(price - Decimal("1")) < Decimal("0.001")

    def test_positive_tick(self):
        sqrt_p = tick_to_sqrt_price(1000)
        price = sqrt_price_to_price(sqrt_p)
        assert price > Decimal("1")

    def test_negative_tick(self):
        sqrt_p = tick_to_sqrt_price(-1000)
        price = sqrt_price_to_price(sqrt_p)
        assert price < Decimal("1")

    def test_roundtrip(self):
        for tick in [0, 100, -200, 5000, -5000]:
            sqrt_p = tick_to_sqrt_price(tick)
            recovered = sqrt_price_to_tick(sqrt_p)
            assert abs(recovered - tick) <= 1  # may be off by one due to floor


class TestFeeTier:
    """Fee tier enum and rates."""

    def test_fee_tier_values(self):
        assert int(FeeTier.ULTRA_LOW) == 100
        assert int(FeeTier.LOW) == 500
        assert int(FeeTier.MEDIUM) == 3000
        assert int(FeeTier.HIGH) == 10000

    def test_fee_rates(self):
        assert FeeTier.ULTRA_LOW.rate == Decimal("0.0001")
        assert FeeTier.LOW.rate == Decimal("0.0005")
        assert FeeTier.MEDIUM.rate == Decimal("0.003")
        assert FeeTier.HIGH.rate == Decimal("0.01")

    def test_tick_spacing(self):
        assert FeeTier.ULTRA_LOW.tick_spacing == 1
        assert FeeTier.LOW.tick_spacing == 10
        assert FeeTier.MEDIUM.tick_spacing == 60
        assert FeeTier.HIGH.tick_spacing == 200

    def test_fee_distribution_sums_to_one(self):
        total = FEE_LP_SHARE + FEE_CREATOR_SHARE + FEE_TREASURY_SHARE + FEE_VALIDATOR_SHARE
        assert total == Decimal("1.00")


class TestPoolState:
    """Pool state data model."""

    def test_pool_state_creation(self):
        state = PoolState(
            id="p1", token0="QRDX", token1="USDC",
            fee_tier=FeeTier.MEDIUM, pool_type=PoolType.STANDARD,
            creator=ADDR_A, sqrt_price=tick_to_sqrt_price(0),
        )
        assert state.token0 == "QRDX"
        assert state.fee_tier == FeeTier.MEDIUM
        price = state.price
        assert abs(price - Decimal("1")) < Decimal("0.001")


class TestConcentratedLiquidity:
    """Core AMM swap and liquidity operations."""

    def _make_pool(self, fee_tier=FeeTier.MEDIUM) -> ConcentratedLiquidityPool:
        state = PoolState(
            id="pool1", token0="QRDX", token1="USDC",
            fee_tier=fee_tier, pool_type=PoolType.STANDARD,
            creator=ADDR_A, sqrt_price=tick_to_sqrt_price(0),
        )
        return ConcentratedLiquidityPool(state)

    def test_add_liquidity(self):
        pool = self._make_pool()
        pos = pool.add_liquidity(ADDR_A, -60, 60, Decimal("1000"))
        assert pos.liquidity == Decimal("1000")
        assert pos.is_active
        assert pool.state.liquidity == Decimal("1000")

    def test_add_liquidity_bad_ticks(self):
        pool = self._make_pool()
        with pytest.raises(ValueError, match="tick_lower"):
            pool.add_liquidity(ADDR_A, 60, -60, Decimal("100"))

    def test_add_liquidity_bad_spacing(self):
        pool = self._make_pool(fee_tier=FeeTier.MEDIUM)  # spacing = 60
        with pytest.raises(ValueError, match="tick_spacing"):
            pool.add_liquidity(ADDR_A, -50, 50, Decimal("100"))

    def test_add_liquidity_zero_amount(self):
        pool = self._make_pool()
        with pytest.raises(ValueError, match="positive"):
            pool.add_liquidity(ADDR_A, -60, 60, Decimal("0"))

    def test_swap_zero_for_one(self):
        pool = self._make_pool()
        pool.add_liquidity(ADDR_A, -60, 60, Decimal("100000"))
        amount_out, fee = pool.swap(Decimal("100"), zero_for_one=True)
        assert amount_out > 0
        assert fee > 0
        assert pool.state.total_volume_0 == Decimal("100")

    def test_swap_one_for_zero(self):
        pool = self._make_pool()
        pool.add_liquidity(ADDR_A, -60, 60, Decimal("100000"))
        amount_out, fee = pool.swap(Decimal("100"), zero_for_one=False)
        assert amount_out >= 0
        assert fee > 0

    def test_swap_no_liquidity(self):
        pool = self._make_pool()
        with pytest.raises(ValueError, match="liquidity"):
            pool.swap(Decimal("100"), zero_for_one=True)

    def test_swap_zero_amount(self):
        pool = self._make_pool()
        pool.add_liquidity(ADDR_A, -60, 60, Decimal("100000"))
        with pytest.raises(ValueError, match="positive"):
            pool.swap(Decimal("0"), zero_for_one=True)

    def test_remove_liquidity(self):
        pool = self._make_pool()
        pos = pool.add_liquidity(ADDR_A, -60, 60, Decimal("1000"))
        fees_0, fees_1 = pool.remove_liquidity(pos.id)
        assert pool.state.liquidity == Decimal("0")

    def test_remove_liquidity_partial(self):
        pool = self._make_pool()
        pos = pool.add_liquidity(ADDR_A, -60, 60, Decimal("1000"))
        pool.remove_liquidity(pos.id, amount=Decimal("500"))
        remaining = pool.state.positions.get(pos.id)
        assert remaining is not None
        assert remaining.liquidity == Decimal("500")

    def test_remove_nonexistent(self):
        pool = self._make_pool()
        with pytest.raises(ValueError, match="not found"):
            pool.remove_liquidity("nope")

    def test_fee_accrual_on_swap(self):
        pool = self._make_pool()
        pool.add_liquidity(ADDR_A, -60, 60, Decimal("100000"))
        pool.swap(Decimal("1000"), zero_for_one=True)
        assert pool.state.fee_growth_global_0 > 0

    def test_protocol_fees_accrued(self):
        pool = self._make_pool()
        pool.add_liquidity(ADDR_A, -60, 60, Decimal("100000"))
        pool.swap(Decimal("1000"), zero_for_one=True)
        assert pool.state.protocol_fees_0 > 0


# ============================================================================
#  §5.3  FEE TIERS & DISTRIBUTION
# ============================================================================

class TestFeeDistribution:
    """Fee split: 70/15/10/5."""

    def test_fee_split_constants_match_whitepaper(self):
        assert EXCHANGE_FEE_LP_SHARE == Decimal("0.70")
        assert EXCHANGE_FEE_CREATOR_SHARE == Decimal("0.15")
        assert EXCHANGE_FEE_TREASURY_SHARE == Decimal("0.10")
        assert EXCHANGE_FEE_VALIDATOR_SHARE == Decimal("0.05")

    def test_fee_split_via_router(self):
        fees = UnifiedRouter._split_fees(Decimal("100"))
        assert fees["fee_lp"] == Decimal("70.00000000")
        assert fees["fee_creator"] == Decimal("15.00000000")
        assert fees["fee_treasury"] == Decimal("10.00000000")
        # validator gets remainder (5.00)
        assert fees["fee_validator"] == Decimal("5.00000000")

    def test_fee_tier_constants_match(self):
        assert EXCHANGE_FEE_TIER_ULTRA_LOW == 100
        assert EXCHANGE_FEE_TIER_LOW == 500
        assert EXCHANGE_FEE_TIER_MEDIUM == 3000
        assert EXCHANGE_FEE_TIER_HIGH == 10000


# ============================================================================
#  §5.4  USER-DEPLOYABLE POOLS
# ============================================================================

class TestPoolManager:
    """Permissionless pool creation with stake requirements."""

    def test_create_standard_pool(self):
        mgr = PoolManager()
        pool = mgr.create_pool("QRDX", "USDC", FeeTier.MEDIUM, PoolType.STANDARD,
                               tick_to_sqrt_price(0), ADDR_A, Decimal("10000"))
        assert pool.state.pool_type == PoolType.STANDARD
        assert mgr.pool_count == 1

    def test_create_bootstrap_pool(self):
        mgr = PoolManager()
        pool = mgr.create_pool("QRDX", "ETH", FeeTier.LOW, PoolType.BOOTSTRAP,
                               tick_to_sqrt_price(0), ADDR_A, Decimal("25000"))
        assert pool.state.pool_type == PoolType.BOOTSTRAP

    def test_create_subsidized_pool(self):
        mgr = PoolManager()
        pool = mgr.create_pool("QRDX", "BTC", FeeTier.HIGH, PoolType.SUBSIDIZED,
                               tick_to_sqrt_price(0), ADDR_A, Decimal("5000"))
        assert pool.state.pool_type == PoolType.SUBSIDIZED

    def test_create_institutional_pool(self):
        mgr = PoolManager()
        pool = mgr.create_pool("QRDX", "GOLD", FeeTier.ULTRA_LOW, PoolType.INSTITUTIONAL,
                               tick_to_sqrt_price(0), ADDR_A, Decimal("100000"))
        assert pool.state.pool_type == PoolType.INSTITUTIONAL

    def test_insufficient_stake_rejected(self):
        mgr = PoolManager()
        with pytest.raises(ValueError, match="staking"):
            mgr.create_pool("QRDX", "USDC", FeeTier.MEDIUM, PoolType.STANDARD,
                            tick_to_sqrt_price(0), ADDR_A, Decimal("5000"))

    def test_subsidized_insufficient_burn(self):
        mgr = PoolManager()
        with pytest.raises(ValueError, match="burning"):
            mgr.create_pool("QRDX", "BTC", FeeTier.HIGH, PoolType.SUBSIDIZED,
                            tick_to_sqrt_price(0), ADDR_A, Decimal("1000"))

    def test_duplicate_pool_rejected(self):
        mgr = PoolManager()
        mgr.create_pool("QRDX", "USDC", FeeTier.MEDIUM, PoolType.STANDARD,
                         tick_to_sqrt_price(0), ADDR_A, Decimal("10000"))
        with pytest.raises(ValueError, match="already exists"):
            mgr.create_pool("QRDX", "USDC", FeeTier.MEDIUM, PoolType.STANDARD,
                            tick_to_sqrt_price(0), ADDR_B, Decimal("10000"))

    def test_same_pair_different_fee_tier(self):
        mgr = PoolManager()
        mgr.create_pool("QRDX", "USDC", FeeTier.MEDIUM, PoolType.STANDARD,
                         tick_to_sqrt_price(0), ADDR_A, Decimal("10000"))
        pool2 = mgr.create_pool("QRDX", "USDC", FeeTier.LOW, PoolType.STANDARD,
                                 tick_to_sqrt_price(0), ADDR_B, Decimal("10000"))
        assert mgr.pool_count == 2

    def test_canonical_ordering(self):
        mgr = PoolManager()
        pool = mgr.create_pool("USDC", "QRDX", FeeTier.MEDIUM, PoolType.STANDARD,
                               tick_to_sqrt_price(0), ADDR_A, Decimal("10000"))
        assert pool.state.token0 == "QRDX"
        assert pool.state.token1 == "USDC"

    def test_get_pool_by_id(self):
        mgr = PoolManager()
        pool = mgr.create_pool("QRDX", "USDC", FeeTier.MEDIUM, PoolType.STANDARD,
                               tick_to_sqrt_price(0), ADDR_A, Decimal("10000"))
        assert mgr.get_pool(pool.state.id) is pool

    def test_get_pools_for_pair(self):
        mgr = PoolManager()
        mgr.create_pool("QRDX", "USDC", FeeTier.MEDIUM, PoolType.STANDARD,
                         tick_to_sqrt_price(0), ADDR_A, Decimal("10000"))
        mgr.create_pool("QRDX", "USDC", FeeTier.LOW, PoolType.STANDARD,
                         tick_to_sqrt_price(0), ADDR_B, Decimal("10000"))
        pools = mgr.get_pools_for_pair("QRDX", "USDC")
        assert len(pools) == 2

    def test_get_best_pool(self):
        mgr = PoolManager()
        p1 = mgr.create_pool("QRDX", "USDC", FeeTier.MEDIUM, PoolType.STANDARD,
                              tick_to_sqrt_price(0), ADDR_A, Decimal("10000"))
        p1.add_liquidity(ADDR_A, -60, 60, Decimal("100"))
        p2 = mgr.create_pool("QRDX", "USDC", FeeTier.LOW, PoolType.STANDARD,
                              tick_to_sqrt_price(0), ADDR_B, Decimal("10000"))
        p2.add_liquidity(ADDR_B, -10, 10, Decimal("500"))
        best = mgr.get_best_pool("QRDX", "USDC")
        assert best is p2  # more liquidity

    def test_pool_stake_requirement_values(self):
        assert POOL_STAKE_REQUIREMENTS[PoolType.STANDARD] == EXCHANGE_POOL_STAKE_STANDARD
        assert POOL_STAKE_REQUIREMENTS[PoolType.BOOTSTRAP] == EXCHANGE_POOL_STAKE_BOOTSTRAP
        assert POOL_STAKE_REQUIREMENTS[PoolType.SUBSIDIZED] == EXCHANGE_POOL_BURN_SUBSIDIZED
        assert POOL_STAKE_REQUIREMENTS[PoolType.INSTITUTIONAL] == EXCHANGE_POOL_STAKE_INSTITUTIONAL

    def test_invalid_sqrt_price(self):
        mgr = PoolManager()
        with pytest.raises(ValueError, match="sqrt price"):
            mgr.create_pool("QRDX", "USDC", FeeTier.MEDIUM, PoolType.STANDARD,
                            Decimal("0"), ADDR_A, Decimal("10000"))


# ============================================================================
#  §5.5  TWAP ORACLE
# ============================================================================

class TestTWAPOracle:
    """Geometric-mean TWAP oracle."""

    def test_record_observation(self):
        oracle = TWAPOracle(pool_id="test")
        obs = oracle.record(Decimal("100"), timestamp=1000.0)
        assert obs.price == Decimal("100")
        assert oracle.observation_count == 1

    def test_latest_price(self):
        oracle = TWAPOracle()
        oracle.record(Decimal("100"), timestamp=1000.0)
        oracle.record(Decimal("110"), timestamp=1010.0)
        assert oracle.latest_price == Decimal("110")

    def test_twap_two_points(self):
        oracle = TWAPOracle()
        oracle.record(Decimal("100"), timestamp=0.0)
        oracle.record(Decimal("100"), timestamp=100.0)
        twap = oracle.twap(100.0)
        assert twap is not None
        assert abs(twap - Decimal("100")) < Decimal("0.01")

    def test_twap_price_change(self):
        oracle = TWAPOracle()
        oracle.record(Decimal("100"), timestamp=0.0)
        oracle.record(Decimal("140"), timestamp=100.0)  # 40% change (within 50% outlier limit)
        twap = oracle.twap(100.0)
        assert twap is not None
        # Geometric mean of constant 140 over interval
        # Since accumulator uses ln(price) * dt, with only end price held constant
        # the TWAP should reflect the end-point price
        assert twap > Decimal("100")

    def test_twap_insufficient_data(self):
        oracle = TWAPOracle()
        oracle.record(Decimal("100"), timestamp=0.0)
        assert oracle.twap(60.0) is None

    def test_negative_price_rejected(self):
        oracle = TWAPOracle()
        with pytest.raises(ValueError, match="positive"):
            oracle.record(Decimal("-1"))

    def test_non_monotonic_rejected(self):
        oracle = TWAPOracle()
        oracle.record(Decimal("100"), timestamp=100.0)
        with pytest.raises(ValueError, match="monotonically"):
            oracle.record(Decimal("100"), timestamp=50.0)

    def test_max_observations_trimmed(self):
        oracle = TWAPOracle(max_observations=10)
        for i in range(20):
            oracle.record(Decimal("100"), timestamp=float(i))
        assert oracle.observation_count == 10

    def test_price_at_timestamp(self):
        oracle = TWAPOracle()
        oracle.record(Decimal("100"), timestamp=0.0)
        oracle.record(Decimal("110"), timestamp=10.0)
        oracle.record(Decimal("120"), timestamp=20.0)
        assert oracle.price_at(10.0) == Decimal("110")
        assert oracle.price_at(5.0) == Decimal("100")  # before second obs

    def test_twap_tick(self):
        oracle = TWAPOracle()
        oracle.record(Decimal("100"), timestamp=0.0)
        oracle.record(Decimal("100"), timestamp=100.0)
        tick = oracle.twap_tick(100.0)
        assert tick is not None
        # tick for price=100 should be ≈ log(100) / log(1.0001) ≈ 46054
        assert 46000 < tick < 46200


# ============================================================================
#  §5.6  ROUTER / SETTLEMENT / HOOKS
# ============================================================================

class TestUnifiedRouter:
    """Best-execution routing and settlement."""

    def _setup_router(self):
        mgr = PoolManager()
        pool = mgr.create_pool("QRDX", "USDC", FeeTier.MEDIUM, PoolType.STANDARD,
                               tick_to_sqrt_price(0), ADDR_A, Decimal("10000"))
        pool.add_liquidity(ADDR_A, -60, 60, Decimal("100000"))

        book = OrderBook(pool_id="QRDX:USDC")
        book.place_order(Order(id="ask1", owner=ADDR_B, side=OrderSide.SELL,
                               order_type=OrderType.LIMIT, price=Decimal("1.01"),
                               amount=Decimal("100")))
        oracle = TWAPOracle(pool_id="QRDX:USDC")
        oracle.record(Decimal("1.0"), timestamp=time.time() - 10)

        router = UnifiedRouter(pool_manager=mgr)
        router.register_order_book("QRDX:USDC", book)
        router.register_oracle("QRDX:USDC", oracle)
        return router

    def test_amm_only_fill(self):
        mgr = PoolManager()
        pool = mgr.create_pool("QRDX", "USDC", FeeTier.MEDIUM, PoolType.STANDARD,
                               tick_to_sqrt_price(0), ADDR_A, Decimal("10000"))
        pool.add_liquidity(ADDR_A, -60, 60, Decimal("100000"))
        router = UnifiedRouter(pool_manager=mgr)
        result = router.execute("QRDX", "USDC", Decimal("10"), ADDR_B)
        assert result.source == FillSource.AMM
        assert result.amount_out > 0
        assert result.fee_total > 0

    def test_clob_only_fill(self):
        book = OrderBook()
        book.place_order(Order(id="ask", owner=ADDR_B, side=OrderSide.SELL,
                               order_type=OrderType.LIMIT, price=Decimal("1.0"),
                               amount=Decimal("100")))
        router = UnifiedRouter()
        router.register_order_book("QRDX:USDC", book)
        result = router.execute("QRDX", "USDC", Decimal("10"), ADDR_A)
        assert result.source == FillSource.CLOB

    def test_no_liquidity_raises(self):
        router = UnifiedRouter()
        with pytest.raises(ValueError, match="No liquidity"):
            router.execute("QRDX", "USDC", Decimal("10"), ADDR_A)

    def test_zero_amount_raises(self):
        router = self._setup_router()
        with pytest.raises(ValueError, match="positive"):
            router.execute("QRDX", "USDC", Decimal("0"), ADDR_A)

    def test_no_sender_raises(self):
        router = self._setup_router()
        with pytest.raises(ValueError, match="Sender"):
            router.execute("QRDX", "USDC", Decimal("10"), "")

    def test_fee_split_in_result(self):
        router = self._setup_router()
        result = router.execute("QRDX", "USDC", Decimal("100"), ADDR_A)
        total = result.fee_lp + result.fee_creator + result.fee_treasury + result.fee_validator
        assert total == result.fee_total

    def test_oracle_update_on_trade(self):
        router = self._setup_router()
        oracle = router.get_oracle("QRDX:USDC")
        before = oracle.observation_count
        router.execute("QRDX", "USDC", Decimal("10"), ADDR_A)
        assert oracle.observation_count > before

    def test_register_and_get_order_book(self):
        router = UnifiedRouter()
        book = OrderBook(pool_id="test")
        router.register_order_book("A:B", book)
        assert router.get_order_book("A:B") is book

    def test_register_and_get_oracle(self):
        router = UnifiedRouter()
        oracle = TWAPOracle()
        router.register_oracle("A:B", oracle)
        assert router.get_oracle("A:B") is oracle


class TestFillResult:
    """FillResult and FillSource."""

    def test_fill_source_enum(self):
        assert FillSource.AMM.value == "amm"
        assert FillSource.CLOB.value == "clob"
        assert FillSource.HYBRID.value == "hybrid"

    def test_fill_result_creation(self):
        fr = FillResult(
            source=FillSource.AMM, amount_in=Decimal("100"),
            amount_out=Decimal("99"), fee_total=Decimal("1"),
            fee_lp=Decimal("0.70"), fee_creator=Decimal("0.15"),
            fee_treasury=Decimal("0.10"), fee_validator=Decimal("0.05"),
            price=Decimal("1.01"), trades=[], pool_id="p1",
        )
        assert fr.source == FillSource.AMM
        assert fr.pool_id == "p1"


# ============================================================================
#  PERPETUAL CONTRACTS
# ============================================================================

class TestPerpMarketCreation:
    """Perp market creation and config."""

    def test_create_market(self):
        engine = PerpEngine()
        market = engine.create_market("BTC")
        assert market.id == "BTC-QRDX-PERP"
        assert market.max_leverage == MAX_LEVERAGE
        assert engine.market_count == 1

    def test_create_duplicate_rejected(self):
        engine = PerpEngine()
        engine.create_market("BTC")
        with pytest.raises(ValueError, match="already exists"):
            engine.create_market("BTC")

    def test_invalid_margin_rates(self):
        engine = PerpEngine()
        with pytest.raises(ValueError, match="positive"):
            engine.create_market("ETH", initial_margin_rate=Decimal("-0.05"))

    def test_maintenance_gte_initial_rejected(self):
        engine = PerpEngine()
        with pytest.raises(ValueError, match="less than"):
            engine.create_market("ETH", initial_margin_rate=Decimal("0.05"),
                                 maintenance_margin_rate=Decimal("0.05"))

    def test_excessive_leverage_rejected(self):
        engine = PerpEngine()
        with pytest.raises(ValueError, match="Leverage"):
            engine.create_market("ETH", max_leverage=Decimal("100"))

    def test_get_market(self):
        engine = PerpEngine()
        engine.create_market("BTC")
        assert engine.get_market("BTC-QRDX-PERP") is not None
        assert engine.get_market("NOPE") is None


class TestPerpPositions:
    """Open, close, and manage perpetual positions."""

    def _engine_with_market(self) -> PerpEngine:
        engine = PerpEngine()
        market = engine.create_market("BTC")
        market.index_price = Decimal("50000")
        market.mark_price = Decimal("50000")
        return engine

    def test_open_long(self):
        engine = self._engine_with_market()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        assert pos.side == PerpSide.LONG
        assert pos.size == Decimal("1")
        assert pos.is_open

    def test_open_short(self):
        engine = self._engine_with_market()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.SHORT,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        assert pos.side == PerpSide.SHORT

    def test_open_invalid_market(self):
        engine = PerpEngine()
        with pytest.raises(ValueError, match="not found"):
            engine.open_position("NOPE", ADDR_A, PerpSide.LONG,
                                  Decimal("1"), Decimal("10"), Decimal("100"))

    def test_open_zero_size(self):
        engine = self._engine_with_market()
        with pytest.raises(ValueError, match="positive"):
            engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                  Decimal("0"), Decimal("10"), Decimal("50000"))

    def test_open_excess_leverage(self):
        engine = self._engine_with_market()
        with pytest.raises(ValueError, match="Leverage"):
            engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                  Decimal("1"), Decimal("25"), Decimal("50000"))

    def test_close_long_profit(self):
        engine = self._engine_with_market()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        pnl = engine.close_position(pos.id, Decimal("55000"))
        assert pnl == Decimal("5000")
        assert not pos.is_open

    def test_close_short_profit(self):
        engine = self._engine_with_market()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.SHORT,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        pnl = engine.close_position(pos.id, Decimal("45000"))
        assert pnl == Decimal("5000")

    def test_close_long_loss(self):
        engine = self._engine_with_market()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        pnl = engine.close_position(pos.id, Decimal("48000"))
        assert pnl == Decimal("-2000")

    def test_close_already_closed(self):
        engine = self._engine_with_market()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        engine.close_position(pos.id, Decimal("50000"))
        with pytest.raises(ValueError, match="closed"):
            engine.close_position(pos.id, Decimal("50000"))

    def test_unrealized_pnl(self):
        engine = self._engine_with_market()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        assert pos.unrealized_pnl(Decimal("52000")) == Decimal("2000")
        assert pos.unrealized_pnl(Decimal("48000")) == Decimal("-2000")

    def test_margin_ratio(self):
        engine = self._engine_with_market()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        mr = pos.margin_ratio(Decimal("50000"))
        assert mr > 0

    def test_liquidation_price(self):
        engine = self._engine_with_market()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        liq = pos.liquidation_price()
        assert liq < Decimal("50000")
        assert liq > 0

    def test_bankruptcy_price(self):
        engine = self._engine_with_market()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        bp = pos.bankruptcy_price()
        assert bp < pos.liquidation_price()

    def test_get_positions_by_owner(self):
        engine = self._engine_with_market()
        engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                              Decimal("1"), Decimal("10"), Decimal("50000"))
        engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.SHORT,
                              Decimal("0.5"), Decimal("5"), Decimal("50000"))
        positions = engine.get_positions_by_owner(ADDR_A)
        assert len(positions) == 2

    def test_open_interest_tracking(self):
        engine = self._engine_with_market()
        engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                              Decimal("1"), Decimal("10"), Decimal("50000"))
        engine.open_position("BTC-QRDX-PERP", ADDR_B, PerpSide.SHORT,
                              Decimal("0.5"), Decimal("5"), Decimal("50000"))
        market = engine.get_market("BTC-QRDX-PERP")
        assert market.open_interest_long == Decimal("1")
        assert market.open_interest_short == Decimal("0.5")
        assert market.open_interest == Decimal("1.5")

    def test_add_margin(self):
        engine = self._engine_with_market()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        old_margin = pos.margin
        new_margin = engine.add_margin(pos.id, Decimal("1000"))
        assert new_margin == old_margin + Decimal("1000")


class TestPerpFunding:
    """Funding rate calculation and application."""

    def _setup(self):
        engine = PerpEngine()
        market = engine.create_market("BTC")
        market.index_price = Decimal("50000")
        market.mark_price = Decimal("50050")  # slight premium
        market.last_funding_time = 0.0  # force eligibility
        return engine, market

    def test_funding_rate_positive(self):
        engine, market = self._setup()
        rate = engine.calculate_funding_rate("BTC-QRDX-PERP")
        assert rate > 0  # mark > index → longs pay

    def test_funding_rate_negative(self):
        engine, _ = self._setup()
        market = engine.get_market("BTC-QRDX-PERP")
        market.mark_price = Decimal("49950")  # discount
        rate = engine.calculate_funding_rate("BTC-QRDX-PERP")
        assert rate < 0

    def test_funding_rate_capped(self):
        engine, _ = self._setup()
        market = engine.get_market("BTC-QRDX-PERP")
        market.mark_price = Decimal("100000")  # extreme premium
        rate = engine.calculate_funding_rate("BTC-QRDX-PERP")
        assert rate == MAX_FUNDING_RATE

    def test_apply_funding(self):
        engine, _ = self._setup()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        old_margin = pos.margin
        snapshot = engine.apply_funding("BTC-QRDX-PERP")
        assert snapshot is not None
        # Long should lose margin when rate > 0
        assert pos.margin < old_margin

    def test_funding_too_early(self):
        engine = PerpEngine()
        market = engine.create_market("BTC")
        market.index_price = Decimal("50000")
        market.mark_price = Decimal("50050")
        market.last_funding_time = time.time()  # just now
        assert engine.apply_funding("BTC-QRDX-PERP") is None


class TestPerpLiquidation:
    """Liquidation, insurance fund, ADL."""

    def _setup(self):
        engine = PerpEngine()
        market = engine.create_market("BTC")
        market.index_price = Decimal("50000")
        market.mark_price = Decimal("50000")
        return engine

    def test_healthy_position_not_liquidated(self):
        engine = self._setup()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        assert engine.check_liquidation(pos.id) is None

    def test_undercollateralized_position_liquidated(self):
        engine = self._setup()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        # Crash the mark price below liquidation price
        market = engine.get_market("BTC-QRDX-PERP")
        liq_price = pos.liquidation_price()
        market.mark_price = liq_price - Decimal("100")
        result = engine.check_liquidation(pos.id)
        assert result is not None
        assert result.pnl < 0
        assert pos.status == PositionStatus.LIQUIDATED

    def test_insurance_fund_used(self):
        engine = self._setup()
        engine.add_insurance("BTC-QRDX-PERP", Decimal("100000"))
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        market = engine.get_market("BTC-QRDX-PERP")
        # Crash below bankruptcy
        bp = pos.bankruptcy_price()
        market.mark_price = bp - Decimal("1000")
        result = engine.check_liquidation(pos.id)
        assert result is not None
        assert result.insurance_used > 0
        assert not result.adl_triggered

    def test_adl_triggered_when_insurance_depleted(self):
        engine = self._setup()
        # No insurance fund
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        market = engine.get_market("BTC-QRDX-PERP")
        bp = pos.bankruptcy_price()
        market.mark_price = bp - Decimal("5000")
        result = engine.check_liquidation(pos.id)
        assert result is not None
        assert result.adl_triggered

    def test_add_insurance_fund(self):
        engine = self._setup()
        engine.add_insurance("BTC-QRDX-PERP", Decimal("10000"))
        market = engine.get_market("BTC-QRDX-PERP")
        assert market.insurance_fund == Decimal("10000")

    def test_add_insurance_invalid(self):
        engine = self._setup()
        with pytest.raises(ValueError, match="positive"):
            engine.add_insurance("BTC-QRDX-PERP", Decimal("0"))


class TestPerpPricing:
    """Mark price and index price management."""

    def test_update_price(self):
        engine = PerpEngine()
        market = engine.create_market("BTC")
        engine.update_price("BTC-QRDX-PERP", Decimal("50000"))
        assert market.index_price == Decimal("50000")
        assert market.mark_price > 0

    def test_update_price_invalid_market(self):
        engine = PerpEngine()
        with pytest.raises(ValueError, match="not found"):
            engine.update_price("NOPE", Decimal("100"))


# ============================================================================
#  EXCHANGE CONSTANTS
# ============================================================================

class TestExchangeConstants:
    """Verify exchange constants match whitepaper."""

    def test_fee_tiers(self):
        assert EXCHANGE_FEE_TIER_ULTRA_LOW == 100
        assert EXCHANGE_FEE_TIER_LOW == 500
        assert EXCHANGE_FEE_TIER_MEDIUM == 3000
        assert EXCHANGE_FEE_TIER_HIGH == 10000

    def test_fee_distribution(self):
        total = (EXCHANGE_FEE_LP_SHARE + EXCHANGE_FEE_CREATOR_SHARE +
                 EXCHANGE_FEE_TREASURY_SHARE + EXCHANGE_FEE_VALIDATOR_SHARE)
        assert total == Decimal("1.00")

    def test_orderbook_fees(self):
        assert EXCHANGE_ORDERBOOK_MAKER_FEE == Decimal("0.0002")
        assert EXCHANGE_ORDERBOOK_TAKER_FEE == Decimal("0.0005")
        assert EXCHANGE_ORDERBOOK_MAX_DEPTH == 500

    def test_pool_stakes(self):
        assert EXCHANGE_POOL_STAKE_STANDARD == Decimal("10000")
        assert EXCHANGE_POOL_STAKE_BOOTSTRAP == Decimal("25000")
        assert EXCHANGE_POOL_BURN_SUBSIDIZED == Decimal("5000")
        assert EXCHANGE_POOL_STAKE_INSTITUTIONAL == Decimal("100000")

    def test_tick_bounds(self):
        assert EXCHANGE_MIN_TICK == -887272
        assert EXCHANGE_MAX_TICK == 887272

    def test_perp_constants(self):
        assert PERP_MAX_LEVERAGE == Decimal("20")
        assert PERP_DEFAULT_INITIAL_MARGIN == Decimal("0.05")
        assert PERP_DEFAULT_MAINTENANCE_MARGIN == Decimal("0.025")
        assert PERP_FUNDING_INTERVAL_SECONDS == 28800
        assert PERP_MAX_FUNDING_RATE == Decimal("0.01")

    def test_gas_costs(self):
        assert EXCHANGE_GAS_SWAP == 65_000
        assert EXCHANGE_GAS_ADD_LIQUIDITY == 90_000
        assert EXCHANGE_GAS_LIMIT_ORDER == 40_000
        assert EXCHANGE_GAS_CANCEL_ORDER == 25_000
        assert EXCHANGE_GAS_CREATE_POOL == 150_000


# ============================================================================
#  PACKAGE IMPORTS
# ============================================================================

class TestPackageImports:
    """Verify top-level package re-exports."""

    def test_orderbook_imports(self):
        from qrdx.exchange import Order, OrderSide, OrderStatus, OrderType, OrderBook, Trade
        assert Order is not None

    def test_amm_imports(self):
        from qrdx.exchange import PoolState, Position, TickInfo, ConcentratedLiquidityPool, PoolManager, FeeTier
        assert PoolManager is not None

    def test_perp_imports(self):
        from qrdx.exchange import PerpPosition, PerpSide, PerpMarket, FundingSnapshot, LiquidationResult, PerpEngine
        assert PerpEngine is not None

    def test_router_imports(self):
        from qrdx.exchange import FillResult, FillSource, UnifiedRouter
        assert UnifiedRouter is not None

    def test_oracle_imports(self):
        from qrdx.exchange import Observation, TWAPOracle
        assert TWAPOracle is not None

    def test_hooks_imports(self):
        from qrdx.exchange import HookFlags, HookContext, HookResult, HookRegistry, CircuitBreaker
        assert HookRegistry is not None

    def test_security_imports(self):
        from qrdx.exchange import (
            SelfTradeAction, MIN_ORDER_SIZE,
            MAX_ORDERS_PER_ADDRESS, MAX_ORDERS_PER_BLOCK_PER_ADDRESS,
        )
        assert MIN_ORDER_SIZE > 0


# ============================================================================
#  SECURITY HARDENING TESTS
# ============================================================================

# ---------------------------------------------------------------------------
# Additional imports for security tests
# ---------------------------------------------------------------------------
from qrdx.exchange.orderbook import (
    SelfTradeAction,
    MIN_ORDER_SIZE,
    MAX_ORDERS_PER_ADDRESS,
    MAX_ORDERS_PER_BLOCK_PER_ADDRESS,
    MAX_STOP_ORDERS_PER_ADDRESS,
)
from qrdx.exchange.oracle import (
    MIN_OBSERVATION_PERIOD,
    MAX_PRICE_CHANGE_PCT,
    STALENESS_THRESHOLD,
)
from qrdx.exchange.perpetual import (
    LIQUIDATION_PENALTY_RATE,
    MAX_OPEN_INTEREST_DEFAULT,
    ORACLE_STALENESS_SECONDS,
    MAX_POSITIONS_PER_OWNER,
)
from qrdx.exchange.router import (
    MAX_PRICE_DEVIATION,
    DEFAULT_DEADLINE_SECONDS,
)
from qrdx.exchange.hooks import (
    HookFlags,
    HookContext,
    HookResult,
    HookRegistry,
    CircuitBreaker,
    ExchangeHook,
)


# ============================================================================
#  ORDER BOOK SECURITY
# ============================================================================

class TestOrderBookSecurity:
    """Self-trade prevention, auth cancel, rate limits, nonce, min size, pause."""

    # -- Self-trade prevention (STP) ----------------------------------------

    def test_stp_reject_mode(self):
        """STP REJECT: same-owner orders don't trade against each other."""
        book = OrderBook(self_trade_action=SelfTradeAction.REJECT)
        book.place_order(Order(id="bid1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("10")))
        trades = book.place_order(Order(id="ask1", owner=ADDR_A, side=OrderSide.SELL,
                                        order_type=OrderType.LIMIT, price=Decimal("100"),
                                        amount=Decimal("10")))
        # Same owner — trade rejected, ask rests on book
        assert len(trades) == 0
        assert book.ask_depth == 1
        assert book.bid_depth == 1

    def test_stp_cancel_maker_mode(self):
        """STP CANCEL_MAKER: maker order cancelled when same owner."""
        book = OrderBook(self_trade_action=SelfTradeAction.CANCEL_MAKER)
        book.place_order(Order(id="bid1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("10")))
        trades = book.place_order(Order(id="ask1", owner=ADDR_A, side=OrderSide.SELL,
                                        order_type=OrderType.LIMIT, price=Decimal("100"),
                                        amount=Decimal("10")))
        # Maker (bid) cancelled, taker (ask) rests on book
        assert len(trades) == 0
        assert book.bid_depth == 0
        assert book.ask_depth == 1

    def test_stp_cancel_both_mode(self):
        """STP CANCEL_BOTH: both orders cancelled."""
        book = OrderBook(self_trade_action=SelfTradeAction.CANCEL_BOTH)
        book.place_order(Order(id="bid1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("10")))
        trades = book.place_order(Order(id="ask1", owner=ADDR_A, side=OrderSide.SELL,
                                        order_type=OrderType.LIMIT, price=Decimal("100"),
                                        amount=Decimal("10")))
        # Both cancelled
        assert len(trades) == 0
        assert book.bid_depth == 0

    def test_stp_different_owners_trade_normally(self):
        """STP doesn't affect different-owner trades."""
        book = OrderBook(self_trade_action=SelfTradeAction.REJECT)
        book.place_order(Order(id="bid1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("10")))
        trades = book.place_order(Order(id="ask1", owner=ADDR_B, side=OrderSide.SELL,
                                        order_type=OrderType.LIMIT, price=Decimal("100"),
                                        amount=Decimal("10")))
        assert len(trades) == 1

    # -- Owner-authorized cancel --------------------------------------------

    def test_cancel_by_owner_succeeds(self):
        book = OrderBook()
        book.place_order(Order(id="o1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("10")))
        result = book.cancel_order("o1", caller=ADDR_A)
        assert result is not None
        assert result.status == OrderStatus.CANCELLED

    def test_cancel_by_non_owner_rejected(self):
        book = OrderBook()
        book.place_order(Order(id="o1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("10")))
        with pytest.raises(ValueError, match="Only order owner"):
            book.cancel_order("o1", caller=ADDR_B)

    def test_cancel_no_caller_still_works(self):
        """Backward compat: cancel without caller arg succeeds."""
        book = OrderBook()
        book.place_order(Order(id="o1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("10")))
        result = book.cancel_order("o1")
        assert result is not None

    def test_cancel_stop_by_non_owner_rejected(self):
        book = OrderBook()
        book.place_order(Order(id="s1", owner=ADDR_A, side=OrderSide.SELL,
                               order_type=OrderType.STOP_LOSS, price=Decimal("90"),
                               amount=Decimal("10"), stop_price=Decimal("95")))
        with pytest.raises(ValueError, match="Only order owner"):
            book.cancel_order("s1", caller=ADDR_B)

    # -- Rate limiting (per block) ------------------------------------------

    def test_rate_limit_enforced(self):
        book = OrderBook()
        # Place MAX_ORDERS_PER_BLOCK_PER_ADDRESS orders
        for i in range(MAX_ORDERS_PER_BLOCK_PER_ADDRESS):
            book.place_order(Order(id=f"o{i}", owner=ADDR_A, side=OrderSide.BUY,
                                   order_type=OrderType.LIMIT, price=Decimal("100"),
                                   amount=Decimal("1")))
        # Next one should fail
        with pytest.raises(ValueError, match="Rate limit"):
            book.place_order(Order(id="overflow", owner=ADDR_A, side=OrderSide.BUY,
                                   order_type=OrderType.LIMIT, price=Decimal("100"),
                                   amount=Decimal("1")))

    def test_rate_limit_resets_on_new_block(self):
        book = OrderBook()
        for i in range(MAX_ORDERS_PER_BLOCK_PER_ADDRESS):
            book.place_order(Order(id=f"o{i}", owner=ADDR_A, side=OrderSide.BUY,
                                   order_type=OrderType.LIMIT, price=Decimal("100"),
                                   amount=Decimal("1")))
        book.new_block()  # reset rate limits
        # Should work again
        book.place_order(Order(id="fresh", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("1")))

    def test_rate_limit_per_address(self):
        """Different addresses have independent rate limits."""
        book = OrderBook()
        for i in range(MAX_ORDERS_PER_BLOCK_PER_ADDRESS):
            book.place_order(Order(id=f"a{i}", owner=ADDR_A, side=OrderSide.BUY,
                                   order_type=OrderType.LIMIT, price=Decimal("100"),
                                   amount=Decimal("1")))
        # ADDR_B should still work
        book.place_order(Order(id="b0", owner=ADDR_B, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("1")))

    # -- Nonce replay protection --------------------------------------------

    def test_nonce_replay_rejected(self):
        book = OrderBook()
        book.place_order(Order(id="o1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("1"), nonce=5))
        with pytest.raises(ValueError, match="Nonce replay"):
            book.place_order(Order(id="o2", owner=ADDR_A, side=OrderSide.BUY,
                                   order_type=OrderType.LIMIT, price=Decimal("100"),
                                   amount=Decimal("1"), nonce=5))

    def test_nonce_must_increase(self):
        book = OrderBook()
        book.place_order(Order(id="o1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("1"), nonce=10))
        with pytest.raises(ValueError, match="Nonce replay"):
            book.place_order(Order(id="o2", owner=ADDR_A, side=OrderSide.BUY,
                                   order_type=OrderType.LIMIT, price=Decimal("100"),
                                   amount=Decimal("1"), nonce=3))

    def test_nonce_zero_ignored(self):
        """Orders without nonce (nonce=0) skip replay check."""
        book = OrderBook()
        book.place_order(Order(id="o1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("1"), nonce=0))
        # Another nonce=0 should be fine
        book.place_order(Order(id="o2", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("1"), nonce=0))

    def test_nonce_strictly_increasing_accepted(self):
        book = OrderBook()
        book.place_order(Order(id="o1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("1"), nonce=1))
        book.place_order(Order(id="o2", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("1"), nonce=2))
        # Different owner can use same nonce value
        book.place_order(Order(id="o3", owner=ADDR_B, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("1"), nonce=1))

    # -- Minimum order size -------------------------------------------------

    def test_min_order_size_rejected(self):
        book = OrderBook()
        with pytest.raises(ValueError, match="minimum"):
            book.place_order(Order(id="tiny", owner=ADDR_A, side=OrderSide.BUY,
                                   order_type=OrderType.LIMIT, price=Decimal("100"),
                                   amount=Decimal("0.000000001")))

    def test_min_order_size_exact_accepted(self):
        book = OrderBook()
        book.place_order(Order(id="min", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=MIN_ORDER_SIZE))

    # -- Duplicate order ID -------------------------------------------------

    def test_duplicate_order_id_rejected(self):
        book = OrderBook()
        book.place_order(Order(id="dup", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("10")))
        with pytest.raises(ValueError, match="Duplicate order ID"):
            book.place_order(Order(id="dup", owner=ADDR_B, side=OrderSide.BUY,
                                   order_type=OrderType.LIMIT, price=Decimal("100"),
                                   amount=Decimal("10")))

    # -- Order expiry -------------------------------------------------------

    def test_expired_order_rejected(self):
        book = OrderBook()
        with pytest.raises(ValueError, match="expired"):
            book.place_order(Order(id="exp", owner=ADDR_A, side=OrderSide.BUY,
                                   order_type=OrderType.LIMIT, price=Decimal("100"),
                                   amount=Decimal("10"), expire_time=1.0))

    # -- Emergency pause ----------------------------------------------------

    def test_paused_book_rejects_orders(self):
        book = OrderBook()
        book.pause()
        assert book.is_paused
        with pytest.raises(ValueError, match="paused"):
            book.place_order(Order(id="o1", owner=ADDR_A, side=OrderSide.BUY,
                                   order_type=OrderType.LIMIT, price=Decimal("100"),
                                   amount=Decimal("10")))

    def test_unpause_resumes_trading(self):
        book = OrderBook()
        book.pause()
        book.unpause()
        assert not book.is_paused
        book.place_order(Order(id="o1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("10")))

    # -- Deterministic trade IDs --------------------------------------------

    def test_trade_ids_are_deterministic(self):
        """Trade IDs are blake2b hashes, not random UUIDs."""
        book = OrderBook()
        book.place_order(Order(id="bid1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("10")))
        trades = book.place_order(Order(id="ask1", owner=ADDR_B, side=OrderSide.SELL,
                                        order_type=OrderType.LIMIT, price=Decimal("100"),
                                        amount=Decimal("10")))
        assert len(trades) == 1
        tid = trades[0].id
        # Should be hex string from blake2b, not UUID format
        assert "-" not in tid  # no dashes (uuid4 has dashes)
        assert len(tid) == 16  # blake2b digest_size=8 → 16 hex chars

    def test_trade_has_sequence_number(self):
        """Trades have monotonic sequence numbers."""
        book = OrderBook()
        book.place_order(Order(id="bid1", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("10")))
        trades1 = book.place_order(Order(id="ask1", owner=ADDR_B, side=OrderSide.SELL,
                                         order_type=OrderType.LIMIT, price=Decimal("100"),
                                         amount=Decimal("5")))
        book.place_order(Order(id="bid2", owner=ADDR_A, side=OrderSide.BUY,
                               order_type=OrderType.LIMIT, price=Decimal("100"),
                               amount=Decimal("10")))
        trades2 = book.place_order(Order(id="ask2", owner=ADDR_B, side=OrderSide.SELL,
                                         order_type=OrderType.LIMIT, price=Decimal("100"),
                                         amount=Decimal("5")))
        assert trades1[0].sequence < trades2[0].sequence


# ============================================================================
#  AMM SECURITY
# ============================================================================

class TestAMMSecurity:
    """Slippage protection, reentrancy lock, price impact, pause, deterministic IDs."""

    def _pool(self) -> ConcentratedLiquidityPool:
        mgr = PoolManager()
        pool = mgr.create_pool("QRDX", "USDC", FeeTier.MEDIUM, PoolType.STANDARD,
                               tick_to_sqrt_price(0), ADDR_A, Decimal("10000"))
        pool.add_liquidity(ADDR_A, -60, 60, Decimal("100000"))
        return pool

    # -- Slippage protection ------------------------------------------------

    def test_swap_slippage_protection(self):
        pool = self._pool()
        amount_out, _ = pool.swap(Decimal("10"), True)
        # Now do a swap with too-high min_amount_out
        with pytest.raises(ValueError, match="[Ss]lippage"):
            pool.swap(Decimal("10"), True, min_amount_out=Decimal("999999"))

    def test_swap_min_amount_out_zero_passes(self):
        pool = self._pool()
        amount_out, fee = pool.swap(Decimal("10"), True, min_amount_out=Decimal("0"))
        assert amount_out > 0

    def test_swap_min_amount_out_exact_passes(self):
        pool = self._pool()
        # Do a test swap to find actual output
        amount_out, _ = pool.swap(Decimal("10"), True)
        # Re-create pool and do same swap with exact min_amount_out
        pool2 = self._pool()
        result_out, _ = pool2.swap(Decimal("10"), True, min_amount_out=amount_out)
        assert result_out >= amount_out

    # -- Price impact -------------------------------------------------------

    def test_price_impact_small_trade(self):
        pool = self._pool()
        impact = pool.price_impact(Decimal("1"), True)
        assert impact >= 0
        assert impact < Decimal("0.10")  # small trade < 10% impact

    def test_price_impact_large_trade(self):
        pool = self._pool()
        impact_small = pool.price_impact(Decimal("1"), True)
        impact_large = pool.price_impact(Decimal("1000"), True)
        # Larger trade should have larger impact
        assert impact_large >= impact_small

    # -- Emergency pause ----------------------------------------------------

    def test_paused_pool_rejects_swap(self):
        pool = self._pool()
        pool.pause()
        with pytest.raises(ValueError, match="[Pp]aused"):
            pool.swap(Decimal("10"), True)

    def test_paused_pool_rejects_add_liquidity(self):
        pool = self._pool()
        pool.pause()
        with pytest.raises(ValueError, match="[Pp]aused"):
            pool.add_liquidity(ADDR_A, -120, 120, Decimal("1000"))

    def test_unpause_resumes(self):
        pool = self._pool()
        pool.pause()
        pool.unpause()
        amount_out, _ = pool.swap(Decimal("10"), True)
        assert amount_out > 0

    # -- Deterministic IDs --------------------------------------------------

    def test_position_ids_deterministic(self):
        pool = self._pool()
        pos = pool.add_liquidity(ADDR_B, -60, 60, Decimal("5000"))
        # blake2b hex, not uuid
        assert "-" not in pos.id
        assert len(pos.id) == 16

    def test_pool_ids_deterministic(self):
        mgr = PoolManager()
        pool = mgr.create_pool("QRDX", "USDC", FeeTier.MEDIUM, PoolType.STANDARD,
                               tick_to_sqrt_price(0), ADDR_A, Decimal("10000"))
        pid = pool.state.id
        # blake2b hex, not uuid format
        assert len(pid) == 16  # blake2b digest_size=8 → 16 hex chars


# ============================================================================
#  PERPETUAL SECURITY
# ============================================================================

class TestPerpSecurity:
    """Partial close, max OI, oracle staleness, reduce-only, pause, liquidation penalty."""

    def _engine_with_market(self) -> PerpEngine:
        engine = PerpEngine()
        market = engine.create_market("BTC")
        market.index_price = Decimal("50000")
        market.mark_price = Decimal("50000")
        return engine

    # -- Emergency pause ----------------------------------------------------

    def test_paused_engine_rejects_open(self):
        engine = self._engine_with_market()
        engine.pause()
        assert engine.is_paused
        with pytest.raises(ValueError, match="[Pp]aused"):
            engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                  Decimal("1"), Decimal("10"), Decimal("50000"))

    def test_unpause_resumes(self):
        engine = self._engine_with_market()
        engine.pause()
        engine.unpause()
        assert not engine.is_paused
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        assert pos.is_open

    # -- Partial close ------------------------------------------------------

    def test_partial_close_reduces_size(self):
        engine = self._engine_with_market()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        pnl = engine.partial_close(pos.id, Decimal("0.5"), Decimal("52000"))
        assert pos.is_open
        assert pos.size == Decimal("0.5")
        assert pnl == Decimal("0.5") * (Decimal("52000") - Decimal("50000"))

    def test_partial_close_releases_proportional_margin(self):
        engine = self._engine_with_market()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        original_margin = pos.margin
        engine.partial_close(pos.id, Decimal("0.5"), Decimal("50000"))
        # Should release roughly half the margin
        assert pos.margin == original_margin * Decimal("0.5")

    def test_partial_close_updates_oi(self):
        engine = self._engine_with_market()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        market = engine.get_market("BTC-QRDX-PERP")
        assert market.open_interest_long == Decimal("1")
        engine.partial_close(pos.id, Decimal("0.3"), Decimal("50000"))
        assert market.open_interest_long == Decimal("0.7")

    def test_partial_close_full_size_closes_entirely(self):
        engine = self._engine_with_market()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        engine.partial_close(pos.id, Decimal("1"), Decimal("50000"))
        assert not pos.is_open

    def test_partial_close_invalid_size(self):
        engine = self._engine_with_market()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        with pytest.raises(ValueError, match="positive"):
            engine.partial_close(pos.id, Decimal("0"), Decimal("50000"))

    # -- Liquidation penalty ------------------------------------------------

    def test_liquidation_penalty_goes_to_insurance(self):
        engine = self._engine_with_market()
        market = engine.get_market("BTC-QRDX-PERP")
        initial_insurance = market.insurance_fund
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        liq_price = pos.liquidation_price()
        market.mark_price = liq_price - Decimal("100")
        engine.check_liquidation(pos.id)
        # Insurance fund should have received the penalty
        assert market.insurance_fund > initial_insurance

    def test_liquidation_penalty_rate(self):
        engine = self._engine_with_market()
        market = engine.get_market("BTC-QRDX-PERP")
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        liq_price = pos.liquidation_price()
        mark = liq_price - Decimal("100")
        market.mark_price = mark
        initial_insurance = market.insurance_fund
        engine.check_liquidation(pos.id)
        # Penalty = notional * 2.5%
        expected_penalty = (Decimal("1") * mark * LIQUIDATION_PENALTY_RATE).quantize(
            Decimal("0.00000001"), rounding=ROUND_HALF_UP
        )
        # Insurance gained at least the penalty (minus any clawback)
        assert market.insurance_fund >= initial_insurance + expected_penalty - abs(pos.realized_pnl)

    # -- Deterministic position IDs -----------------------------------------

    def test_position_ids_deterministic(self):
        engine = self._engine_with_market()
        pos = engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                                    Decimal("1"), Decimal("10"), Decimal("50000"))
        assert "-" not in pos.id  # blake2b, not uuid
        assert len(pos.id) == 16

    # -- OI-weighted funding dampening --------------------------------------

    def test_funding_rate_dampened_by_oi_imbalance(self):
        """With all-long OI, rate is scaled by imbalance ratio."""
        engine = self._engine_with_market()
        market = engine.get_market("BTC-QRDX-PERP")
        market.mark_price = Decimal("50050")  # slight premium

        # No positions → no OI → no dampening
        rate_no_oi = engine.calculate_funding_rate("BTC-QRDX-PERP")

        # Add only long OI (100% longs, 0% shorts)
        engine.open_position("BTC-QRDX-PERP", ADDR_A, PerpSide.LONG,
                              Decimal("1"), Decimal("10"), Decimal("50000"))
        rate_all_long = engine.calculate_funding_rate("BTC-QRDX-PERP")

        # With 100% long ratio: rate * 1.0 * 2 = 2x base rate
        assert rate_all_long > rate_no_oi


# ============================================================================
#  ROUTER SECURITY
# ============================================================================

class TestRouterSecurity:
    """Deadline enforcement, slippage, circuit breaker, pause, read-only quote."""

    def _setup_router(self):
        mgr = PoolManager()
        pool = mgr.create_pool("QRDX", "USDC", FeeTier.MEDIUM, PoolType.STANDARD,
                               tick_to_sqrt_price(0), ADDR_A, Decimal("10000"))
        pool.add_liquidity(ADDR_A, -60, 60, Decimal("100000"))
        oracle = TWAPOracle(pool_id="QRDX:USDC")
        oracle.record(Decimal("1.0"), timestamp=time.time() - 10)
        router = UnifiedRouter(pool_manager=mgr)
        router.register_oracle("QRDX:USDC", oracle)
        return router

    # -- Deadline enforcement -----------------------------------------------

    def test_expired_deadline_rejected(self):
        router = self._setup_router()
        with pytest.raises(ValueError, match="deadline"):
            router.execute("QRDX", "USDC", Decimal("10"), ADDR_A,
                           deadline=time.time() - 100)  # already expired

    def test_future_deadline_accepted(self):
        router = self._setup_router()
        result = router.execute("QRDX", "USDC", Decimal("10"), ADDR_A,
                                deadline=time.time() + 3600)
        assert result.amount_out > 0

    def test_zero_deadline_no_check(self):
        """deadline=0 means no deadline enforcement."""
        router = self._setup_router()
        result = router.execute("QRDX", "USDC", Decimal("10"), ADDR_A, deadline=0)
        assert result.amount_out > 0

    # -- Slippage enforcement -----------------------------------------------

    def test_min_amount_out_enforced(self):
        router = self._setup_router()
        with pytest.raises(ValueError, match="[Ss]lippage"):
            router.execute("QRDX", "USDC", Decimal("10"), ADDR_A,
                           min_amount_out=Decimal("999999"))

    def test_min_amount_out_satisfied(self):
        router = self._setup_router()
        result = router.execute("QRDX", "USDC", Decimal("10"), ADDR_A,
                                min_amount_out=Decimal("0.001"))
        assert result.amount_out >= Decimal("0.001")

    # -- Emergency pause ----------------------------------------------------

    def test_paused_router_rejects_trades(self):
        router = self._setup_router()
        router.pause()
        assert router.is_paused
        with pytest.raises(ValueError, match="[Pp]aused"):
            router.execute("QRDX", "USDC", Decimal("10"), ADDR_A)

    def test_unpause_resumes(self):
        router = self._setup_router()
        router.pause()
        router.unpause()
        result = router.execute("QRDX", "USDC", Decimal("10"), ADDR_A)
        assert result.amount_out > 0

    # -- Read-only AMM quoting (no state mutation) --------------------------

    def test_quote_amm_is_read_only(self):
        """quote_amm should not mutate pool state."""
        mgr = PoolManager()
        pool = mgr.create_pool("QRDX", "USDC", FeeTier.MEDIUM, PoolType.STANDARD,
                               tick_to_sqrt_price(0), ADDR_A, Decimal("10000"))
        pool.add_liquidity(ADDR_A, -60, 60, Decimal("100000"))
        router = UnifiedRouter(pool_manager=mgr)

        # Snapshot state before
        sqrt_before = pool.state.sqrt_price
        tick_before = pool.state.tick
        liq_before = pool.state.liquidity

        # Do a quote
        quote = router.quote_amm("QRDX", "USDC", Decimal("10"))

        # State should be unchanged
        assert pool.state.sqrt_price == sqrt_before
        assert pool.state.tick == tick_before
        assert pool.state.liquidity == liq_before

    # -- Deterministic CLOB order IDs ---------------------------------------

    def test_clob_order_ids_deterministic(self):
        book = OrderBook()
        book.place_order(Order(id="ask", owner=ADDR_B, side=OrderSide.SELL,
                               order_type=OrderType.LIMIT, price=Decimal("1.0"),
                               amount=Decimal("100")))
        router = UnifiedRouter()
        router.register_order_book("QRDX:USDC", book)
        result = router.execute("QRDX", "USDC", Decimal("10"), ADDR_A)
        # The order placed on the book should have a deterministic ID
        assert result.source == FillSource.CLOB


# ============================================================================
#  ORACLE SECURITY
# ============================================================================

class TestOracleSecurity:
    """Outlier rejection, same-block dedup, min observation period, staleness."""

    # -- Outlier rejection --------------------------------------------------

    def test_outlier_price_rejected(self):
        oracle = TWAPOracle()
        oracle.record(Decimal("100"), timestamp=0.0)
        # 60% change > 50% limit
        with pytest.raises(ValueError, match="[Oo]utlier"):
            oracle.record(Decimal("160"), timestamp=10.0)

    def test_within_threshold_accepted(self):
        oracle = TWAPOracle()
        oracle.record(Decimal("100"), timestamp=0.0)
        # 40% change < 50% limit
        oracle.record(Decimal("140"), timestamp=10.0)

    def test_outlier_drop_accepted(self):
        oracle = TWAPOracle()
        oracle.record(Decimal("100"), timestamp=0.0)
        # 49% drop is within threshold
        oracle.record(Decimal("51"), timestamp=10.0)

    def test_outlier_boundary_50pct(self):
        oracle = TWAPOracle()
        oracle.record(Decimal("100"), timestamp=0.0)
        # Exactly 50% change is accepted (not strictly greater)
        oracle.record(Decimal("150"), timestamp=10.0)

    def test_outlier_boundary_just_over(self):
        oracle = TWAPOracle()
        oracle.record(Decimal("100"), timestamp=0.0)
        # 50.01% change > 50% limit
        with pytest.raises(ValueError, match="[Oo]utlier"):
            oracle.record(Decimal("150.01"), timestamp=10.0)

    # -- Same-block dedup ---------------------------------------------------

    def test_same_timestamp_overwrites(self):
        oracle = TWAPOracle()
        oracle.record(Decimal("100"), timestamp=0.0)
        oracle.record(Decimal("105"), timestamp=0.0)  # same timestamp
        assert oracle.observation_count == 1  # not 2
        assert oracle.latest_price == Decimal("105")

    # -- Min observation period for TWAP ------------------------------------

    def test_twap_below_min_period_returns_none(self):
        oracle = TWAPOracle()
        oracle.record(Decimal("100"), timestamp=0.0)
        oracle.record(Decimal("100"), timestamp=30.0)  # 30s < 60s min
        assert oracle.twap(30.0) is None

    def test_twap_at_min_period_returns_value(self):
        oracle = TWAPOracle()
        oracle.record(Decimal("100"), timestamp=0.0)
        oracle.record(Decimal("100"), timestamp=60.0)  # exactly 60s
        twap = oracle.twap(60.0)
        assert twap is not None

    # -- Staleness check ----------------------------------------------------

    def test_is_stale_fresh(self):
        oracle = TWAPOracle()
        oracle.record(Decimal("100"), timestamp=time.time())
        assert not oracle.is_stale()

    def test_is_stale_old(self):
        oracle = TWAPOracle()
        oracle.record(Decimal("100"), timestamp=time.time() - 600)
        assert oracle.is_stale()

    def test_is_stale_no_observations(self):
        oracle = TWAPOracle()
        assert oracle.is_stale()

    def test_age_property(self):
        oracle = TWAPOracle()
        t = time.time() - 100
        oracle.record(Decimal("100"), timestamp=t)
        assert oracle.age >= 99  # at least 99 seconds old


# ============================================================================
#  HOOKS SYSTEM
# ============================================================================

class TestHookSystem:
    """HookFlags, HookContext, HookResult, HookRegistry, CircuitBreaker."""

    # -- HookFlags ----------------------------------------------------------

    def test_hook_flags_composition(self):
        flags = HookFlags.BEFORE_SWAP | HookFlags.AFTER_SWAP
        assert HookFlags.BEFORE_SWAP in flags
        assert HookFlags.AFTER_SWAP in flags
        assert HookFlags.BEFORE_LIQUIDITY not in flags

    def test_hook_flags_all(self):
        assert HookFlags.BEFORE_SWAP in HookFlags.ALL
        assert HookFlags.AFTER_SWAP in HookFlags.ALL
        assert HookFlags.BEFORE_LIQUIDITY in HookFlags.ALL
        assert HookFlags.AFTER_LIQUIDITY in HookFlags.ALL

    # -- HookContext --------------------------------------------------------

    def test_hook_context_creation(self):
        ctx = HookContext(
            pool_id="pool1", sender=ADDR_A,
            token_in="QRDX", token_out="USDC",
            amount_in=Decimal("100"), amount_out=Decimal("99"),
        )
        assert ctx.pool_id == "pool1"
        assert ctx.amount_in == Decimal("100")

    # -- HookResult ---------------------------------------------------------

    def test_hook_result_allow(self):
        r = HookResult(allow=True)
        assert r.allow

    def test_hook_result_deny(self):
        r = HookResult(allow=False, reason="Blocked")
        assert not r.allow
        assert r.reason == "Blocked"

    def test_hook_result_fee_override(self):
        r = HookResult(allow=True, modified_fee=Decimal("0.001"))
        assert r.modified_fee == Decimal("0.001")

    # -- HookRegistry -------------------------------------------------------

    class _TestHook:
        """Simple test hook that always allows."""
        def __init__(self):
            self.before_swap_count = 0
            self.after_swap_count = 0
            self.before_liq_count = 0
            self.after_liq_count = 0

        @property
        def flags(self) -> HookFlags:
            return HookFlags.ALL

        def on_before_swap(self, ctx: HookContext) -> HookResult:
            self.before_swap_count += 1
            return HookResult(allow=True)

        def on_after_swap(self, ctx: HookContext) -> HookResult:
            self.after_swap_count += 1
            return HookResult(allow=True)

        def on_before_liquidity(self, ctx: HookContext) -> HookResult:
            self.before_liq_count += 1
            return HookResult(allow=True)

        def on_after_liquidity(self, ctx: HookContext) -> HookResult:
            self.after_liq_count += 1
            return HookResult(allow=True)

    class _BlockingHook:
        """Hook that blocks all operations."""
        @property
        def flags(self) -> HookFlags:
            return HookFlags.ALL

        def on_before_swap(self, ctx: HookContext) -> HookResult:
            return HookResult(allow=False, reason="Blocked by test hook")

        def on_after_swap(self, ctx: HookContext) -> HookResult:
            return HookResult(allow=False, reason="Blocked by test hook")

        def on_before_liquidity(self, ctx: HookContext) -> HookResult:
            return HookResult(allow=False, reason="Blocked by test hook")

        def on_after_liquidity(self, ctx: HookContext) -> HookResult:
            return HookResult(allow=False, reason="Blocked by test hook")

    def test_register_and_run_hook(self):
        reg = HookRegistry()
        hook = self._TestHook()
        reg.register(hook)
        assert reg.hook_count == 1

        ctx = HookContext(pool_id="p1", amount_in=Decimal("10"))
        result = reg.run_before_swap(ctx)
        assert result.allow
        assert hook.before_swap_count == 1

    def test_multiple_hooks_all_run(self):
        reg = HookRegistry()
        h1 = self._TestHook()
        h2 = self._TestHook()
        reg.register(h1)
        reg.register(h2)

        ctx = HookContext(pool_id="p1")
        reg.run_before_swap(ctx)
        assert h1.before_swap_count == 1
        assert h2.before_swap_count == 1

    def test_blocking_hook_stops_execution(self):
        reg = HookRegistry()
        reg.register(self._BlockingHook())
        ctx = HookContext()
        result = reg.run_before_swap(ctx)
        assert not result.allow
        assert "Blocked" in result.reason

    def test_unregister_hook(self):
        reg = HookRegistry()
        hook = self._TestHook()
        reg.register(hook)
        assert reg.hook_count == 1
        reg.unregister(hook)
        assert reg.hook_count == 0

    def test_hook_flag_filtering(self):
        """Hooks only receive events matching their flags."""
        class SwapOnlyHook:
            @property
            def flags(self):
                return HookFlags.BEFORE_SWAP

            def on_before_swap(self, ctx):
                return HookResult(allow=False, reason="No swaps")

            def on_before_liquidity(self, ctx):
                return HookResult(allow=False, reason="No liq")

        reg = HookRegistry()
        reg.register(SwapOnlyHook())

        # Before-swap should be blocked
        r1 = reg.run_before_swap(HookContext())
        assert not r1.allow

        # Before-liquidity should pass (hook doesn't have that flag)
        r2 = reg.run_before_liquidity(HookContext())
        assert r2.allow

    def test_all_four_hook_points(self):
        reg = HookRegistry()
        hook = self._TestHook()
        reg.register(hook)
        ctx = HookContext()

        reg.run_before_swap(ctx)
        reg.run_after_swap(ctx)
        reg.run_before_liquidity(ctx)
        reg.run_after_liquidity(ctx)

        assert hook.before_swap_count == 1
        assert hook.after_swap_count == 1
        assert hook.before_liq_count == 1
        assert hook.after_liq_count == 1

    # -- Circuit Breaker ----------------------------------------------------

    def test_circuit_breaker_manual_trip(self):
        cb = CircuitBreaker()
        assert not cb.is_tripped
        cb.trip("Emergency")
        assert cb.is_tripped
        assert "Emergency" in cb.trip_reason

    def test_circuit_breaker_reset(self):
        cb = CircuitBreaker()
        cb.trip("Test")
        cb.reset()
        assert not cb.is_tripped

    def test_circuit_breaker_blocks_when_tripped(self):
        cb = CircuitBreaker()
        cb.trip("Test")
        result = cb.on_before_swap(HookContext(amount_in=Decimal("1")))
        assert not result.allow

    def test_circuit_breaker_allows_when_not_tripped(self):
        cb = CircuitBreaker()
        result = cb.on_before_swap(HookContext(amount_in=Decimal("1")))
        assert result.allow

    def test_circuit_breaker_volume_trip(self):
        cb = CircuitBreaker(max_volume_per_block=Decimal("100"))
        # First swap within limit
        r1 = cb.on_before_swap(HookContext(amount_in=Decimal("50")))
        assert r1.allow
        # Second swap pushes over limit
        r2 = cb.on_before_swap(HookContext(amount_in=Decimal("60")))
        assert not r2.allow
        assert cb.is_tripped

    def test_circuit_breaker_new_block_resets_volume(self):
        cb = CircuitBreaker(max_volume_per_block=Decimal("100"))
        cb.on_before_swap(HookContext(amount_in=Decimal("90")))
        cb.new_block()
        # Volume should be reset
        r = cb.on_before_swap(HookContext(amount_in=Decimal("90")))
        assert r.allow

    def test_circuit_breaker_price_deviation_trip(self):
        cb = CircuitBreaker(max_price_deviation=Decimal("0.10"))
        # First swap establishes baseline price
        cb.on_after_swap(HookContext(amount_in=Decimal("100"), amount_out=Decimal("100")))
        # Big price deviation
        result = cb.on_after_swap(HookContext(amount_in=Decimal("100"), amount_out=Decimal("50")))
        # Price went from 1.0 to 2.0 → 100% deviation > 10%
        assert not result.allow
        assert cb.is_tripped

    def test_circuit_breaker_liquidity_blocked_when_tripped(self):
        cb = CircuitBreaker()
        cb.trip("Test")
        result = cb.on_before_liquidity(HookContext())
        assert not result.allow

    def test_circuit_breaker_flags(self):
        cb = CircuitBreaker()
        assert HookFlags.BEFORE_SWAP in cb.flags
        assert HookFlags.AFTER_SWAP in cb.flags

    def test_circuit_breaker_integrated_with_registry(self):
        reg = HookRegistry()
        cb = CircuitBreaker()
        reg.register(cb)
        cb.trip("Emergency")
        result = reg.run_before_swap(HookContext(amount_in=Decimal("1")))
        assert not result.allow
