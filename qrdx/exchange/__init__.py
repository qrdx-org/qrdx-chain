"""
QRDX Integrated Exchange Engine

Protocol-native exchange embedded in the execution layer (Whitepaper §7).

Components:
  - AMM Engine (concentrated liquidity, Uniswap V3 model)
  - On-Chain Order Book (limit, stop-loss, price-time priority)
  - Perpetual Contracts (funding rate, margin, liquidation)
  - Unified Router (best execution across AMM + CLOB)
  - Settlement Layer (atomic, same-block finality)
  - TWAP Oracle (geometric mean time-weighted average price)
  - Fee Tiers & Distribution
"""

from .orderbook import (
    Order,
    OrderSide,
    OrderStatus,
    OrderType,
    OrderBook,
    Trade,
    SelfTradeAction,
    MIN_ORDER_SIZE,
    MAX_ORDERS_PER_ADDRESS,
    MAX_ORDERS_PER_BLOCK_PER_ADDRESS,
)
from .amm import (
    PoolState,
    Position,
    TickInfo,
    ConcentratedLiquidityPool,
    PoolManager,
    FeeTier,
)
from .perpetual import (
    PerpPosition,
    PerpSide,
    PerpMarket,
    FundingSnapshot,
    LiquidationResult,
    PerpEngine,
)
from .router import (
    FillResult,
    FillSource,
    UnifiedRouter,
)
from .oracle import (
    Observation,
    TWAPOracle,
)
from .hooks import (
    HookFlags,
    HookContext,
    HookResult,
    HookRegistry,
    CircuitBreaker,
)

__all__ = [
    # Order Book
    "Order", "OrderSide", "OrderStatus", "OrderType", "OrderBook", "Trade",
    "SelfTradeAction", "MIN_ORDER_SIZE", "MAX_ORDERS_PER_ADDRESS",
    "MAX_ORDERS_PER_BLOCK_PER_ADDRESS",
    # AMM
    "PoolState", "Position", "TickInfo", "ConcentratedLiquidityPool",
    "PoolManager", "FeeTier",
    # Perpetual
    "PerpPosition", "PerpSide", "PerpMarket", "FundingSnapshot",
    "LiquidationResult", "PerpEngine",
    # Router
    "FillResult", "FillSource", "UnifiedRouter",
    # Oracle
    "Observation", "TWAPOracle",
    # Hooks
    "HookFlags", "HookContext", "HookResult", "HookRegistry", "CircuitBreaker",
]
