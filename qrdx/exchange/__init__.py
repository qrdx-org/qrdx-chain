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

from .amm import (
    ConcentratedLiquidityPool,
    FeeTier,
    PoolManager,
    PoolState,
    Position,
    TickInfo,
)
from .block_processor import (
    BLOCK_EXCHANGE_TXS_KEY,
    apply_block_exchange_section,
    build_oracle_update_tx,
    decode_exchange_txs,
    encode_exchange_txs,
    exchange_txs_canonical_bytes,
    extract_exchange_transactions,
    extract_exchange_transactions_from_dict,
    get_validator_fee_share,
    process_exchange_transactions,
    rebuild_exchange_state_from_chain,
    validate_exchange_state_root,
    verify_exchange_tx,
)
from .hooks import (
    HookContext,
    HookFlags,
    HookRegistry,
    HookResult,
)
from .mempool import ExchangeMempool
from .oracle import (
    Observation,
    TWAPOracle,
)
from .orderbook import (
    MAX_ORDERS_PER_ADDRESS,
    MAX_ORDERS_PER_BLOCK_PER_ADDRESS,
    MIN_ORDER_SIZE,
    Order,
    OrderBook,
    OrderSide,
    OrderStatus,
    OrderType,
    SelfTradeAction,
    Trade,
)
from .perpetual import (
    FundingSnapshot,
    LiquidationResult,
    PerpEngine,
    PerpMarket,
    PerpPosition,
    PerpSide,
)
from .router import (
    FillResult,
    FillSource,
    UnifiedRouter,
)
from .state_manager import (
    ExchangeExecResult,
    ExchangeStateManager,
)
from .transactions import (
    EXCHANGE_GAS_COSTS,
    ExchangeOpType,
    ExchangeTransaction,
)

__all__ = [
    # Order Book
    "Order",
    "OrderSide",
    "OrderStatus",
    "OrderType",
    "OrderBook",
    "Trade",
    "SelfTradeAction",
    "MIN_ORDER_SIZE",
    "MAX_ORDERS_PER_ADDRESS",
    "MAX_ORDERS_PER_BLOCK_PER_ADDRESS",
    # AMM
    "PoolState",
    "Position",
    "TickInfo",
    "ConcentratedLiquidityPool",
    "PoolManager",
    "FeeTier",
    # Perpetual
    "PerpPosition",
    "PerpSide",
    "PerpMarket",
    "FundingSnapshot",
    "LiquidationResult",
    "PerpEngine",
    # Router
    "FillResult",
    "FillSource",
    "UnifiedRouter",
    # Oracle
    "Observation",
    "TWAPOracle",
    # Hooks
    "HookFlags",
    "HookContext",
    "HookResult",
    "HookRegistry",
    # Transactions (blockchain integration)
    "ExchangeOpType",
    "ExchangeTransaction",
    "EXCHANGE_GAS_COSTS",
    # State Manager (consensus bridge)
    "ExchangeExecResult",
    "ExchangeStateManager",
    # Block Processor (consensus integration)
    "process_exchange_transactions",
    "validate_exchange_state_root",
    "extract_exchange_transactions",
    "build_oracle_update_tx",
    "get_validator_fee_share",
    "verify_exchange_tx",
    "apply_block_exchange_section",
    "rebuild_exchange_state_from_chain",
    # Block-body codec (Phase D2)
    "encode_exchange_txs",
    "decode_exchange_txs",
    "exchange_txs_canonical_bytes",
    "extract_exchange_transactions_from_dict",
    "BLOCK_EXCHANGE_TXS_KEY",
    # Mempool (admission)
    "ExchangeMempool",
]
