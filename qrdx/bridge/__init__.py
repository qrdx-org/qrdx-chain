"""
QRDX Cross-Chain Bridge Infrastructure

Provides:
  - types: Core data structures (ChainId, BridgeRecord, OracleTransaction, etc.)
  - adapters: Chain adapters (Ethereum, Bitcoin, Solana), OracleConsensus, BlockHeightTracker
  - shielding: ShieldingManager, DoomsdayProtocol, BridgeMinter
  - doomsday_store: Production DB-backed DoomsdayStateStore
"""

from .adapters import (
    BaseChainAdapter,
    BitcoinAdapter,
    BlockHeightTracker,
    EthereumAdapter,
    InclusionProof,
    OracleConsensus,
    SolanaAdapter,
)
from .doomsday_store import DatabaseDoomsdayStateStore
from .shielding import (
    BRIDGE_FEE_BPS,
    DEFAULT_TOKEN_CONFIGS,
    DOOMSDAY_CANARY_ADDRESS,
    DOOMSDAY_CANARY_BALANCE,
    DOOMSDAY_DOMAIN,
    FRAUD_PROOF_WINDOW_SECONDS,
    HIGH_VALUE_THRESHOLD_USD,
    BridgeMinter,
    DoomsdayAttestation,
    DoomsdayAware,
    DoomsdayProof,
    DoomsdayProtocol,
    DoomsdayStateStore,
    InMemoryDoomsdayStateStore,
    ShieldingManager,
)
from .types import (
    CHAIN_NAMES,
    BlockHeightRecord,
    BridgeOperationType,
    BridgeRecord,
    BridgeStatus,
    BridgeTokenConfig,
    ChainId,
    ConditionType,
    ExecutionCondition,
    OracleAttestation,
    OracleTransaction,
    OracleTxStatus,
    OracleTxType,
    ValidatorProof,
)

__all__ = [
    # Types
    "BlockHeightRecord",
    "BridgeOperationType",
    "BridgeRecord",
    "BridgeStatus",
    "BridgeTokenConfig",
    "CHAIN_NAMES",
    "ChainId",
    "ConditionType",
    "ExecutionCondition",
    "OracleAttestation",
    "OracleTxStatus",
    "OracleTxType",
    "OracleTransaction",
    "ValidatorProof",
    # Adapters
    "BaseChainAdapter",
    "BitcoinAdapter",
    "BlockHeightTracker",
    "EthereumAdapter",
    "InclusionProof",
    "OracleConsensus",
    "SolanaAdapter",
    # Shielding
    "BridgeMinter",
    "DoomsdayAware",
    "DoomsdayAttestation",
    "DoomsdayProof",
    "DoomsdayProtocol",
    "DoomsdayStateStore",
    "InMemoryDoomsdayStateStore",
    "ShieldingManager",
    "BRIDGE_FEE_BPS",
    "DEFAULT_TOKEN_CONFIGS",
    "DOOMSDAY_CANARY_ADDRESS",
    "DOOMSDAY_CANARY_BALANCE",
    "DOOMSDAY_DOMAIN",
    "FRAUD_PROOF_WINDOW_SECONDS",
    "HIGH_VALUE_THRESHOLD_USD",
    # Production State Store
    "DatabaseDoomsdayStateStore",
]
