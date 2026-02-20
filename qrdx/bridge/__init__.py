"""
QRDX Cross-Chain Bridge Infrastructure

Provides:
  - types: Core data structures (ChainId, BridgeRecord, OracleTransaction, etc.)
  - adapters: Chain adapters (Ethereum, Bitcoin, Solana), OracleConsensus, BlockHeightTracker
  - shielding: ShieldingManager, DoomsdayProtocol, BridgeMinter
"""

from .types import (
    BlockHeightRecord,
    BridgeOperationType,
    BridgeRecord,
    BridgeStatus,
    BridgeTokenConfig,
    CHAIN_NAMES,
    ChainId,
    ConditionType,
    ExecutionCondition,
    OracleAttestation,
    OracleTxStatus,
    OracleTxType,
    OracleTransaction,
    ValidatorProof,
)

from .adapters import (
    BaseChainAdapter,
    BitcoinAdapter,
    BlockHeightTracker,
    EthereumAdapter,
    InclusionProof,
    OracleConsensus,
    SolanaAdapter,
)

from .shielding import (
    BridgeMinter,
    DoomsdayProtocol,
    ShieldingManager,
    BRIDGE_FEE_BPS,
    DEFAULT_TOKEN_CONFIGS,
    DOOMSDAY_CANARY_ADDRESS,
    DOOMSDAY_CANARY_BALANCE,
    FRAUD_PROOF_WINDOW_SECONDS,
    HIGH_VALUE_THRESHOLD_USD,
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
    "DoomsdayProtocol",
    "ShieldingManager",
    "BRIDGE_FEE_BPS",
    "DEFAULT_TOKEN_CONFIGS",
    "DOOMSDAY_CANARY_ADDRESS",
    "DOOMSDAY_CANARY_BALANCE",
    "FRAUD_PROOF_WINDOW_SECONDS",
    "HIGH_VALUE_THRESHOLD_USD",
]
