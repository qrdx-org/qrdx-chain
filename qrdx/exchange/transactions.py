"""
QRDX Exchange Transaction Types  (Whitepaper §7 — On-Chain Execution)

Defines the transaction envelope for all exchange operations that are
included in blocks and processed deterministically by every validator.

Exchange transactions are serialized, signed, included in the mempool,
and executed during block production — identical to contract transactions
but processed by the native exchange engine rather than the EVM.

Transaction Types:
  - CREATE_POOL:       Deploy a new liquidity pool
  - ADD_LIQUIDITY:     Provide liquidity to a pool
  - REMOVE_LIQUIDITY:  Withdraw liquidity from a pool
  - SWAP:              Exchange tokens via AMM or CLOB
  - PLACE_ORDER:       Place a limit/market/stop order on the CLOB
  - CANCEL_ORDER:      Cancel an open order
  - OPEN_POSITION:     Open a perpetual futures position
  - CLOSE_POSITION:    Close a perpetual position
  - PARTIAL_CLOSE:     Partially close a perpetual position
  - ADD_MARGIN:        Add margin to a perpetual position
  - UPDATE_ORACLE:     Submit an oracle price update (validator duty)

Security:
  - All operations are signed by the sender's PQ key (Dilithium)
  - Nonce prevents replay attacks
  - Gas metering limits execution cost
  - Deterministic execution — every node produces identical state
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from decimal import Decimal, ROUND_HALF_UP
from enum import IntEnum
from typing import Any, Dict, List, Optional

ZERO = Decimal("0")


# ---------------------------------------------------------------------------
# Exchange Operation Types
# ---------------------------------------------------------------------------

class ExchangeOpType(IntEnum):
    """All exchange operation types.  Values are consensus-critical."""
    CREATE_POOL = 1
    ADD_LIQUIDITY = 2
    REMOVE_LIQUIDITY = 3
    SWAP = 4
    PLACE_ORDER = 5
    CANCEL_ORDER = 6
    OPEN_POSITION = 7
    CLOSE_POSITION = 8
    PARTIAL_CLOSE = 9
    ADD_MARGIN = 10
    UPDATE_ORACLE = 11


# ---------------------------------------------------------------------------
# Exchange Transaction
# ---------------------------------------------------------------------------

@dataclass
class ExchangeTransaction:
    """
    Blockchain-level envelope for a single exchange operation.

    Fields are consensus-critical — changing any field changes the tx hash.
    """
    op_type: ExchangeOpType
    sender: str                         # PQ address of the signer
    nonce: int                          # per-sender monotonic nonce
    params: Dict[str, Any]              # operation-specific parameters
    gas_limit: int = 100_000            # max gas for this operation
    gas_price: Decimal = Decimal("1")   # gas price in QRDX
    timestamp: float = 0.0             # submission timestamp
    signature: bytes = b""              # Dilithium signature
    public_key: bytes = b""             # Dilithium public key

    # --- Computed after execution ---
    gas_used: int = 0
    success: bool = False
    result: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    # -- Hashing ------------------------------------------------------------

    def tx_hash(self) -> str:
        """Deterministic transaction hash (consensus-critical)."""
        raw = self._canonical_bytes()
        return hashlib.blake2b(raw, digest_size=32).hexdigest()

    def _canonical_bytes(self) -> bytes:
        """Canonical byte representation for hashing and signing."""
        # Deterministic JSON serialization of params
        params_json = json.dumps(
            self.params, sort_keys=True, default=str
        ).encode("utf-8")
        parts = [
            self.op_type.to_bytes(1, "big"),
            self.sender.encode("utf-8"),
            self.nonce.to_bytes(8, "big"),
            params_json,
            self.gas_limit.to_bytes(8, "big"),
            str(self.gas_price).encode("utf-8"),
        ]
        return b"".join(parts)

    def signing_bytes(self) -> bytes:
        """Bytes that the sender must sign."""
        return self._canonical_bytes()

    # -- Serialization ------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-safe dictionary."""
        return {
            "op_type": int(self.op_type),
            "sender": self.sender,
            "nonce": self.nonce,
            "params": self.params,
            "gas_limit": self.gas_limit,
            "gas_price": str(self.gas_price),
            "timestamp": self.timestamp,
            "signature": self.signature.hex() if self.signature else "",
            "public_key": self.public_key.hex() if self.public_key else "",
            "tx_hash": self.tx_hash(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExchangeTransaction:
        """Deserialize from a dictionary."""
        return cls(
            op_type=ExchangeOpType(data["op_type"]),
            sender=data["sender"],
            nonce=data["nonce"],
            params=data["params"],
            gas_limit=data.get("gas_limit", 100_000),
            gas_price=Decimal(data.get("gas_price", "1")),
            timestamp=data.get("timestamp", 0.0),
            signature=bytes.fromhex(data["signature"]) if data.get("signature") else b"",
            public_key=bytes.fromhex(data["public_key"]) if data.get("public_key") else b"",
        )

    def to_hex(self) -> str:
        """Serialize to hex string for mempool/network transmission."""
        return json.dumps(self.to_dict(), sort_keys=True, default=str)

    @classmethod
    def from_hex(cls, hex_str: str) -> ExchangeTransaction:
        """Deserialize from hex string."""
        data = json.loads(hex_str)
        return cls.from_dict(data)

    # -- Gas ----------------------------------------------------------------

    def fee(self) -> Decimal:
        """Total fee = gas_used * gas_price."""
        return Decimal(self.gas_used) * self.gas_price

    def max_fee(self) -> Decimal:
        """Max fee = gas_limit * gas_price."""
        return Decimal(self.gas_limit) * self.gas_price

    # -- Validation ---------------------------------------------------------

    def validate_basic(self) -> bool:
        """
        Basic structural validation (no state access needed).

        Returns:
            True if structurally valid

        Raises:
            ValueError: with specific reason
        """
        if not self.sender:
            raise ValueError("Missing sender address")
        if self.nonce < 0:
            raise ValueError("Nonce must be non-negative")
        if self.gas_limit <= 0:
            raise ValueError("Gas limit must be positive")
        if self.gas_price <= 0:
            raise ValueError("Gas price must be positive")
        if self.op_type not in ExchangeOpType:
            raise ValueError(f"Unknown operation type: {self.op_type}")

        # Type-specific parameter validation
        self._validate_params()
        return True

    def _validate_params(self) -> None:
        """Validate operation-specific parameters."""
        p = self.params
        op = self.op_type

        if op == ExchangeOpType.CREATE_POOL:
            for key in ("token0", "token1", "fee_tier", "pool_type", "initial_sqrt_price", "stake_amount"):
                if key not in p:
                    raise ValueError(f"CREATE_POOL missing param: {key}")

        elif op == ExchangeOpType.ADD_LIQUIDITY:
            for key in ("pool_id", "tick_lower", "tick_upper", "amount"):
                if key not in p:
                    raise ValueError(f"ADD_LIQUIDITY missing param: {key}")

        elif op == ExchangeOpType.REMOVE_LIQUIDITY:
            for key in ("pool_id", "position_id"):
                if key not in p:
                    raise ValueError(f"REMOVE_LIQUIDITY missing param: {key}")

        elif op == ExchangeOpType.SWAP:
            for key in ("token_in", "token_out", "amount_in"):
                if key not in p:
                    raise ValueError(f"SWAP missing param: {key}")

        elif op == ExchangeOpType.PLACE_ORDER:
            for key in ("pair", "side", "order_type", "amount"):
                if key not in p:
                    raise ValueError(f"PLACE_ORDER missing param: {key}")

        elif op == ExchangeOpType.CANCEL_ORDER:
            if "order_id" not in p:
                raise ValueError("CANCEL_ORDER missing param: order_id")

        elif op == ExchangeOpType.OPEN_POSITION:
            for key in ("market_id", "side", "size", "leverage", "price"):
                if key not in p:
                    raise ValueError(f"OPEN_POSITION missing param: {key}")

        elif op == ExchangeOpType.CLOSE_POSITION:
            for key in ("position_id", "price"):
                if key not in p:
                    raise ValueError(f"CLOSE_POSITION missing param: {key}")

        elif op == ExchangeOpType.PARTIAL_CLOSE:
            for key in ("position_id", "close_size", "price"):
                if key not in p:
                    raise ValueError(f"PARTIAL_CLOSE missing param: {key}")

        elif op == ExchangeOpType.ADD_MARGIN:
            for key in ("position_id", "amount"):
                if key not in p:
                    raise ValueError(f"ADD_MARGIN missing param: {key}")

        elif op == ExchangeOpType.UPDATE_ORACLE:
            for key in ("pair", "price"):
                if key not in p:
                    raise ValueError(f"UPDATE_ORACLE missing param: {key}")

    # -- Identification -----------------------------------------------------

    def is_exchange_transaction(self) -> bool:
        """Marker method for exchange transaction identification."""
        return True

    def __repr__(self) -> str:
        return (f"ExchangeTransaction(op={self.op_type.name}, sender={self.sender[:16]}..., "
                f"nonce={self.nonce}, hash={self.tx_hash()[:12]}...)")


# ---------------------------------------------------------------------------
# Gas cost table (consensus-critical constants)
# ---------------------------------------------------------------------------

EXCHANGE_GAS_COSTS: Dict[ExchangeOpType, int] = {
    ExchangeOpType.CREATE_POOL: 150_000,
    ExchangeOpType.ADD_LIQUIDITY: 90_000,
    ExchangeOpType.REMOVE_LIQUIDITY: 60_000,
    ExchangeOpType.SWAP: 65_000,
    ExchangeOpType.PLACE_ORDER: 40_000,
    ExchangeOpType.CANCEL_ORDER: 25_000,
    ExchangeOpType.OPEN_POSITION: 80_000,
    ExchangeOpType.CLOSE_POSITION: 60_000,
    ExchangeOpType.PARTIAL_CLOSE: 60_000,
    ExchangeOpType.ADD_MARGIN: 30_000,
    ExchangeOpType.UPDATE_ORACLE: 20_000,
}
