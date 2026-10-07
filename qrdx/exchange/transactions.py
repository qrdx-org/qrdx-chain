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
  - Gas metering limits execution cost; gas is priced in wei, at least
    constants.EXCHANGE_MIN_GAS_PRICE_WEI, and every executed operation pays
    gas_used × gas_price (burned)
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


def _min_gas_price() -> int:
    from .. import constants
    return constants.EXCHANGE_MIN_GAS_PRICE_WEI


def _wei_per_qrdx() -> Decimal:
    from .. import constants
    return Decimal(constants.WEI_PER_QRDX)


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
    CREATE_MARKET = 12
    TOKEN_DEPLOY = 13
    TOKEN_TRANSFER = 14
    STAKE_DEPOSIT = 15
    STAKE_EXIT = 16
    REMOVE_POOL = 17
    # Perps clearinghouse (docs/PERPS_CLEARINGHOUSE.md). OPEN_POSITION, CLOSE_POSITION,
    # PARTIAL_CLOSE and ADD_MARGIN (7-10) are retired: they traded against nobody.
    PERP_DEPOSIT = 18
    PERP_WITHDRAW = 19
    PERP_SET_LEVERAGE = 20
    PERP_ORDER = 21
    PERP_CANCEL = 22
    VAULT_DEPOSIT = 23     # perps backstop vault: collateral in, shares at NAV
    VAULT_WITHDRAW = 24    # shares out at NAV, after the lockup
    ORACLE_VOTE = 25       # a validator's USD prices for perp markets
    # The native token standard (qrdx/exchange/tokens.py): authorities, supply, allowances.
    TOKEN_MINT = 26            # the mint authority mints new supply
    TOKEN_BURN = 27            # a holder burns its own balance
    TOKEN_APPROVE = 28         # set a spender's allowance (0 revokes)
    TOKEN_TRANSFER_FROM = 29   # a spender moves an owner's tokens within its allowance
    TOKEN_SET_AUTHORITY = 30   # hand over or renounce the mint / freeze authority
    TOKEN_FREEZE = 31          # the freeze authority freezes an account's balance
    TOKEN_THAW = 32            # … and thaws it
    # Token-2022-style extensions and ERC-777 operators (docs/NATIVE_TOKENS.md §7).
    TOKEN_UPDATE_METADATA = 33     # the metadata authority edits name, symbol, uri, fields
    TOKEN_SET_TRANSFER_FEE = 34    # the fee authority sets a new rate (applies later)
    TOKEN_WITHDRAW_FEES = 35       # the withdraw authority collects withheld transfer fees
    TOKEN_PAUSE = 36               # the pause authority stops transfers, mints and burns
    TOKEN_RESUME = 37              # … and lets them run again
    TOKEN_AUTHORIZE_OPERATOR = 38  # a holder lets an operator move its balance
    TOKEN_REVOKE_OPERATOR = 39     # … and stops it (a default operator too)
    # Native NFTs (qrdx/exchange/nfts.py): collections of supply-1 tokens.
    NFT_CREATE_COLLECTION = 40     # a collection: metadata, royalties, update + mint authorities
    NFT_MINT = 41                  # the mint authority adds an NFT to the collection
    NFT_TRANSFER = 42              # the owner (or its approved account / operator) moves one
    NFT_BURN = 43                  # … or burns it
    NFT_APPROVE = 44               # the owner approves one account for one NFT
    NFT_SET_APPROVAL_FOR_ALL = 45  # the owner approves an operator for all its NFTs in a collection
    NFT_UPDATE = 46                # the update authority edits the collection's or an NFT's metadata
    NFT_SET_AUTHORITY = 47         # hand over or renounce the update / mint authority


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
    gas_price: int = field(default_factory=_min_gas_price)   # WEI per gas (1 QRDX = 10^18 wei)
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
        # Wei are whole: hold the price as an int, so it hashes and signs as "1000000000"
        # however the caller wrote it. A fractional price is left as given and refused by
        # validate_fee.
        try:
            d = Decimal(str(self.gas_price))
            if d == d.to_integral_value():
                self.gas_price = int(d)
        except Exception:
            pass

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

    # -- Authentication -----------------------------------------------------

    def verify(self) -> bool:
        """
        Verify the transaction's post-quantum signature and sender binding.

        Security-critical: this is the only thing standing between a submitted
        exchange transaction and execution as ``self.sender``. It enforces two
        properties:

          1. **Authenticity** — the Dilithium signature over ``signing_bytes()``
             is valid for the embedded ``public_key``.
          2. **Binding** — ``public_key`` actually derives to ``sender``, so a
             valid signature for some *other* key cannot be replayed against a
             victim's address.

        Returns:
            True iff both hold. Never raises — callers branch on the bool.

        Note:
            This is an *admission/validation* check (mempool + block validation),
            deliberately kept out of the deterministic execution core
            (``ExchangeStateManager.process_transaction``), which assumes
            already-admitted transactions.
        """
        if not self.signature or not self.public_key:
            return False
        try:
            from ..crypto.pq.dilithium import PQPublicKey, PQSignature, verify as pq_verify

            pub = PQPublicKey.from_bytes(self.public_key)

            # Binding: the key must derive to the claimed sender address.
            if pub.to_address().lower() != str(self.sender).lower():
                return False

            return pq_verify(pub, self.signing_bytes(), PQSignature.from_bytes(self.signature))
        except Exception:
            # Malformed key/signature material → unauthenticated.
            return False

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
            gas_price=data.get("gas_price", _min_gas_price()),
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
        """What the executed operation paid, in QRDX: gas_used × gas_price wei."""
        return Decimal(self.gas_used) * Decimal(self.gas_price) / _wei_per_qrdx()

    def max_fee(self) -> Decimal:
        """The most it can pay, in QRDX: gas_limit × gas_price wei — reserved up front."""
        return Decimal(self.gas_limit) * Decimal(self.gas_price) / _wei_per_qrdx()

    def validate_fee(self, min_gas_price: Optional[int] = None) -> None:
        """Raises ValueError unless gas_price is a whole number of wei at or above the floor."""
        floor = _min_gas_price() if min_gas_price is None else int(min_gas_price)
        if not isinstance(self.gas_price, int) or isinstance(self.gas_price, bool):
            raise ValueError(f"gas_price must be a whole number of wei, got {self.gas_price}")
        if self.gas_price < floor:
            raise ValueError(f"gas_price {self.gas_price} wei is below the minimum {floor} wei")

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
            for key in ("token0", "token1", "fee_tier", "pool_type", "stake_amount"):
                if key not in p:
                    raise ValueError(f"CREATE_POOL missing param: {key}")
            if "initial_sqrt_price" not in p and "initial_price" not in p:
                raise ValueError("CREATE_POOL missing param: initial_price (or initial_sqrt_price)")

        elif op == ExchangeOpType.ADD_LIQUIDITY:
            for key in ("tick_lower", "tick_upper", "amount"):
                if key not in p:
                    raise ValueError(f"ADD_LIQUIDITY missing param: {key}")
            if "pool_id" not in p and not (p.get("token0") and p.get("token1")):
                raise ValueError("ADD_LIQUIDITY needs pool_id, or token0 and token1")

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

        elif op in (ExchangeOpType.PERP_DEPOSIT, ExchangeOpType.PERP_WITHDRAW):
            if "amount" not in p:
                raise ValueError(f"{op.name} missing param: amount")

        elif op == ExchangeOpType.PERP_SET_LEVERAGE:
            for key in ("market_id", "leverage"):
                if key not in p:
                    raise ValueError(f"PERP_SET_LEVERAGE missing param: {key}")

        elif op == ExchangeOpType.PERP_ORDER:
            for key in ("market_id", "side", "size", "price"):
                if key not in p:
                    raise ValueError(f"PERP_ORDER missing param: {key}")

        elif op == ExchangeOpType.PERP_CANCEL:
            for key in ("market_id", "order_id"):
                if key not in p:
                    raise ValueError(f"PERP_CANCEL missing param: {key}")

        elif op == ExchangeOpType.VAULT_DEPOSIT:
            if "amount" not in p:
                raise ValueError("VAULT_DEPOSIT missing param: amount")

        elif op == ExchangeOpType.VAULT_WITHDRAW:
            if "shares" not in p:
                raise ValueError("VAULT_WITHDRAW missing param: shares")

        elif op == ExchangeOpType.ORACLE_VOTE:
            if not isinstance(p.get("prices"), dict) or not p["prices"]:
                raise ValueError("ORACLE_VOTE needs a non-empty prices map")

        elif op == ExchangeOpType.UPDATE_ORACLE:
            for key in ("pair", "price"):
                if key not in p:
                    raise ValueError(f"UPDATE_ORACLE missing param: {key}")

        elif op == ExchangeOpType.CREATE_MARKET:
            if "base_token" not in p:
                raise ValueError("CREATE_MARKET missing param: base_token")

        elif op == ExchangeOpType.TOKEN_DEPLOY:
            for key in ("name", "symbol"):
                if key not in p:
                    raise ValueError(f"TOKEN_DEPLOY missing param: {key}")
            if "total_supply" not in p and "initial_supply" not in p and not p.get("mint_authority"):
                raise ValueError("TOKEN_DEPLOY needs an initial supply or a mint authority")

        elif op in (ExchangeOpType.TOKEN_MINT, ExchangeOpType.TOKEN_BURN):
            for key in ("token_address", "amount"):
                if key not in p:
                    raise ValueError(f"{op.name} missing param: {key}")

        elif op == ExchangeOpType.TOKEN_APPROVE:
            for key in ("token_address", "spender", "amount"):
                if key not in p:
                    raise ValueError(f"TOKEN_APPROVE missing param: {key}")

        elif op == ExchangeOpType.TOKEN_TRANSFER_FROM:
            for key in ("token_address", "from", "to", "amount"):
                if key not in p:
                    raise ValueError(f"TOKEN_TRANSFER_FROM missing param: {key}")

        elif op == ExchangeOpType.TOKEN_SET_AUTHORITY:
            for key in ("token_address", "authority"):
                if key not in p:
                    raise ValueError(f"TOKEN_SET_AUTHORITY missing param: {key}")
            if "new_authority" not in p:
                raise ValueError("TOKEN_SET_AUTHORITY missing param: new_authority "
                                 "(empty to renounce)")

        elif op in (ExchangeOpType.TOKEN_FREEZE, ExchangeOpType.TOKEN_THAW):
            for key in ("token_address", "account"):
                if key not in p:
                    raise ValueError(f"{op.name} missing param: {key}")

        elif op == ExchangeOpType.TOKEN_TRANSFER:
            for key in ("token_address", "to", "amount"):
                if key not in p:
                    raise ValueError(f"TOKEN_TRANSFER missing param: {key}")

        elif op == ExchangeOpType.TOKEN_UPDATE_METADATA:
            if "token_address" not in p:
                raise ValueError("TOKEN_UPDATE_METADATA missing param: token_address")
            if not any(k in p for k in ("name", "symbol", "uri", "fields")):
                raise ValueError("TOKEN_UPDATE_METADATA changes nothing: give name, symbol, "
                                 "uri or fields")

        elif op == ExchangeOpType.TOKEN_SET_TRANSFER_FEE:
            for key in ("token_address", "transfer_fee_bps"):
                if key not in p:
                    raise ValueError(f"TOKEN_SET_TRANSFER_FEE missing param: {key}")

        elif op in (ExchangeOpType.TOKEN_WITHDRAW_FEES, ExchangeOpType.TOKEN_PAUSE,
                    ExchangeOpType.TOKEN_RESUME):
            if "token_address" not in p:
                raise ValueError(f"{op.name} missing param: token_address")

        elif op in (ExchangeOpType.TOKEN_AUTHORIZE_OPERATOR, ExchangeOpType.TOKEN_REVOKE_OPERATOR):
            for key in ("token_address", "operator"):
                if key not in p:
                    raise ValueError(f"{op.name} missing param: {key}")

        elif op in _NFT_REQUIRED:
            for key in _NFT_REQUIRED[op]:
                if key not in p:
                    raise ValueError(f"{op.name} missing param: {key}")

        elif op == ExchangeOpType.STAKE_DEPOSIT:
            for key in ("validator_public_key", "stake_amount"):
                if key not in p:
                    raise ValueError(f"STAKE_DEPOSIT missing param: {key}")

        elif op == ExchangeOpType.STAKE_EXIT:
            pass  # the sender exits their own validator; no extra params

        elif op == ExchangeOpType.REMOVE_POOL:
            if not self.params.get("pool_id"):
                raise ValueError("REMOVE_POOL missing param: pool_id")

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
    ExchangeOpType.CREATE_MARKET: 100_000,
    ExchangeOpType.TOKEN_DEPLOY: 120_000,
    ExchangeOpType.TOKEN_TRANSFER: 40_000,
    ExchangeOpType.STAKE_DEPOSIT: 150_000,
    ExchangeOpType.STAKE_EXIT: 80_000,
    ExchangeOpType.REMOVE_POOL: 60_000,
    ExchangeOpType.PERP_DEPOSIT: 40_000,
    ExchangeOpType.PERP_WITHDRAW: 40_000,
    ExchangeOpType.PERP_SET_LEVERAGE: 20_000,
    ExchangeOpType.PERP_ORDER: 60_000,
    ExchangeOpType.PERP_CANCEL: 25_000,
    ExchangeOpType.VAULT_DEPOSIT: 40_000,
    ExchangeOpType.VAULT_WITHDRAW: 40_000,
    ExchangeOpType.ORACLE_VOTE: 30_000,
    ExchangeOpType.TOKEN_MINT: 40_000,
    ExchangeOpType.TOKEN_BURN: 30_000,
    ExchangeOpType.TOKEN_APPROVE: 25_000,
    ExchangeOpType.TOKEN_TRANSFER_FROM: 45_000,
    ExchangeOpType.TOKEN_SET_AUTHORITY: 25_000,
    ExchangeOpType.TOKEN_FREEZE: 25_000,
    ExchangeOpType.TOKEN_THAW: 25_000,
    ExchangeOpType.TOKEN_UPDATE_METADATA: 30_000,
    ExchangeOpType.TOKEN_SET_TRANSFER_FEE: 25_000,
    ExchangeOpType.TOKEN_WITHDRAW_FEES: 40_000,
    ExchangeOpType.TOKEN_PAUSE: 25_000,
    ExchangeOpType.TOKEN_RESUME: 25_000,
    ExchangeOpType.TOKEN_AUTHORIZE_OPERATOR: 25_000,
    ExchangeOpType.TOKEN_REVOKE_OPERATOR: 25_000,
    ExchangeOpType.NFT_CREATE_COLLECTION: 120_000,
    ExchangeOpType.NFT_MINT: 60_000,
    ExchangeOpType.NFT_TRANSFER: 35_000,
    ExchangeOpType.NFT_BURN: 25_000,
    ExchangeOpType.NFT_APPROVE: 25_000,
    ExchangeOpType.NFT_SET_APPROVAL_FOR_ALL: 25_000,
    ExchangeOpType.NFT_UPDATE: 30_000,
    ExchangeOpType.NFT_SET_AUTHORITY: 25_000,
}

_NFT_REQUIRED = {
    ExchangeOpType.NFT_CREATE_COLLECTION: ("name", "symbol"),
    ExchangeOpType.NFT_MINT: ("collection",),
    ExchangeOpType.NFT_TRANSFER: ("collection", "token_id", "to"),
    ExchangeOpType.NFT_BURN: ("collection", "token_id"),
    ExchangeOpType.NFT_APPROVE: ("collection", "token_id", "spender"),
    ExchangeOpType.NFT_SET_APPROVAL_FOR_ALL: ("collection", "operator"),
    ExchangeOpType.NFT_UPDATE: ("collection",),
    ExchangeOpType.NFT_SET_AUTHORITY: ("collection", "authority", "new_authority"),
}
