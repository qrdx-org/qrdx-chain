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
from dataclasses import dataclass, field
from decimal import Decimal
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple

ZERO = Decimal("0")


def _min_gas_price() -> int:
    from .. import constants

    return constants.EXCHANGE_MIN_GAS_PRICE_WEI


def _network_chain_id() -> int:
    """The chain id of this process's network (its chain spec)."""
    from .. import chain_spec

    return chain_spec.active().chain_id


_SIGNING_TAG = b"QRDX-EXCHANGE-TX-v1\x00"


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
    VAULT_DEPOSIT = 23  # perps backstop vault: collateral in, shares at NAV
    VAULT_WITHDRAW = 24  # shares out at NAV, after the lockup
    ORACLE_VOTE = 25  # a validator's USD prices for perp markets
    # The native token standard (qrdx/exchange/tokens.py): authorities, supply, allowances.
    TOKEN_MINT = 26  # the mint authority mints new supply
    TOKEN_BURN = 27  # a holder burns its own balance
    TOKEN_APPROVE = 28  # set a spender's allowance (0 revokes)
    TOKEN_TRANSFER_FROM = 29  # a spender moves an owner's tokens within its allowance
    TOKEN_SET_AUTHORITY = 30  # hand over or renounce the mint / freeze authority
    TOKEN_FREEZE = 31  # the freeze authority freezes an account's balance
    TOKEN_THAW = 32  # … and thaws it
    # Token-2022-style extensions and ERC-777 operators (docs/NATIVE_TOKENS.md §7).
    TOKEN_UPDATE_METADATA = 33  # the metadata authority edits name, symbol, uri, fields
    TOKEN_SET_TRANSFER_FEE = 34  # the fee authority sets a new rate (applies later)
    TOKEN_WITHDRAW_FEES = 35  # the withdraw authority collects withheld transfer fees
    TOKEN_PAUSE = 36  # the pause authority stops transfers, mints and burns
    TOKEN_RESUME = 37  # … and lets them run again
    TOKEN_AUTHORIZE_OPERATOR = 38  # a holder lets an operator move its balance
    TOKEN_REVOKE_OPERATOR = 39  # … and stops it (a default operator too)
    # Native NFTs (qrdx/exchange/nfts.py): collections of supply-1 tokens.
    NFT_CREATE_COLLECTION = 40  # a collection: metadata, royalties, update + mint authorities
    NFT_MINT = 41  # the mint authority adds an NFT to the collection
    NFT_TRANSFER = 42  # the owner (or its approved account / operator) moves one
    NFT_BURN = 43  # … or burns it
    NFT_APPROVE = 44  # the owner approves one account for one NFT
    NFT_SET_APPROVAL_FOR_ALL = 45  # the owner approves an operator for all its NFTs in a collection
    NFT_UPDATE = 46  # the update authority edits the collection's or an NFT's metadata
    NFT_SET_AUTHORITY = 47  # hand over or renounce the update / mint authority
    # On-chain governance (qrdx/exchange/governance.py, docs/GOVERNANCE.md).
    GOV_PROPOSE = 48  # a validator proposes: system_spend, freeze_master, approve_fork
    GOV_VOTE = 49  # a validator votes, weighted by its committee stake
    GOV_VETO = 50  # a holder locks QRDX against a passed proposal (timelock only)
    GOV_EXECUTE = 51  # anyone executes a proposal whose timelock has ended
    # Consensus bridge (docs/BRIDGE.md): deposits are attested in ORACLE_VOTEs.
    BRIDGE_WITHDRAW = 52  # burn a bridged token; the lockbox's custodian releases it
    # Delegation pools (docs/STAKING.md): stake with a validator without running one.
    STAKE_DELEGATE = 53  # lock QRDX in a validator's pool
    STAKE_UNDELEGATE = 54  # redeem pool shares (unbonding, then paid)
    STAKE_SET_COMMISSION = 55  # a validator sets its cut of its pool's rewards
    # Trading (docs/TRADING_FEATURES.md).
    PERP_TRIGGER = 56  # a stop / take-profit order, fired on the mark price
    CANCEL_ALL = 57  # every resting order and trigger of the sender (or of one market)
    PERP_MODIFY = 58  # change a perp order or trigger in one step
    MODIFY_ORDER = 59  # change a spot order in one step
    BATCH = 60  # several trading operations, all or nothing
    TWAP_ORDER = 61  # a size worked into the market in slices over a duration
    TWAP_CANCEL = 62  # stop a TWAP (a spot TWAP's unspent escrow comes back)
    # Acting for an account (docs/TRADING_FEATURES.md).
    AGENT_APPROVE = 63  # let an agent key sign trading operations for the account
    AGENT_REVOKE = 64  # … and stop it
    SUBACCOUNT_CREATE = 65  # a sub-account: its own balances and margin, signed for by the master
    SUBACCOUNT_TRANSFER = 66  # move QRDX or a token between the master and a sub-account
    VAULT_CREATE = 67  # a user vault: a margin account its leader trades and others join
    REFERRAL_REGISTER = 68  # take a referral code
    REFERRAL_JOIN = 69  # join a referrer's code (a fee discount; the referrer shares the fees)
    # Account control (docs/ACCOUNT_CONTROL.md).
    ACCOUNT_POLICY = 70  # bind controllers, turn the own key off or on, set the delay, cancel
    # QNS, the QRDX Name Service (docs/QNS.md): names are native NFTs.
    QNS_REGISTER = 71  # register label.qrdx for some years
    QNS_RENEW = 72  # extend a name (anyone may pay)
    QNS_SET_RECORD = 73  # the owner sets where it resolves, or a text record
    QNS_SET_PRIMARY = 74  # an account's reverse record
    ACCOUNT_RECOVER = 75  # a guardian backs a new controller for an account (social recovery)
    PERP_ISOLATED_MARGIN = 76  # add margin to (or remove it from) an isolated position
    SCHEDULE_CANCEL = 77  # the dead man's switch: cancel every order at a block time
    APPROVE_BUILDER_FEE = 78  # let a front-end (builder) charge up to a fee rate on orders
    # Deployer markets (docs/HYPERLIQUID_PARITY.md, Hyperliquid's HIP-3): perp markets a bonded
    # deployer lists under its own namespace and runs the oracle of.
    DEPLOYER_BOND = 79  # bond QRDX as a market deployer (the first bond names its namespace)
    DEPLOYER_UNBOND = 80  # start unbonding some of it, or claim what has unbonded
    DEPLOYER_SET_ORACLE = 81  # the deployer's oracle price for one of its markets
    DEPLOYER_HALT = 82  # the deployer settles one of its markets at its oracle price


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
    sender: str  # PQ address of the signer
    nonce: int  # per-sender monotonic nonce
    params: Dict[str, Any]  # operation-specific parameters
    gas_limit: int = 100_000  # max gas for this operation
    gas_price: int = field(default_factory=_min_gas_price)  # WEI per gas (1 QRDX = 10^18 wei)
    timestamp: float = 0.0  # submission timestamp
    signature: bytes = b""  # Dilithium signature
    public_key: bytes = b""  # Dilithium public key
    # The network this transaction is for (EIP-155's role): signed, part of the hash, and
    # checked against the verifying node's chain id — a transaction signed for another network
    # never verifies here. Defaults to this process's network.
    chain_id: int = field(default_factory=_network_chain_id)
    # Who signed it, when that is not ``sender`` (docs/TRADING_FEATURES.md, "Acting for an
    # account"): an agent key the account approved (AGENT_APPROVE), trading only, or the master
    # of a sub-account. Signed and part of the hash; the signature binds to this key, and
    # execution refuses — consuming nothing — unless the account authorized it. Its nonces
    # are its own lane (``nonce_key``), so a bot and its owner's wallet never race.
    signer: str = ""

    # --- Computed after execution ---
    gas_used: int = 0
    success: bool = False
    result: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()
        if isinstance(self.chain_id, bool) or not isinstance(self.chain_id, int):
            try:
                self.chain_id = int(str(self.chain_id))
            except ValueError:
                raise ValueError(f"chain_id must be an integer, got {self.chain_id!r}") from None
        if not 0 <= self.chain_id < 2**63:
            raise ValueError(f"chain_id out of range: {self.chain_id}")
        self.signer = str(self.signer or "")
        if self.signer == self.sender:
            self.signer = ""  # the account itself: one form, one hash
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
        params_json = json.dumps(self.params, sort_keys=True, default=str).encode("utf-8")
        parts = [
            _SIGNING_TAG,
            int(self.chain_id).to_bytes(8, "big"),
            self.op_type.to_bytes(1, "big"),
            self.sender.encode("utf-8"),
            self.nonce.to_bytes(8, "big"),
            params_json,
            self.gas_limit.to_bytes(8, "big"),
            str(self.gas_price).encode("utf-8"),
        ]
        if self.signer:  # (only then: every other transaction keeps its bytes and hash)
            parts.append(b"\x00signer:" + self.signer.encode("utf-8"))
        return b"".join(parts)

    def signature_gas(self) -> int:
        """What verifying the signature costs beyond a single key's: a multisig's every
        partial signature (``MULTISIG_GAS_PER_SIGNATURE`` each)."""
        from ..crypto import multisig_wire

        return multisig_wire.signer_count(self.signature) * MULTISIG_GAS_PER_SIGNATURE

    def nonce_key(self) -> str:
        """The nonce sequence this transaction takes its nonce from: the account's own, or
        — signed by an agent or a sub-account's master — that signer's lane for it."""
        return f"{self.sender}|{self.signer}" if self.signer else self.sender

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
        if self.chain_error():
            return False
        signing_address = str(self.signer or self.sender)
        from ..crypto import multisig_wire

        if multisig_wire.is_multisig_material(self.public_key):
            # An m-of-n multisig (docs/ACCOUNT_CONTROL.md): the keyset derives the address it
            # signs for, and at least m of its keys signed.
            proven = multisig_wire.verify(self.public_key, self.signature, self.signing_bytes())
            return proven is not None and proven.lower() == signing_address.lower()
        try:
            from ..crypto.pq.dilithium import PQPublicKey, PQSignature, verify as pq_verify

            pub = PQPublicKey.from_bytes(self.public_key)

            # Binding: the key must derive to the claimed sender address — or to the signer
            # acting for it, whose authority execution checks (``signer_error``).
            if pub.to_address().lower() != signing_address.lower():
                return False

            return pq_verify(pub, self.signing_bytes(), PQSignature.from_bytes(self.signature))
        except Exception:
            # Malformed key/signature material → unauthenticated.
            return False

    def chain_error(self) -> str:
        """Why this transaction is not for this network ("" if it is)."""
        expected = _network_chain_id()
        if not self.chain_id:
            return (
                f"exchange transaction is not bound to a chain id; sign it for chain id "
                f"{expected}"
            )
        if self.chain_id != expected:
            return (
                f"exchange transaction is signed for chain id {self.chain_id}, but this "
                f"network's chain id is {expected}"
            )
        return ""

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
            "chain_id": self.chain_id,
            **({"signer": self.signer} if self.signer else {}),
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
            # Absent means unbound (0): such a transaction never verifies. Never defaulted to
            # this network's id — that would make an unbound signature valid everywhere.
            chain_id=data.get("chain_id") or 0,
            signer=data.get("signer") or "",
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

    def expires_at(self) -> Optional[Decimal]:
        """The block time after which the action may not be included (the signed
        ``params.expires_at``, as Hyperliquid's ``expiresAfter``); None if it never expires (or
        the value is not a time)."""
        raw = (self.params or {}).get("expires_at")
        if raw is None or isinstance(raw, bool):
            return None
        try:
            value = Decimal(str(raw))
        except (ArithmeticError, ValueError):
            return None
        return value if value.is_finite() and value >= 0 else None

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
        if self.signer and self.op_type == ExchangeOpType.ORACLE_VOTE:
            raise ValueError("an oracle vote is signed by its validator")
        if (self.params or {}).get("expires_at") is not None and self.expires_at() is None:
            raise ValueError("expires_at is a block time (seconds)")

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
            for key in (
                ("token_in", "token_out", "amount_in") if "path" not in p else ("amount_in",)
            ):
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

        elif op == ExchangeOpType.PERP_TRIGGER:
            for key in ("market_id", "side", "kind", "trigger_price"):
                if key not in p:
                    raise ValueError(f"PERP_TRIGGER missing param: {key}")

        elif op == ExchangeOpType.PERP_MODIFY:
            for key in ("market_id", "order_id"):
                if key not in p:
                    raise ValueError(f"PERP_MODIFY missing param: {key}")

        elif op == ExchangeOpType.MODIFY_ORDER:
            for key in ("pair", "order_id"):
                if key not in p:
                    raise ValueError(f"MODIFY_ORDER missing param: {key}")

        elif op == ExchangeOpType.CANCEL_ALL:
            if p.get("scope", "all") not in ("all", "spot", "perps"):
                raise ValueError("CANCEL_ALL scope is all, spot or perps")

        elif op == ExchangeOpType.TWAP_ORDER:
            if "duration" not in p:
                raise ValueError("TWAP_ORDER missing param: duration")
            need = (
                ("market_id", "side", "size")
                if "market_id" in p
                else ("token_in", "token_out", "amount_in")
            )
            for key in need:
                if key not in p:
                    raise ValueError(f"TWAP_ORDER missing param: {key}")

        elif op == ExchangeOpType.TWAP_CANCEL:
            if "twap_id" not in p:
                raise ValueError("TWAP_CANCEL missing param: twap_id")

        elif op in (ExchangeOpType.AGENT_APPROVE, ExchangeOpType.AGENT_REVOKE):
            if "agent" not in p:
                raise ValueError(f"{op.name} missing param: agent")

        elif op == ExchangeOpType.ACCOUNT_POLICY:
            action = p.get("action")
            required = {
                "add_controller": "controller",
                "remove_controller": "controller",
                "own_key": "enabled",
                "delay": "seconds",
                "cancel": "change_id",
                "publish_keyset": "keyset",
                "guardians": "guardians",
            }
            if action not in required:
                raise ValueError(f"ACCOUNT_POLICY action is one of {', '.join(required)}")
            if required[action] not in p:
                raise ValueError(f"ACCOUNT_POLICY {action} missing param: {required[action]}")

        elif op in (
            ExchangeOpType.QNS_REGISTER,
            ExchangeOpType.QNS_RENEW,
            ExchangeOpType.QNS_SET_RECORD,
            ExchangeOpType.QNS_SET_PRIMARY,
        ):
            if not isinstance(p.get("name"), str):
                raise ValueError(f"{op.name} missing param: name")
            if op == ExchangeOpType.QNS_SET_RECORD and "key" not in p:
                raise ValueError("QNS_SET_RECORD missing param: key")

        elif op == ExchangeOpType.PERP_ISOLATED_MARGIN:
            for key in ("market_id", "amount"):
                if key not in p:
                    raise ValueError(f"PERP_ISOLATED_MARGIN missing param: {key}")

        elif op == ExchangeOpType.APPROVE_BUILDER_FEE:
            for key in ("builder", "max_fee_rate"):
                if key not in p:
                    raise ValueError(f"APPROVE_BUILDER_FEE missing param: {key}")

        elif op == ExchangeOpType.DEPLOYER_BOND:
            if "amount" not in p:
                raise ValueError("DEPLOYER_BOND missing param: amount")
            if "dex" in p and not isinstance(p["dex"], str):
                raise ValueError("DEPLOYER_BOND dex is a name")

        elif op == ExchangeOpType.DEPLOYER_UNBOND:
            if ("amount" in p) == bool(p.get("claim")):
                raise ValueError("DEPLOYER_UNBOND takes an amount, or claim: true")

        elif op == ExchangeOpType.DEPLOYER_SET_ORACLE:
            for key in ("market_id", "price"):
                if key not in p:
                    raise ValueError(f"DEPLOYER_SET_ORACLE missing param: {key}")

        elif op == ExchangeOpType.DEPLOYER_HALT:
            if "market_id" not in p:
                raise ValueError("DEPLOYER_HALT missing param: market_id")

        elif op == ExchangeOpType.ACCOUNT_RECOVER:
            if not isinstance(p.get("account"), str):
                raise ValueError("ACCOUNT_RECOVER missing param: account")
            if not isinstance(p.get("new_controller", ""), str):
                raise ValueError('ACCOUNT_RECOVER new_controller is an address ("": withdraw)')

        elif op in (ExchangeOpType.REFERRAL_REGISTER, ExchangeOpType.REFERRAL_JOIN):
            if not isinstance(p.get("code"), str):
                raise ValueError(f"{op.name} missing param: code")

        elif op == ExchangeOpType.VAULT_CREATE:
            if "amount" not in p:
                raise ValueError("VAULT_CREATE missing param: amount")

        elif op == ExchangeOpType.SUBACCOUNT_TRANSFER:
            for key in ("subaccount", "asset", "amount", "direction"):
                if key not in p:
                    raise ValueError(f"SUBACCOUNT_TRANSFER missing param: {key}")

        elif op == ExchangeOpType.BATCH:
            for _op, _params in batch_actions(p):
                ExchangeTransaction(
                    op_type=_op, sender=self.sender, nonce=0, params=_params, chain_id=self.chain_id
                )._validate_params()

        elif op == ExchangeOpType.VAULT_DEPOSIT:
            if "amount" not in p:
                raise ValueError("VAULT_DEPOSIT missing param: amount")

        elif op == ExchangeOpType.VAULT_WITHDRAW:
            if "shares" not in p:
                raise ValueError("VAULT_WITHDRAW missing param: shares")

        elif op == ExchangeOpType.ORACLE_VOTE:
            prices, deposits = p.get("prices", {}), p.get("deposits", [])
            heads, freeze = p.get("heads", []), p.get("freeze", [])
            if (
                not isinstance(prices, dict)
                or not isinstance(deposits, list)
                or not isinstance(heads, list)
                or not isinstance(freeze, list)
            ):
                raise ValueError("ORACLE_VOTE: prices is a map, deposits, heads and freeze lists")
            if not prices and not deposits and not heads and not freeze:
                raise ValueError("ORACLE_VOTE needs prices, deposits, chain heads or freezes")

        elif op == ExchangeOpType.STAKE_DELEGATE:
            for key in ("validator", "amount"):
                if key not in p:
                    raise ValueError(f"STAKE_DELEGATE missing param: {key}")

        elif op == ExchangeOpType.STAKE_UNDELEGATE:
            if "validator" not in p:
                raise ValueError("STAKE_UNDELEGATE missing param: validator")

        elif op == ExchangeOpType.STAKE_SET_COMMISSION:
            if "commission_bps" not in p:
                raise ValueError("STAKE_SET_COMMISSION missing param: commission_bps")

        elif op == ExchangeOpType.BRIDGE_WITHDRAW:
            for key in ("token_address", "amount", "to"):
                if key not in p:
                    raise ValueError(f"BRIDGE_WITHDRAW missing param: {key}")

        elif op == ExchangeOpType.GOV_PROPOSE:
            if not isinstance(p.get("action"), str):
                raise ValueError("GOV_PROPOSE missing param: action")

        elif op in (ExchangeOpType.GOV_VOTE, ExchangeOpType.GOV_VETO, ExchangeOpType.GOV_EXECUTE):
            if "proposal_id" not in p:
                raise ValueError(f"{op.name} missing param: proposal_id")
            if op == ExchangeOpType.GOV_VOTE and not isinstance(p.get("support"), bool):
                raise ValueError("GOV_VOTE needs support: true or false")
            if op == ExchangeOpType.GOV_VETO and "amount" not in p:
                raise ValueError("GOV_VETO missing param: amount")

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
            if (
                "total_supply" not in p
                and "initial_supply" not in p
                and not p.get("mint_authority")
            ):
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
                raise ValueError(
                    "TOKEN_SET_AUTHORITY missing param: new_authority " "(empty to renounce)"
                )

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
                raise ValueError(
                    "TOKEN_UPDATE_METADATA changes nothing: give name, symbol, " "uri or fields"
                )

        elif op == ExchangeOpType.TOKEN_SET_TRANSFER_FEE:
            for key in ("token_address", "transfer_fee_bps"):
                if key not in p:
                    raise ValueError(f"TOKEN_SET_TRANSFER_FEE missing param: {key}")

        elif op in (
            ExchangeOpType.TOKEN_WITHDRAW_FEES,
            ExchangeOpType.TOKEN_PAUSE,
            ExchangeOpType.TOKEN_RESUME,
        ):
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
        return (
            f"ExchangeTransaction(op={self.op_type.name}, sender={self.sender[:16]}..., "
            f"nonce={self.nonce}, hash={self.tx_hash()[:12]}...)"
        )


# ---------------------------------------------------------------------------
# Gas cost table (consensus-critical constants)
# ---------------------------------------------------------------------------

# Matching's cost (docs/BLOCK_LIMITS.md): each resting order an order visits — filled, skipped
# or cancelled — costs this on top of the operation's base gas, and an order visits no more
# than its gas limit pays for (``orderbook.MatchBudget``). A visit takes ~25 µs; at the rate the
# base costs imply (~2.5 ns a unit of exchange gas) that is 10,000.
EXCHANGE_GAS_PER_MAKER = 10_000
# A transaction signed by a multisig pays this for each partial signature it carries — each is a
# Dilithium verification, like the one a single-key transaction's base gas covers.
MULTISIG_GAS_PER_SIGNATURE = 20_000
# CANCEL_ALL: each order or trigger it cancels costs this on top of its base gas.
EXCHANGE_GAS_PER_CANCEL = 5_000

# BATCH: up to this many actions, each one of these operations (never a batch), run in order as
# the batch's sender — all or nothing. Each action's gas counts against the batch's gas limit.
BATCH_MAX_ACTIONS = 20
BATCH_ACTIONS = frozenset(
    {
        ExchangeOpType.PLACE_ORDER,
        ExchangeOpType.CANCEL_ORDER,
        ExchangeOpType.MODIFY_ORDER,
        ExchangeOpType.SWAP,
        ExchangeOpType.PERP_DEPOSIT,
        ExchangeOpType.PERP_WITHDRAW,
        ExchangeOpType.PERP_SET_LEVERAGE,
        ExchangeOpType.PERP_ORDER,
        ExchangeOpType.PERP_CANCEL,
        ExchangeOpType.PERP_TRIGGER,
        ExchangeOpType.PERP_MODIFY,
        ExchangeOpType.CANCEL_ALL,
        ExchangeOpType.TWAP_ORDER,
        ExchangeOpType.TWAP_CANCEL,
    }
)

# What an agent key may sign for the account that approved it: trading — never moving funds out
# (withdrawals, transfers, deposits), never approving agents, staking or governance.
AGENT_SCOPE = frozenset(
    {
        ExchangeOpType.PLACE_ORDER,
        ExchangeOpType.CANCEL_ORDER,
        ExchangeOpType.MODIFY_ORDER,
        ExchangeOpType.SWAP,
        ExchangeOpType.PERP_SET_LEVERAGE,
        ExchangeOpType.PERP_ORDER,
        ExchangeOpType.PERP_CANCEL,
        ExchangeOpType.PERP_TRIGGER,
        ExchangeOpType.PERP_MODIFY,
        ExchangeOpType.CANCEL_ALL,
        ExchangeOpType.TWAP_ORDER,
        ExchangeOpType.TWAP_CANCEL,
        ExchangeOpType.PERP_ISOLATED_MARGIN,  # (moves value only within the account)
        ExchangeOpType.SCHEDULE_CANCEL,
        ExchangeOpType.DEPLOYER_SET_ORACLE,  # (a deployer's oracle bot signs with an agent key)
        ExchangeOpType.BATCH,  # (if every action is in scope)
    }
)


def batch_actions(params: Dict[str, Any]) -> List[Tuple["ExchangeOpType", Dict[str, Any]]]:
    """A BATCH's actions as (operation, params). Raises ValueError unless it is a list of 1 to
    BATCH_MAX_ACTIONS ``{"op": name or number, "params": {...}}``, each a batchable
    operation."""
    actions = params.get("actions")
    if not isinstance(actions, list) or not 1 <= len(actions) <= BATCH_MAX_ACTIONS:
        raise ValueError(f"BATCH needs actions: a list of 1 to {BATCH_MAX_ACTIONS}")
    out = []
    for i, action in enumerate(actions):
        if not isinstance(action, dict) or not isinstance(action.get("params", {}), dict):
            raise ValueError(f"BATCH action {i}: {{op, params}} expected")
        raw = action.get("op")
        try:
            if isinstance(raw, str):
                op = ExchangeOpType[raw]
            elif isinstance(raw, int) and not isinstance(raw, bool):
                op = ExchangeOpType(raw)
            else:
                raise TypeError(raw)
        except (KeyError, ValueError, TypeError):
            raise ValueError(f"BATCH action {i}: unknown operation {raw!r}") from None
        if op not in BATCH_ACTIONS:
            raise ValueError(f"BATCH action {i}: {op.name} cannot be batched")
        out.append((op, action.get("params", {})))
    return out


def match_budget(op_type: "ExchangeOpType", gas_limit: Optional[int]) -> Optional[int]:
    """How many resting orders an order with this gas limit may visit (None: no limit given —
    an operation built in process, never one from a block)."""
    if gas_limit is None:
        return None
    base = EXCHANGE_GAS_COSTS.get(op_type, 100_000)
    return max(0, (int(gas_limit) - base) // EXCHANGE_GAS_PER_MAKER)


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
    ExchangeOpType.GOV_PROPOSE: 100_000,
    ExchangeOpType.GOV_VOTE: 30_000,
    ExchangeOpType.GOV_VETO: 50_000,
    ExchangeOpType.GOV_EXECUTE: 80_000,
    ExchangeOpType.BRIDGE_WITHDRAW: 60_000,
    ExchangeOpType.STAKE_DELEGATE: 60_000,
    ExchangeOpType.STAKE_UNDELEGATE: 40_000,
    ExchangeOpType.STAKE_SET_COMMISSION: 25_000,
    ExchangeOpType.PERP_TRIGGER: 40_000,  # + the matching it prepays (max_makers)
    ExchangeOpType.CANCEL_ALL: 20_000,  # + EXCHANGE_GAS_PER_CANCEL for each cancelled
    ExchangeOpType.PERP_MODIFY: 60_000,  # + matching, as PERP_ORDER
    ExchangeOpType.MODIFY_ORDER: 40_000,  # + matching, as PLACE_ORDER
    ExchangeOpType.BATCH: 10_000,  # + each action's
    ExchangeOpType.TWAP_ORDER: 40_000,  # + each slice's work and matching, paid up front
    ExchangeOpType.TWAP_CANCEL: 25_000,
    ExchangeOpType.AGENT_APPROVE: 30_000,
    ExchangeOpType.AGENT_REVOKE: 20_000,
    ExchangeOpType.SUBACCOUNT_CREATE: 50_000,
    ExchangeOpType.SUBACCOUNT_TRANSFER: 40_000,
    ExchangeOpType.VAULT_CREATE: 100_000,
    ExchangeOpType.REFERRAL_REGISTER: 30_000,
    ExchangeOpType.REFERRAL_JOIN: 30_000,
    ExchangeOpType.ACCOUNT_POLICY: 40_000,
    ExchangeOpType.QNS_REGISTER: 80_000,
    ExchangeOpType.QNS_RENEW: 40_000,
    ExchangeOpType.QNS_SET_RECORD: 30_000,
    ExchangeOpType.QNS_SET_PRIMARY: 25_000,
    ExchangeOpType.ACCOUNT_RECOVER: 40_000,
    ExchangeOpType.PERP_ISOLATED_MARGIN: 30_000,
    ExchangeOpType.SCHEDULE_CANCEL: 20_000,
    ExchangeOpType.APPROVE_BUILDER_FEE: 25_000,
    ExchangeOpType.DEPLOYER_BOND: 40_000,
    ExchangeOpType.DEPLOYER_UNBOND: 40_000,
    ExchangeOpType.DEPLOYER_SET_ORACLE: 25_000,
    ExchangeOpType.DEPLOYER_HALT: 200_000,  # + what settling the market's positions costs
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
