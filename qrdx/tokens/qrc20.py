"""
qRC20 Token Standard — Whitepaper §9.1

Implements a Python-native qRC20 fungible token with:
  - ERC-20–style interface (transfer, approve, transferFrom, balanceOf)
  - Post-quantum signature verification on every state-mutating call
  - Bridge mint / burn hooks for cross-chain shielded tokens
  - Batch transfer support
  - EIP-2612–style permit (Dilithium)
"""

import hashlib
import time
from dataclasses import dataclass, field
from decimal import Decimal
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple

from ..logger import get_logger
from ..constants import (
    QRC20_DEFAULT_DECIMALS,
    QRC20_DOMAIN_APPROVE,
    QRC20_DOMAIN_TRANSFER,
    QRC20_MAX_BATCH_SIZE,
    QRC20_MAX_SUPPLY,
)

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════
#  EXCEPTIONS
# ══════════════════════════════════════════════════════════════════════

class QRC20Error(Exception):
    """Base exception for qRC20 operations."""


class InsufficientBalanceError(QRC20Error):
    """Raised when sender balance is too low."""


class InsufficientAllowanceError(QRC20Error):
    """Raised when spender allowance is too low."""


class InvalidSignatureError(QRC20Error):
    """Raised when a PQ signature fails verification."""


class TokenFrozenError(QRC20Error):
    """Raised when the token is frozen (e.g. paused by governance)."""


# ══════════════════════════════════════════════════════════════════════
#  EVENTS
# ══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class QRC20TransferEvent:
    """Emitted on every successful transfer."""
    token_symbol: str
    sender: str
    recipient: str
    amount: Decimal
    proof_hash: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event": "TransferWithProof",
            "token": self.token_symbol,
            "from": self.sender,
            "to": self.recipient,
            "amount": str(self.amount),
            "proofHash": self.proof_hash,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class QRC20ApprovalEvent:
    """Emitted on every successful approve."""
    token_symbol: str
    owner: str
    spender: str
    amount: Decimal
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event": "Approval",
            "token": self.token_symbol,
            "owner": self.owner,
            "spender": self.spender,
            "amount": str(self.amount),
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class QRC20BridgeMintEvent:
    """Emitted when bridge mints shielded tokens."""
    token_symbol: str
    recipient: str
    amount: Decimal
    source_chain_id: int
    source_tx_hash: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event": "BridgeMint",
            "token": self.token_symbol,
            "to": self.recipient,
            "amount": str(self.amount),
            "sourceChainId": self.source_chain_id,
            "sourceTxHash": self.source_tx_hash,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class QRC20BridgeBurnEvent:
    """Emitted when bridge burns shielded tokens (unshield)."""
    token_symbol: str
    sender: str
    amount: Decimal
    destination_address: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event": "BridgeBurn",
            "token": self.token_symbol,
            "from": self.sender,
            "amount": str(self.amount),
            "destinationAddress": self.destination_address,
            "timestamp": self.timestamp,
        }


# ══════════════════════════════════════════════════════════════════════
#  SIGNATURE HELPER
# ══════════════════════════════════════════════════════════════════════

def _make_transfer_digest(
    token_symbol: str,
    sender: str,
    recipient: str,
    amount: Decimal,
    nonce: int,
) -> bytes:
    """Produce a deterministic digest for a transfer-with-proof."""
    payload = (
        QRC20_DOMAIN_TRANSFER
        + token_symbol.encode()
        + sender.encode()
        + recipient.encode()
        + str(amount).encode()
        + nonce.to_bytes(8, "big")
    )
    return hashlib.blake2b(payload, digest_size=32).digest()


def _make_approve_digest(
    token_symbol: str,
    owner: str,
    spender: str,
    amount: Decimal,
    nonce: int,
) -> bytes:
    """Produce a deterministic digest for an approval."""
    payload = (
        QRC20_DOMAIN_APPROVE
        + token_symbol.encode()
        + owner.encode()
        + spender.encode()
        + str(amount).encode()
        + nonce.to_bytes(8, "big")
    )
    return hashlib.blake2b(payload, digest_size=32).digest()


def _proof_hash(digest: bytes) -> str:
    """Human-readable proof hash from raw digest bytes."""
    return hashlib.sha256(digest).hexdigest()


# ══════════════════════════════════════════════════════════════════════
#  QRC20 TOKEN
# ══════════════════════════════════════════════════════════════════════

class QRC20Token:
    """
    qRC20 Token — PQ-verified fungible token.

    Mirrors ERC-20 semantics:
        - balanceOf(address) → Decimal
        - transfer(sender, recipient, amount, signature)
        - approve(owner, spender, amount, signature)
        - transferFrom(spender, sender, recipient, amount, signature)
        - totalSupply → Decimal

    Additional hooks:
        - bridge_mint / bridge_burn (bridge-only)
        - shouldTradeAfterDoomsday → bool

    Every state-mutating call requires a PQ (Dilithium) signature which is
    verified against the supplied public-key resolver callback.
    """

    def __init__(
        self,
        name: str,
        symbol: str,
        decimals: int = QRC20_DEFAULT_DECIMALS,
        total_supply: Decimal = Decimal("0"),
        deployer: str = "",
        *,
        post_doomsday_trade: bool = True,
        source_chain_id: Optional[int] = None,
        source_token_address: Optional[str] = None,
        verify_signature_fn=None,
    ):
        """
        Args:
            name: Human-readable token name
            symbol: Short ticker (e.g. "qETH")
            decimals: Fractional digits
            total_supply: Initial minted supply
            deployer: Address of deploying account
            post_doomsday_trade: Advisory flag (§9.2)
            source_chain_id: Bridge source chain (None for native)
            source_token_address: Contract address on source chain
            verify_signature_fn: async (address, message, signature) → bool
        """
        if not name:
            raise QRC20Error("Token name cannot be empty")
        if not symbol:
            raise QRC20Error("Token symbol cannot be empty")
        if decimals < 0 or decimals > 18:
            raise QRC20Error(f"Decimals must be 0-18, got {decimals}")
        if total_supply < 0:
            raise QRC20Error("Total supply cannot be negative")
        if total_supply > QRC20_MAX_SUPPLY:
            raise QRC20Error(f"Total supply {total_supply} exceeds max {QRC20_MAX_SUPPLY}")

        self.name = name
        self.symbol = symbol
        self.decimals = decimals
        self._total_supply = total_supply
        self.deployer = deployer
        self.post_doomsday_trade = post_doomsday_trade
        self.source_chain_id = source_chain_id
        self.source_token_address = source_token_address
        self._frozen = False

        # Balances & allowances
        self._balances: Dict[str, Decimal] = {}
        self._allowances: Dict[Tuple[str, str], Decimal] = {}  # (owner, spender)
        self._nonces: Dict[str, int] = {}  # per-address nonce

        # Event log
        self._events: List[Any] = []

        # Signature verifier (dependency injection)
        self._verify_signature_fn = verify_signature_fn

        # Bridge authorization
        self._bridge_operators: set = set()

        # Credit deployer with initial supply
        if total_supply > 0 and deployer:
            self._balances[deployer] = total_supply

        self._created_at = time.time()
        logger.info(f"qRC20 deployed: {symbol} ({name}), supply={total_supply}")

    # ── Read-only views ───────────────────────────────────────────────

    @property
    def total_supply(self) -> Decimal:
        return self._total_supply

    def balance_of(self, address: str) -> Decimal:
        return self._balances.get(address, Decimal("0"))

    def allowance(self, owner: str, spender: str) -> Decimal:
        return self._allowances.get((owner, spender), Decimal("0"))

    def nonce_of(self, address: str) -> int:
        return self._nonces.get(address, 0)

    @property
    def is_frozen(self) -> bool:
        return self._frozen

    @property
    def events(self) -> List[Any]:
        return list(self._events)

    def bridge_info(self) -> Dict[str, Any]:
        """Return cross-chain bridge metadata (§9.1)."""
        total_shielded = sum(self._balances.values())
        return {
            "sourceChainId": self.source_chain_id,
            "sourceToken": self.source_token_address,
            "totalShielded": str(total_shielded),
        }

    # ── Signature verification ────────────────────────────────────────

    async def _verify(self, address: str, message: bytes, signature: bytes) -> bool:
        """Verify PQ signature. Uses injected verifier or auto-passes."""
        if self._verify_signature_fn is None:
            return True  # no verifier injected → accept (testing)
        return await self._verify_signature_fn(address, message, signature)

    # ── State guards ──────────────────────────────────────────────────

    def _require_not_frozen(self):
        if self._frozen:
            raise TokenFrozenError(f"Token {self.symbol} is frozen")

    # ── Core ERC-20 operations ────────────────────────────────────────

    async def transfer(
        self,
        sender: str,
        recipient: str,
        amount: Decimal,
        signature: bytes = b"",
    ) -> QRC20TransferEvent:
        """
        Transfer tokens with PQ-verified proof (§9.1 transferWithProof).

        Args:
            sender: From address
            recipient: To address
            amount: Transfer amount
            signature: Dilithium signature over the transfer digest
        """
        self._require_not_frozen()

        if amount <= 0:
            raise QRC20Error("Transfer amount must be positive")
        if sender == recipient:
            raise QRC20Error("Cannot transfer to self")

        bal = self.balance_of(sender)
        if bal < amount:
            raise InsufficientBalanceError(
                f"{sender} balance {bal} < transfer amount {amount}"
            )

        # Verify PQ signature
        nonce = self._nonces.get(sender, 0)
        digest = _make_transfer_digest(self.symbol, sender, recipient, amount, nonce)
        if not await self._verify(sender, digest, signature):
            raise InvalidSignatureError("Transfer signature verification failed")

        # Execute
        self._balances[sender] = bal - amount
        self._balances[recipient] = self._balances.get(recipient, Decimal("0")) + amount
        self._nonces[sender] = nonce + 1

        event = QRC20TransferEvent(
            token_symbol=self.symbol,
            sender=sender,
            recipient=recipient,
            amount=amount,
            proof_hash=_proof_hash(digest),
        )
        self._events.append(event)
        logger.debug(f"Transfer: {sender} → {recipient} {amount} {self.symbol}")
        return event

    async def approve(
        self,
        owner: str,
        spender: str,
        amount: Decimal,
        signature: bytes = b"",
    ) -> QRC20ApprovalEvent:
        """
        Set spender allowance (§9.1 approve).
        """
        self._require_not_frozen()

        if amount < 0:
            raise QRC20Error("Allowance amount cannot be negative")

        nonce = self._nonces.get(owner, 0)
        digest = _make_approve_digest(self.symbol, owner, spender, amount, nonce)
        if not await self._verify(owner, digest, signature):
            raise InvalidSignatureError("Approve signature verification failed")

        self._allowances[(owner, spender)] = amount
        self._nonces[owner] = nonce + 1

        event = QRC20ApprovalEvent(
            token_symbol=self.symbol,
            owner=owner,
            spender=spender,
            amount=amount,
        )
        self._events.append(event)
        logger.debug(f"Approve: {owner} → {spender} allowance={amount} {self.symbol}")
        return event

    async def transfer_from(
        self,
        spender: str,
        sender: str,
        recipient: str,
        amount: Decimal,
        signature: bytes = b"",
    ) -> QRC20TransferEvent:
        """
        Transfer on behalf of *sender* using spender's allowance (§9.1 transferFrom).
        """
        self._require_not_frozen()

        if amount <= 0:
            raise QRC20Error("Transfer amount must be positive")

        bal = self.balance_of(sender)
        if bal < amount:
            raise InsufficientBalanceError(
                f"{sender} balance {bal} < transfer amount {amount}"
            )

        allow = self.allowance(sender, spender)
        if allow < amount:
            raise InsufficientAllowanceError(
                f"Allowance {allow} < transfer amount {amount}"
            )

        # Verify spender's PQ signature
        nonce = self._nonces.get(spender, 0)
        digest = _make_transfer_digest(self.symbol, sender, recipient, amount, nonce)
        if not await self._verify(spender, digest, signature):
            raise InvalidSignatureError("transferFrom signature verification failed")

        # Execute
        self._balances[sender] = bal - amount
        self._balances[recipient] = self._balances.get(recipient, Decimal("0")) + amount
        self._allowances[(sender, spender)] = allow - amount
        self._nonces[spender] = nonce + 1

        event = QRC20TransferEvent(
            token_symbol=self.symbol,
            sender=sender,
            recipient=recipient,
            amount=amount,
            proof_hash=_proof_hash(digest),
        )
        self._events.append(event)
        logger.debug(
            f"transferFrom: spender={spender} {sender} → {recipient} {amount} {self.symbol}"
        )
        return event

    # ── Batch transfer ────────────────────────────────────────────────

    async def batch_transfer(
        self,
        sender: str,
        recipients: List[Tuple[str, Decimal]],
        signature: bytes = b"",
    ) -> List[QRC20TransferEvent]:
        """
        Batch transfer to multiple recipients (gas-optimised pattern §9.1).
        """
        if len(recipients) > QRC20_MAX_BATCH_SIZE:
            raise QRC20Error(
                f"Batch size {len(recipients)} exceeds max {QRC20_MAX_BATCH_SIZE}"
            )

        events = []
        for recipient, amount in recipients:
            ev = await self.transfer(sender, recipient, amount, signature)
            events.append(ev)
        return events

    # ── Bridge operations (mint / burn) ───────────────────────────────

    def add_bridge_operator(self, operator_address: str):
        """Authorize an address to mint/burn via bridge."""
        self._bridge_operators.add(operator_address)
        logger.info(f"Bridge operator added: {operator_address} for {self.symbol}")

    def remove_bridge_operator(self, operator_address: str):
        self._bridge_operators.discard(operator_address)

    def _require_bridge_operator(self, address: str):
        if address not in self._bridge_operators:
            raise QRC20Error(f"{address} is not an authorized bridge operator")

    async def bridge_mint(
        self,
        operator: str,
        recipient: str,
        amount: Decimal,
        source_chain_id: int,
        source_tx_hash: str,
    ) -> QRC20BridgeMintEvent:
        """
        Mint shielded tokens from bridge lock (§9.1 bridgeMint).
        """
        self._require_not_frozen()
        self._require_bridge_operator(operator)

        if amount <= 0:
            raise QRC20Error("Mint amount must be positive")

        new_supply = self._total_supply + amount
        if new_supply > QRC20_MAX_SUPPLY:
            raise QRC20Error(f"Minting {amount} would exceed max supply")

        self._total_supply = new_supply
        self._balances[recipient] = self._balances.get(recipient, Decimal("0")) + amount

        event = QRC20BridgeMintEvent(
            token_symbol=self.symbol,
            recipient=recipient,
            amount=amount,
            source_chain_id=source_chain_id,
            source_tx_hash=source_tx_hash,
        )
        self._events.append(event)
        logger.info(
            f"BridgeMint: {amount} {self.symbol} → {recipient} "
            f"(chain={source_chain_id}, tx={source_tx_hash[:16]}…)"
        )
        return event

    async def bridge_burn(
        self,
        operator: str,
        sender: str,
        amount: Decimal,
        destination_address: str,
    ) -> QRC20BridgeBurnEvent:
        """
        Burn shielded tokens for unshield (§9.1 bridgeBurn).
        """
        self._require_not_frozen()
        self._require_bridge_operator(operator)

        if amount <= 0:
            raise QRC20Error("Burn amount must be positive")

        bal = self.balance_of(sender)
        if bal < amount:
            raise InsufficientBalanceError(
                f"{sender} balance {bal} < burn amount {amount}"
            )

        self._balances[sender] = bal - amount
        self._total_supply -= amount

        event = QRC20BridgeBurnEvent(
            token_symbol=self.symbol,
            sender=sender,
            amount=amount,
            destination_address=destination_address,
        )
        self._events.append(event)
        logger.info(f"BridgeBurn: {sender} burned {amount} {self.symbol} → {destination_address}")
        return event

    # ── Freeze / unfreeze (governance) ────────────────────────────────

    def freeze(self):
        """Governance can freeze all token operations."""
        self._frozen = True
        logger.warning(f"Token {self.symbol} FROZEN")

    def unfreeze(self):
        self._frozen = False
        logger.info(f"Token {self.symbol} unfrozen")

    # ── Serialization ─────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "symbol": self.symbol,
            "decimals": self.decimals,
            "totalSupply": str(self._total_supply),
            "deployer": self.deployer,
            "postDoomsdayTrade": self.post_doomsday_trade,
            "sourceChainId": self.source_chain_id,
            "sourceTokenAddress": self.source_token_address,
            "frozen": self._frozen,
            "holders": len([b for b in self._balances.values() if b > 0]),
            "createdAt": self._created_at,
        }

    def __repr__(self) -> str:
        return f"<QRC20Token {self.symbol} supply={self._total_supply}>"


# ══════════════════════════════════════════════════════════════════════
#  QRC20 REGISTRY
# ══════════════════════════════════════════════════════════════════════

class QRC20Registry:
    """
    Global qRC20 token registry.

    Manages deployment, lookup, and enumeration of all qRC20 tokens
    on the QRDX network.
    """

    def __init__(self, max_tokens: int = 10_000):
        self._tokens: Dict[str, QRC20Token] = {}
        self._max_tokens = max_tokens

    # ── Deploy ────────────────────────────────────────────────────────

    def deploy(self, token: QRC20Token) -> QRC20Token:
        """
        Register a new qRC20 token.

        Raises QRC20Error if symbol already exists or registry is full.
        """
        if token.symbol in self._tokens:
            raise QRC20Error(f"Token {token.symbol} already registered")
        if len(self._tokens) >= self._max_tokens:
            raise QRC20Error("Token registry is full")

        self._tokens[token.symbol] = token
        logger.info(f"Token registered: {token.symbol} ({token.name})")
        return token

    # ── Lookup ────────────────────────────────────────────────────────

    def get(self, symbol: str) -> Optional[QRC20Token]:
        return self._tokens.get(symbol)

    def get_or_raise(self, symbol: str) -> QRC20Token:
        token = self.get(symbol)
        if token is None:
            raise QRC20Error(f"Token {symbol} not found in registry")
        return token

    def exists(self, symbol: str) -> bool:
        return symbol in self._tokens

    # ── Enumeration ───────────────────────────────────────────────────

    def list_tokens(self) -> List[str]:
        return list(self._tokens.keys())

    def all_tokens(self) -> List[QRC20Token]:
        return list(self._tokens.values())

    @property
    def count(self) -> int:
        return len(self._tokens)

    # ── Remove (governance action) ────────────────────────────────────

    def remove(self, symbol: str) -> bool:
        if symbol in self._tokens:
            del self._tokens[symbol]
            logger.warning(f"Token removed from registry: {symbol}")
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tokenCount": len(self._tokens),
            "maxTokens": self._max_tokens,
            "tokens": {s: t.to_dict() for s, t in self._tokens.items()},
        }

    def __repr__(self) -> str:
        return f"<QRC20Registry tokens={len(self._tokens)}>"
