"""
QRDX Asset Shielding & Doomsday Protocol

Implements:
  - §8.1  Shield: Classical → Quantum-Resistant
  - §8.2  Unshield: Quantum-Resistant → Classical
  - §8.5  Doomsday Protocol (canary wallet, circuit breaker)

Shield flow:
  1. User locks classical asset on source chain (ETH/BTC/SOL)
  2. Adapter detects lock, creates BridgeRecord
  3. Source chain reaches required confirmations
  4. Oracle consensus (≥ 2/3+1 validators attest)
  5. Mint corresponding shielded asset on QRDX (qETH, qBTC, etc.)

Unshield flow:
  1. User burns shielded token on QRDX (BridgeRecord UNSHIELD)
  2. Oracle quorum attests the burn
  3. Unlock classical token on destination chain
  4. High-value (>$100K): 7-day fraud proof window before release

Doomsday Protocol (§8.5):
  - A publicly-known ECDSA "canary" wallet holds 1M QRDX
  - If it is drained by a quantum attacker, shielding is BLOCKED
  - Unshielding continues (users can exit)
  - QRDX trading continues on the quantum-resistant chain
"""

import hashlib
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Callable, Dict, List, Optional, Protocol, runtime_checkable

from .types import (
    BridgeOperationType,
    BridgeRecord,
    BridgeStatus,
    BridgeTokenConfig,
    ChainId,
    ValidatorProof,
)
from ..constants import (
    BRIDGE_FEE_BPS,
    DOOMSDAY_CANARY_ADDRESS,
    DOOMSDAY_CANARY_BOUNTY,
    FRAUD_PROOF_WINDOW_SECONDS,
    HIGH_VALUE_THRESHOLD_USD,
    ORACLE_ATTESTATION_QUORUM_NUMERATOR,
    ORACLE_ATTESTATION_QUORUM_DENOMINATOR,
)
from ..crypto.hashing import keccak256
from ..logger import get_logger

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════════════

# Re-export canary bounty under the legacy alias used by bridge __init__
DOOMSDAY_CANARY_BALANCE = DOOMSDAY_CANARY_BOUNTY

# Domain separator for doomsday proof signing (EIP-712 style)
DOOMSDAY_DOMAIN = b"QRDX-DOOMSDAY-PROTOCOL-v1"

# Default token configurations
DEFAULT_TOKEN_CONFIGS = {
    "ETH": BridgeTokenConfig(
        symbol="ETH",
        shielded_symbol="qETH",
        source_chain_id=ChainId.ETHEREUM,
        source_token_address="native",
        decimals=18,
        active=True,
        min_amount=Decimal("0.01"),
        max_amount=Decimal("10000"),
        confirmations_required=12,
    ),
    "BTC": BridgeTokenConfig(
        symbol="BTC",
        shielded_symbol="qBTC",
        source_chain_id=ChainId.BITCOIN,
        source_token_address="native",
        decimals=8,
        active=True,
        min_amount=Decimal("0.0001"),
        max_amount=Decimal("1000"),
        confirmations_required=6,
    ),
    "SOL": BridgeTokenConfig(
        symbol="SOL",
        shielded_symbol="qSOL",
        source_chain_id=ChainId.SOLANA,
        source_token_address="native",
        decimals=9,
        active=True,
        min_amount=Decimal("0.01"),
        max_amount=Decimal("100000"),
        confirmations_required=32,
    ),
    "USDC": BridgeTokenConfig(
        symbol="USDC",
        shielded_symbol="qUSDC",
        source_chain_id=ChainId.ETHEREUM,
        source_token_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        decimals=6,
        active=True,
        min_amount=Decimal("1"),
        max_amount=Decimal("10000000"),
        confirmations_required=12,
    ),
}


# ══════════════════════════════════════════════════════════════════════
#  DOOMSDAY BRIDGE INTERFACE  (for notification callbacks)
# ══════════════════════════════════════════════════════════════════════

@runtime_checkable
class DoomsdayAware(Protocol):
    """
    Interface for bridge contracts that need doomsday notification.

    Matches Whitepaper §8.5: IDoomsdayAware(bridge).onDoomsday()
    Any registered bridge must implement on_doomsday().
    """

    def on_doomsday(self, block_height: int, timestamp: int) -> None:
        """Called when doomsday protocol is activated."""
        ...


# ══════════════════════════════════════════════════════════════════════
#  DOOMSDAY ATTESTATION  (validator vote for canary drain)
# ══════════════════════════════════════════════════════════════════════

@dataclass
class DoomsdayAttestation:
    """
    A single validator's attestation that the canary wallet has been
    drained, proving a quantum computer has broken ECDSA.

    Attributes:
        validator_address: PQ address of the attesting validator
        canary_address: The canary address being monitored
        observed_balance: Balance the validator observed
        observed_block_height: Block height of the observation
        observed_block_hash: Block hash of the observation
        timestamp: When the attestation was created
        signature: Dilithium signature over the attestation contents
    """
    validator_address: str
    canary_address: str
    observed_balance: Decimal
    observed_block_height: int
    observed_block_hash: str
    timestamp: int
    signature: str = ""

    def attestation_hash(self) -> str:
        """Compute deterministic hash of attestation contents for signing."""
        data = (
            DOOMSDAY_DOMAIN
            + self.validator_address.encode("utf-8")
            + self.canary_address.encode("utf-8")
            + str(self.observed_balance).encode("utf-8")
            + self.observed_block_height.to_bytes(8, "big")
            + bytes.fromhex(self.observed_block_hash.replace("0x", ""))
            + self.timestamp.to_bytes(8, "big")
        )
        return hashlib.sha256(data).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "validator_address": self.validator_address,
            "canary_address": self.canary_address,
            "observed_balance": str(self.observed_balance),
            "observed_block_height": self.observed_block_height,
            "observed_block_hash": self.observed_block_hash,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DoomsdayAttestation":
        return cls(
            validator_address=d["validator_address"],
            canary_address=d["canary_address"],
            observed_balance=Decimal(d["observed_balance"]),
            observed_block_height=d["observed_block_height"],
            observed_block_hash=d["observed_block_hash"],
            timestamp=d["timestamp"],
            signature=d.get("signature", ""),
        )


# ══════════════════════════════════════════════════════════════════════
#  DOOMSDAY PROOF  (aggregated quorum proof)
# ══════════════════════════════════════════════════════════════════════

@dataclass
class DoomsdayProof:
    """
    Aggregated proof that the canary has been drained, containing
    ≥ 2/3+1 validator attestations plus (optionally) an on-chain
    ECDSA signature from the canary address itself.

    Two trigger paths are supported (Whitepaper §8.5):

    Path A — Canary Self-Trigger:
        The canary private key holder calls triggerDoomsday() directly.
        This requires canary_signature to be set (proves ECDSA was broken).

    Path B — Validator Consensus:
        ≥ 2/3+1 validators attest that the canary balance is zero.
        This covers the case where the attacker drains but doesn't call
        the trigger function.

    Attributes:
        attestations: Validator attestations observing canary drain
        canary_signature: Optional ECDSA signature from the canary address
                          proving the private key was derived
        canary_signed_message: Message signed by canary (if canary_signature set)
        trigger_block_height: Block height when trigger was initiated
        verification_hash: SHA-256 of the full proof for on-chain recording
    """
    attestations: List[DoomsdayAttestation] = field(default_factory=list)
    canary_signature: str = ""
    canary_signed_message: str = ""
    trigger_block_height: int = 0
    verification_hash: str = ""

    def compute_verification_hash(self) -> str:
        """Compute SHA-256 over the entire proof for immutable recording."""
        parts = [DOOMSDAY_DOMAIN]
        for att in sorted(self.attestations, key=lambda a: a.validator_address):
            parts.append(att.attestation_hash().encode("utf-8"))
        if self.canary_signature:
            parts.append(self.canary_signature.encode("utf-8"))
        parts.append(self.trigger_block_height.to_bytes(8, "big"))
        return hashlib.sha256(b"".join(parts)).hexdigest()

    @property
    def has_canary_signature(self) -> bool:
        return bool(self.canary_signature)

    @property
    def attestation_count(self) -> int:
        return len(self.attestations)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attestations": [a.to_dict() for a in self.attestations],
            "canary_signature": self.canary_signature,
            "canary_signed_message": self.canary_signed_message,
            "trigger_block_height": self.trigger_block_height,
            "verification_hash": self.verification_hash,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DoomsdayProof":
        return cls(
            attestations=[
                DoomsdayAttestation.from_dict(a) for a in d.get("attestations", [])
            ],
            canary_signature=d.get("canary_signature", ""),
            canary_signed_message=d.get("canary_signed_message", ""),
            trigger_block_height=d.get("trigger_block_height", 0),
            verification_hash=d.get("verification_hash", ""),
        )


# ══════════════════════════════════════════════════════════════════════
#  STATE PERSISTENCE INTERFACE
# ══════════════════════════════════════════════════════════════════════

@runtime_checkable
class DoomsdayStateStore(Protocol):
    """
    Persistence backend for doomsday state.

    Implementations should write to the chain's state trie or a
    dedicated database table so that doomsday state survives node
    restarts and is replicated across all validators.
    """

    def save_doomsday_state(self, state: Dict[str, Any]) -> bool:
        """Persist doomsday state atomically."""
        ...

    def load_doomsday_state(self) -> Optional[Dict[str, Any]]:
        """Load doomsday state from persistent storage."""
        ...


class InMemoryDoomsdayStateStore:
    """
    In-memory fallback for tests. NOT suitable for production.
    """

    def __init__(self):
        self._state: Optional[Dict[str, Any]] = None

    def save_doomsday_state(self, state: Dict[str, Any]) -> bool:
        self._state = dict(state)
        return True

    def load_doomsday_state(self) -> Optional[Dict[str, Any]]:
        return dict(self._state) if self._state else None


# ══════════════════════════════════════════════════════════════════════
#  DOOMSDAY PROTOCOL  (Whitepaper §8.5)
# ══════════════════════════════════════════════════════════════════════

class DoomsdayProtocol:
    """
    Circuit breaker that monitors a publicly-known ECDSA canary wallet.

    If the canary is drained (indicating a quantum attacker can break
    classical crypto), all new shield operations are BLOCKED while
    unshields remain permitted so users can withdraw to safety.

    Security properties (Whitepaper §8.5):
        1. Trigger requires cryptographic proof:
           - Path A: ECDSA signature from the canary address, OR
           - Path B: ≥ 2/3+1 validator attestations of canary drain
        2. Activation is irreversible (survives restarts via state store)
        3. All registered bridges are notified on activation
        4. 1M QRDX bounty is tracked for the trigger caller
        5. State is persisted: block height, timestamp, verification hash

    Whitepaper §8.5 post-doomsday behaviour table:
        ┌──────────────────────┬─────────────┐
        │ Operation            │ Status      │
        ├──────────────────────┼─────────────┤
        │ Shield (lock new)    │ BLOCKED     │
        │ Unshield (withdraw)  │ ALLOWED     │
        │ QRDX native trading  │ NORMAL      │
        │ PQ-signed txns       │ NORMAL      │
        └──────────────────────┴─────────────┘
    """

    def __init__(
        self,
        total_validators: int = 1,
        state_store: Optional[DoomsdayStateStore] = None,
        verify_ecdsa_fn: Optional[Callable[[str, bytes, str], bool]] = None,
    ):
        """
        Args:
            total_validators: Total validators in the active set
                              (used to compute 2/3+1 quorum threshold)
            state_store: Persistent storage backend. If None, uses
                         InMemoryDoomsdayStateStore (test only).
            verify_ecdsa_fn: Callable(address, message_hash, signature) → bool
                             that verifies an ECDSA signature recovers to the
                             given address. If None, canary self-trigger (Path A)
                             is disabled; only validator quorum (Path B) works.
        """
        # ── quorum parameters ──
        if total_validators < 1:
            raise ValueError("total_validators must be >= 1")
        self._total_validators = total_validators
        self._threshold = (
            (total_validators * ORACLE_ATTESTATION_QUORUM_NUMERATOR)
            // ORACLE_ATTESTATION_QUORUM_DENOMINATOR
        ) + 1

        # ── canary identity (from constants — single source of truth) ──
        self._canary_address: str = DOOMSDAY_CANARY_ADDRESS
        self._canary_expected_balance: Decimal = DOOMSDAY_CANARY_BALANCE

        # ── state (loaded from store if available) ──
        self._doomsday_active: bool = False
        self._triggered_at: int = 0
        self._trigger_block_height: int = 0
        self._verification_hash: str = ""
        self._trigger_address: str = ""  # who triggered (canary addr or first attester)
        self._bounty_recipient: str = ""
        self._bounty_amount: Decimal = DOOMSDAY_CANARY_BOUNTY
        self._bounty_paid: bool = False

        # ── attestation buffer (pre-trigger) ──
        self._attestations: List[DoomsdayAttestation] = []
        self._attesting_validators: set = set()  # dedup

        # ── bridge notification registry (Whitepaper §8.5) ──
        self._registered_bridges: List[DoomsdayAware] = []
        self._registered_bridge_ids: set = set()

        # ── persistence ──
        self._state_store: DoomsdayStateStore = (
            state_store or InMemoryDoomsdayStateStore()
        )

        # ── ECDSA verification for Path A ──
        self._verify_ecdsa_fn = verify_ecdsa_fn

        # ── attempt to restore state from store ──
        self._load_state()

    # ── Properties ──────────────────────────────────────────────────

    @property
    def canary_address(self) -> str:
        return self._canary_address

    @property
    def is_active(self) -> bool:
        """Check if doomsday mode is currently active."""
        return self._doomsday_active

    @property
    def threshold(self) -> int:
        """Validator attestation quorum threshold (≥ 2/3+1)."""
        return self._threshold

    @property
    def total_validators(self) -> int:
        return self._total_validators

    # ── Path A: Canary Self-Trigger (§8.5) ──────────────────────────

    def trigger_by_canary_signature(
        self,
        message: bytes,
        signature: str,
        block_height: int = 0,
    ) -> bool:
        """
        Trigger doomsday via ECDSA signature from the canary address.

        This is the primary trigger path: if anyone can sign a message
        with the canary's private key, they've proven quantum capability.

        Whitepaper §8.5:
            ``if (msg.sender != CANARY_ADDRESS) revert InvalidCaller();``

        Args:
            message: The signed message bytes
            signature: Hex-encoded ECDSA signature (65 bytes: r + s + v)
            block_height: Block height at time of trigger

        Returns:
            True if doomsday was triggered, False if rejected
        """
        if self._doomsday_active:
            logger.warning("Doomsday already active — ignoring canary trigger")
            return False

        if self._verify_ecdsa_fn is None:
            logger.error(
                "Canary self-trigger (Path A) unavailable: "
                "no ECDSA verification function configured"
            )
            return False

        # Compute message hash for recovery
        msg_hash = keccak256(DOOMSDAY_DOMAIN + message)

        # Verify the signature recovers to the canary address
        if not self._verify_ecdsa_fn(self._canary_address, msg_hash, signature):
            logger.warning(
                "Doomsday trigger REJECTED — signature does not recover "
                f"to canary address {self._canary_address}"
            )
            return False

        # Build proof
        proof = DoomsdayProof(
            canary_signature=signature,
            canary_signed_message=message.hex(),
            trigger_block_height=block_height,
        )
        proof.verification_hash = proof.compute_verification_hash()

        # Activate
        self._activate(
            proof=proof,
            trigger_address=self._canary_address,
            bounty_recipient=self._canary_address,
            block_height=block_height,
        )
        return True

    # ── Path B: Validator Consensus (§8.5) ──────────────────────────

    def submit_canary_attestation(self, attestation: DoomsdayAttestation) -> bool:
        """
        Submit a validator's attestation that the canary has been drained.

        Once ≥ 2/3+1 validators attest, doomsday is triggered automatically.

        Args:
            attestation: DoomsdayAttestation from a validator

        Returns:
            True if this attestation caused doomsday to trigger
        """
        if self._doomsday_active:
            return False

        # Validate attestation target
        if attestation.canary_address != self._canary_address:
            logger.warning(
                f"Attestation rejected: wrong canary address "
                f"{attestation.canary_address} != {self._canary_address}"
            )
            return False

        # Validate balance observation (must show drain)
        if attestation.observed_balance >= self._canary_expected_balance:
            logger.debug(
                f"Attestation from {attestation.validator_address[:16]}... "
                f"shows balance {attestation.observed_balance} >= expected "
                f"{self._canary_expected_balance} — canary safe"
            )
            return False

        # Reject duplicate from same validator
        if attestation.validator_address in self._attesting_validators:
            logger.debug(
                f"Duplicate attestation from {attestation.validator_address[:16]}..."
            )
            return False

        # Accept attestation
        self._attestations.append(attestation)
        self._attesting_validators.add(attestation.validator_address)

        logger.info(
            f"Doomsday attestation {len(self._attestations)}/{self._threshold} "
            f"from {attestation.validator_address[:16]}... "
            f"(observed balance: {attestation.observed_balance})"
        )

        # Check if quorum is reached
        if len(self._attestations) >= self._threshold:
            proof = DoomsdayProof(
                attestations=list(self._attestations),
                trigger_block_height=attestation.observed_block_height,
            )
            proof.verification_hash = proof.compute_verification_hash()

            self._activate(
                proof=proof,
                trigger_address=attestation.validator_address,
                bounty_recipient=self._attestations[0].validator_address,
                block_height=attestation.observed_block_height,
            )
            return True

        return False

    # ── Legacy API (backward-compatible) ────────────────────────────

    def trigger_doomsday(self, proof: str) -> bool:
        """
        Legacy trigger method — requires structured JSON proof.

        For backward compatibility with existing callers. The proof string
        must be a JSON-encoded DoomsdayProof with either a valid canary
        signature or ≥ threshold validator attestations.

        Args:
            proof: JSON-encoded DoomsdayProof string

        Returns:
            True if doomsday was triggered, False if rejected
        """
        if self._doomsday_active:
            return False

        if not proof:
            logger.warning("Doomsday trigger rejected: empty proof")
            return False

        # Parse structured proof
        try:
            proof_data = json.loads(proof)
            doomsday_proof = DoomsdayProof.from_dict(proof_data)
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning(f"Doomsday trigger rejected: malformed proof — {exc}")
            return False

        # Path A check: canary signature present
        if doomsday_proof.has_canary_signature:
            if self._verify_ecdsa_fn is None:
                logger.error("Cannot verify canary signature — no ECDSA fn")
                return False

            msg_bytes = bytes.fromhex(doomsday_proof.canary_signed_message)
            msg_hash = keccak256(DOOMSDAY_DOMAIN + msg_bytes)

            if not self._verify_ecdsa_fn(
                self._canary_address, msg_hash, doomsday_proof.canary_signature
            ):
                logger.warning("Doomsday proof rejected: invalid canary signature")
                return False

            doomsday_proof.verification_hash = doomsday_proof.compute_verification_hash()
            self._activate(
                proof=doomsday_proof,
                trigger_address=self._canary_address,
                bounty_recipient=self._canary_address,
                block_height=doomsday_proof.trigger_block_height,
            )
            return True

        # Path B check: validator quorum
        if doomsday_proof.attestation_count >= self._threshold:
            # Verify all attestations target the right canary and show drain
            seen_validators: set = set()
            valid_count = 0
            for att in doomsday_proof.attestations:
                if att.canary_address != self._canary_address:
                    continue
                if att.observed_balance >= self._canary_expected_balance:
                    continue
                if att.validator_address in seen_validators:
                    continue
                seen_validators.add(att.validator_address)
                valid_count += 1

            if valid_count < self._threshold:
                logger.warning(
                    f"Doomsday proof rejected: only {valid_count} valid "
                    f"attestations, need {self._threshold}"
                )
                return False

            doomsday_proof.verification_hash = doomsday_proof.compute_verification_hash()
            first_attester = doomsday_proof.attestations[0].validator_address
            self._activate(
                proof=doomsday_proof,
                trigger_address=first_attester,
                bounty_recipient=first_attester,
                block_height=doomsday_proof.trigger_block_height,
            )
            return True

        logger.warning(
            f"Doomsday proof rejected: insufficient evidence "
            f"(attestations={doomsday_proof.attestation_count}, "
            f"threshold={self._threshold}, has_sig={doomsday_proof.has_canary_signature})"
        )
        return False

    def check_canary(self, current_balance: Decimal) -> bool:
        """
        Check the canary wallet balance.

        If balance has been drained (< expected), log a WARNING.
        Doomsday is NOT automatically triggered — that requires
        validator quorum (Path B) or canary signature (Path A)
        to prevent single-node false positives.

        Args:
            current_balance: Current balance of the canary wallet

        Returns:
            True if canary is safe, False if balance is below expected
        """
        if self._doomsday_active:
            return False

        if current_balance < self._canary_expected_balance:
            logger.warning(
                f"CANARY ALERT: balance {current_balance} < expected "
                f"{self._canary_expected_balance} — validators should submit "
                f"DoomsdayAttestations to confirm"
            )
            return False
        return True

    # ── Bridge Registration (§8.5) ──────────────────────────────────

    def register_bridge(self, bridge: DoomsdayAware, bridge_id: str = "") -> bool:
        """
        Register a bridge for doomsday notification.

        Matches Whitepaper §8.5:
            ``function registerBridge(address bridge) external``

        Args:
            bridge: Object implementing DoomsdayAware protocol
            bridge_id: Unique identifier (defaults to id(bridge))

        Returns:
            True if registered, False if already registered
        """
        bid = bridge_id or str(id(bridge))
        if bid in self._registered_bridge_ids:
            logger.warning(f"Bridge {bid} already registered for doomsday")
            return False
        self._registered_bridges.append(bridge)
        self._registered_bridge_ids.add(bid)
        logger.info(f"Bridge registered for doomsday notification: {bid}")
        return True

    def unregister_bridge(self, bridge_id: str) -> bool:
        """Remove a bridge from doomsday notifications."""
        if bridge_id not in self._registered_bridge_ids:
            return False
        self._registered_bridge_ids.discard(bridge_id)
        # Remove from list (linear scan — small list in practice)
        self._registered_bridges = [
            b for i, b in enumerate(self._registered_bridges)
            if str(id(b)) != bridge_id
        ]
        return True

    # ── Bounty (§8.5) ──────────────────────────────────────────────

    def get_bounty_info(self) -> Dict[str, Any]:
        """Get bounty status for the doomsday trigger."""
        return {
            "amount": str(self._bounty_amount),
            "recipient": self._bounty_recipient,
            "paid": self._bounty_paid,
        }

    def mark_bounty_paid(self) -> bool:
        """
        Mark the bounty as paid (called by treasury/token system
        after the actual transfer is executed on-chain).
        """
        if not self._doomsday_active:
            return False
        if self._bounty_paid:
            return False
        self._bounty_paid = True
        self._persist_state()
        logger.info(
            f"Doomsday bounty {self._bounty_amount} QRDX marked paid "
            f"to {self._bounty_recipient}"
        )
        return True

    # ── Shield/Unshield Gates ───────────────────────────────────────

    def can_shield(self) -> bool:
        """Check if shielding is permitted (blocked during doomsday)."""
        return not self._doomsday_active

    def can_unshield(self) -> bool:
        """Unshield is ALWAYS allowed, even during doomsday."""
        return True

    # ── Status / Queries ────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """
        Full doomsday status (matches Whitepaper getDoomsdayStatus()).

        Returns dict with:
            doomsday_active, triggered_at, trigger_block_height,
            verification_hash, trigger_address, canary_address,
            shield_allowed, unshield_allowed, bounty info,
            attestation progress.
        """
        return {
            "doomsday_active": self._doomsday_active,
            "triggered_at": self._triggered_at,
            "trigger_block_height": self._trigger_block_height,
            "verification_hash": self._verification_hash,
            "trigger_address": self._trigger_address,
            "canary_address": self._canary_address,
            "shield_allowed": self.can_shield(),
            "unshield_allowed": self.can_unshield(),
            "bounty": self.get_bounty_info(),
            "attestation_progress": {
                "received": len(self._attestations),
                "threshold": self._threshold,
                "total_validators": self._total_validators,
            },
            "registered_bridges": len(self._registered_bridges),
        }

    def get_attestation_progress(self) -> Dict[str, Any]:
        """Get current attestation count vs threshold."""
        return {
            "received": len(self._attestations),
            "threshold": self._threshold,
            "total_validators": self._total_validators,
            "validators_attested": list(self._attesting_validators),
        }

    # ── Internal ────────────────────────────────────────────────────

    def _activate(
        self,
        proof: DoomsdayProof,
        trigger_address: str,
        bounty_recipient: str,
        block_height: int,
    ) -> None:
        """
        Activate doomsday protocol (internal, called after validation).

        This method is irreversible — once called, the node MUST persist
        the state and notify all registered bridges.
        """
        self._doomsday_active = True
        self._triggered_at = int(time.time())
        self._trigger_block_height = block_height
        self._verification_hash = proof.verification_hash
        self._trigger_address = trigger_address
        self._bounty_recipient = bounty_recipient

        # Persist state BEFORE notifying bridges (crash safety)
        self._persist_state()

        logger.critical(
            "══════════════════════════════════════════════════════════\n"
            "  DOOMSDAY PROTOCOL ACTIVATED\n"
            "  Shield operations: BLOCKED\n"
            "  Unshield operations: ALLOWED\n"
            "  QRDX native trading: NORMAL\n"
            f"  Triggered by: {trigger_address}\n"
            f"  Block height: {block_height}\n"
            f"  Verification: {proof.verification_hash[:32]}...\n"
            f"  Bounty recipient: {bounty_recipient}\n"
            "══════════════════════════════════════════════════════════"
        )

        # Notify all registered bridges (§8.5 _notifyBridges)
        self._notify_bridges(block_height)

    def _notify_bridges(self, block_height: int) -> None:
        """
        Notify all registered bridges that doomsday is active.

        Matches Whitepaper §8.5:
            ``for (uint256 i = 0; i < registeredBridges.length; i++)``
        """
        timestamp = self._triggered_at
        for bridge in self._registered_bridges:
            try:
                bridge.on_doomsday(block_height, timestamp)
            except Exception as exc:
                logger.error(
                    f"Failed to notify bridge of doomsday: {exc}",
                    exc_info=True,
                )

    def _persist_state(self) -> None:
        """Persist doomsday state to the state store."""
        state = {
            "doomsday_active": self._doomsday_active,
            "triggered_at": self._triggered_at,
            "trigger_block_height": self._trigger_block_height,
            "verification_hash": self._verification_hash,
            "trigger_address": self._trigger_address,
            "bounty_recipient": self._bounty_recipient,
            "bounty_paid": self._bounty_paid,
        }
        try:
            if not self._state_store.save_doomsday_state(state):
                logger.error("Failed to persist doomsday state")
        except Exception as exc:
            logger.error(f"State store error: {exc}", exc_info=True)

    def _load_state(self) -> None:
        """Restore doomsday state from the state store on startup."""
        try:
            state = self._state_store.load_doomsday_state()
        except Exception as exc:
            logger.error(f"Failed to load doomsday state: {exc}", exc_info=True)
            return

        if state is None:
            return  # Fresh start

        self._doomsday_active = state.get("doomsday_active", False)
        self._triggered_at = state.get("triggered_at", 0)
        self._trigger_block_height = state.get("trigger_block_height", 0)
        self._verification_hash = state.get("verification_hash", "")
        self._trigger_address = state.get("trigger_address", "")
        self._bounty_recipient = state.get("bounty_recipient", "")
        self._bounty_paid = state.get("bounty_paid", False)

        if self._doomsday_active:
            logger.warning(
                "Doomsday state RESTORED from store — shield operations remain BLOCKED"
            )

    def __setattr__(self, name: str, value: Any) -> None:
        """
        Guard against accidental reset of doomsday state after activation.

        Once _doomsday_active is True, it cannot be set back to False
        except through _load_state (which checks the persisted state).
        """
        if (
            name == "_doomsday_active"
            and hasattr(self, "_doomsday_active")
            and self._doomsday_active
            and value is False
        ):
            raise RuntimeError(
                "SECURITY: Doomsday activation is IRREVERSIBLE. "
                "Cannot set _doomsday_active back to False."
            )
        super().__setattr__(name, value)


# ══════════════════════════════════════════════════════════════════════
#  BRIDGE MINTER  (Whitepaper §10.3)
# ══════════════════════════════════════════════════════════════════════

class BridgeMinter:
    """
    Manages minting and burning of shielded tokens on QRDX.

    Shielded tokens (qETH, qBTC, qSOL, qUSDC) are minted 1:1 when
    the oracle consensus confirms a lock on the source chain.  They are
    burned when a user unshields back to the classical chain.

    Attributes:
        token_configs: Registered bridgeable tokens
        total_minted: Running totals per shielded token
        total_burned: Running totals per shielded token
    """

    def __init__(self, token_configs: Optional[Dict[str, BridgeTokenConfig]] = None):
        self.token_configs: Dict[str, BridgeTokenConfig] = (
            dict(token_configs) if token_configs else dict(DEFAULT_TOKEN_CONFIGS)
        )
        self.total_minted: Dict[str, Decimal] = {}
        self.total_burned: Dict[str, Decimal] = {}
        self._mint_records: List[Dict[str, Any]] = []

    def register_token(self, config: BridgeTokenConfig) -> None:
        """Register a new bridgeable token."""
        self.token_configs[config.symbol] = config
        logger.info(f"Registered bridge token: {config.symbol} → {config.shielded_symbol}")

    def get_token_config(self, symbol: str) -> Optional[BridgeTokenConfig]:
        return self.token_configs.get(symbol)

    def mint(
        self,
        token_symbol: str,
        amount: Decimal,
        recipient: str,
        bridge_record_id: str,
    ) -> bool:
        """
        Mint shielded tokens to a QRDX address.

        Args:
            token_symbol: Source token (e.g. "ETH")
            amount: Amount to mint (after fee deduction)
            recipient: QRDX address receiving the shielded tokens
            bridge_record_id: Bridge record authorizing the mint

        Returns:
            True if minted successfully
        """
        config = self.token_configs.get(token_symbol)
        if not config:
            logger.error(f"Unknown token: {token_symbol}")
            return False
        if not config.active:
            logger.error(f"Token {token_symbol} is not active")
            return False
        if amount <= 0:
            return False

        shielded = config.shielded_symbol
        self.total_minted.setdefault(shielded, Decimal(0))
        self.total_minted[shielded] += amount

        self._mint_records.append({
            "type": "mint",
            "token": shielded,
            "amount": str(amount),
            "recipient": recipient,
            "bridge_record_id": bridge_record_id,
            "timestamp": int(time.time()),
        })

        logger.info(f"Minted {amount} {shielded} to {recipient[:16]}...")
        return True

    def burn(
        self,
        token_symbol: str,
        amount: Decimal,
        burner: str,
        bridge_record_id: str,
    ) -> bool:
        """
        Burn shielded tokens (for unshielding).

        Args:
            token_symbol: Source token symbol (e.g. "ETH")
            amount: Amount to burn
            burner: QRDX address burning the tokens
            bridge_record_id: Associated bridge record

        Returns:
            True if burned successfully
        """
        config = self.token_configs.get(token_symbol)
        if not config:
            return False

        shielded = config.shielded_symbol
        minted = self.total_minted.get(shielded, Decimal(0))
        burned = self.total_burned.get(shielded, Decimal(0))
        outstanding = minted - burned

        if amount > outstanding:
            logger.error(
                f"Cannot burn {amount} {shielded}: only {outstanding} outstanding"
            )
            return False

        self.total_burned.setdefault(shielded, Decimal(0))
        self.total_burned[shielded] += amount

        self._mint_records.append({
            "type": "burn",
            "token": shielded,
            "amount": str(amount),
            "burner": burner,
            "bridge_record_id": bridge_record_id,
            "timestamp": int(time.time()),
        })

        logger.info(f"Burned {amount} {shielded} from {burner[:16]}...")
        return True

    def get_outstanding(self, shielded_symbol: str) -> Decimal:
        """Get total outstanding (minted − burned) for a shielded token."""
        minted = self.total_minted.get(shielded_symbol, Decimal(0))
        burned = self.total_burned.get(shielded_symbol, Decimal(0))
        return minted - burned

    def get_stats(self) -> Dict[str, Any]:
        """Get minting/burning statistics."""
        return {
            "total_minted": {k: str(v) for k, v in self.total_minted.items()},
            "total_burned": {k: str(v) for k, v in self.total_burned.items()},
            "outstanding": {
                sym: str(self.get_outstanding(sym))
                for sym in self.total_minted
            },
            "registered_tokens": list(self.token_configs.keys()),
        }


# ══════════════════════════════════════════════════════════════════════
#  SHIELDING MANAGER  (Whitepaper §8.1 – §8.3)
# ══════════════════════════════════════════════════════════════════════

class ShieldingManager:
    """
    Orchestrates the full shield/unshield lifecycle.

    Coordinates between chain adapters, oracle consensus, doomsday
    protocol, and the bridge minter.

    Implements DoomsdayAware so that doomsday activation automatically
    disables shielding and logs the event for audit.
    """

    def __init__(
        self,
        minter: Optional[BridgeMinter] = None,
        doomsday: Optional[DoomsdayProtocol] = None,
        bridge_id: str = "shielding-manager",
    ):
        self.minter = minter or BridgeMinter()
        self.doomsday = doomsday or DoomsdayProtocol()
        self._records: Dict[str, BridgeRecord] = {}
        self._fraud_windows: Dict[str, int] = {}  # record_id → expiry timestamp
        self._doomsday_block_height: int = 0
        self._doomsday_timestamp: int = 0

        # Register self for doomsday notifications (§8.5)
        self.doomsday.register_bridge(self, bridge_id=bridge_id)

    # ── DoomsdayAware implementation ────────────────────────────────

    def on_doomsday(self, block_height: int, timestamp: int) -> None:
        """
        Called by DoomsdayProtocol when doomsday is activated.

        Records the activation metadata and logs a critical warning.
        Shield operations are already blocked via ``self.doomsday.can_shield()``,
        but this callback allows the manager to take additional defensive
        action (e.g. rejecting in-flight records, emitting events).
        """
        self._doomsday_block_height = block_height
        self._doomsday_timestamp = timestamp

        # Fail any PENDING/CONFIRMING shield records immediately
        failed_count = 0
        for record in self._records.values():
            if (
                record.operation == BridgeOperationType.SHIELD
                and record.status in (BridgeStatus.PENDING, BridgeStatus.CONFIRMING)
            ):
                record.status = BridgeStatus.FAILED
                failed_count += 1

        logger.critical(
            f"ShieldingManager: doomsday callback received — "
            f"block={block_height}, timestamp={timestamp}, "
            f"failed {failed_count} in-flight shield record(s)"
        )

    # ── Shield Operations (§8.1) ────────────────────────────────────

    def initiate_shield(
        self,
        source_chain: ChainId,
        source_tx_hash: str,
        amount: Decimal,
        source_address: str,
        qrdx_address: str,
        token_symbol: str = "ETH",
        block_height: int = 0,
        block_hash: str = "",
    ) -> Optional[BridgeRecord]:
        """
        Start a shield operation (Classical → Quantum-Resistant).

        Called when a lock is detected on the source chain.

        Returns:
            BridgeRecord if accepted, None if rejected
        """
        # Doomsday check
        if not self.doomsday.can_shield():
            logger.warning("Shield BLOCKED — doomsday protocol is active")
            return None

        # Token config validation
        config = self.minter.get_token_config(token_symbol)
        if not config:
            logger.error(f"No config for token: {token_symbol}")
            return None
        if not config.active:
            logger.error(f"Token {token_symbol} shielding is disabled")
            return None
        if amount < config.min_amount:
            logger.error(f"Amount {amount} below minimum {config.min_amount}")
            return None
        if amount > config.max_amount:
            logger.error(f"Amount {amount} above maximum {config.max_amount}")
            return None

        record = BridgeRecord(
            record_id="",  # auto-computed
            source_chain_id=source_chain,
            dest_chain_id=ChainId.QRDX,
            block_height=block_height,
            block_hash=block_hash,
            source_tx_hash=source_tx_hash,
            amount=amount,
            source_address=source_address,
            qrdx_address=qrdx_address,
            operation=BridgeOperationType.SHIELD,
            token_symbol=token_symbol,
            confirmations_required=config.confirmations_required,
        )

        self._records[record.record_id] = record
        logger.info(
            f"Shield initiated: {amount} {token_symbol} from "
            f"{source_chain.name} → {record.record_id[:12]}..."
        )
        return record

    def confirm_shield(self, record_id: str) -> bool:
        """
        Add a confirmation to a pending shield operation.

        Returns True if the confirmation threshold is now met.
        """
        record = self._records.get(record_id)
        if not record:
            return False
        if record.operation != BridgeOperationType.SHIELD:
            return False
        return record.add_confirmation()

    def attest_shield(self, record_id: str, proof: ValidatorProof) -> bool:
        """
        Apply oracle attestation to a confirmed shield record.

        Args:
            record_id: Bridge record to attest
            proof: ValidatorProof from oracle consensus

        Returns:
            True if attestation accepted and record advanced
        """
        record = self._records.get(record_id)
        if not record:
            return False
        if not record.is_confirmed:
            return False
        if not proof.meets_threshold:
            return False

        record.status = BridgeStatus.ATTESTED
        return True

    def execute_shield(self, record_id: str) -> bool:
        """
        Execute a shield by minting the shielded tokens.

        Called after oracle attestation.
        """
        record = self._records.get(record_id)
        if not record:
            return False
        if record.status != BridgeStatus.ATTESTED:
            return False
        if not self.doomsday.can_shield():
            return False

        # Calculate fee
        fee = (record.amount * BRIDGE_FEE_BPS) / Decimal("10000")
        mint_amount = record.amount - fee

        success = self.minter.mint(
            record.token_symbol,
            mint_amount,
            record.qrdx_address,
            record.record_id,
        )
        if success:
            record.status = BridgeStatus.EXECUTED
            logger.info(
                f"Shield executed: {mint_amount} "
                f"q{record.token_symbol} to {record.qrdx_address[:16]}..."
            )
        else:
            record.status = BridgeStatus.FAILED
        return success

    # ── Unshield Operations (§8.2) ──────────────────────────────────

    def initiate_unshield(
        self,
        dest_chain: ChainId,
        amount: Decimal,
        qrdx_address: str,
        dest_address: str,
        token_symbol: str = "ETH",
    ) -> Optional[BridgeRecord]:
        """
        Start an unshield operation (Quantum-Resistant → Classical).

        Burns shielded tokens on QRDX and initiates unlock on the
        destination chain.

        High-value transfers (>$100K) enter a 7-day fraud proof window.
        """
        # Unshield is ALWAYS allowed, even during doomsday
        config = self.minter.get_token_config(token_symbol)
        if not config:
            return None
        if amount < config.min_amount:
            return None
        if amount > config.max_amount:
            return None

        record = BridgeRecord(
            record_id="",
            source_chain_id=ChainId.QRDX,
            dest_chain_id=dest_chain,
            block_height=0,
            block_hash="",
            source_tx_hash=hashlib.sha256(
                f"unshield:{qrdx_address}:{amount}:{int(time.time())}".encode()
            ).hexdigest(),
            amount=amount,
            source_address=qrdx_address,
            qrdx_address=qrdx_address,
            operation=BridgeOperationType.UNSHIELD,
            token_symbol=token_symbol,
            confirmations_required=1,  # QRDX-side confirmation
        )

        # Burn tokens
        success = self.minter.burn(
            token_symbol, amount, qrdx_address, record.record_id
        )
        if not success:
            return None

        # Check for high-value fraud proof window
        if self._is_high_value(amount, token_symbol):
            expiry = int(time.time()) + FRAUD_PROOF_WINDOW_SECONDS
            self._fraud_windows[record.record_id] = expiry
            record.status = BridgeStatus.CONFIRMING
            logger.info(
                f"High-value unshield ({amount} {token_symbol}): "
                f"7-day fraud proof window until {expiry}"
            )
        else:
            record.status = BridgeStatus.PENDING

        self._records[record.record_id] = record
        return record

    def _is_high_value(self, amount: Decimal, token_symbol: str) -> bool:
        """
        Check if amount exceeds the high-value threshold for fraud proof window.
        
        Uses per-token thresholds derived from the bridge token configuration
        to ensure denomination-aware comparison. The thresholds are conservative
        estimates based on the token's expected value range.
        """
        # Per-token high-value thresholds (amount of token ≈ $100K USD)
        # These are updated via governance proposals as prices change.
        HIGH_VALUE_THRESHOLDS: Dict[str, Decimal] = {
            "ETH": Decimal("30"),        # ~$100K at $3,300/ETH
            "BTC": Decimal("1"),         # ~$100K at $100K/BTC
            "SOL": Decimal("500"),       # ~$100K at $200/SOL
            "USDC": Decimal("100000"),   # $100K
            "QRDX": HIGH_VALUE_THRESHOLD_USD,  # Direct comparison for native token
        }
        threshold = HIGH_VALUE_THRESHOLDS.get(token_symbol, HIGH_VALUE_THRESHOLD_USD)
        return amount >= threshold

    def check_fraud_window(self, record_id: str) -> bool:
        """
        Check if a high-value unshield's fraud proof window has expired.

        Returns True if the window has passed and the unlock can proceed.
        """
        expiry = self._fraud_windows.get(record_id)
        if expiry is None:
            return True  # No fraud window
        return int(time.time()) >= expiry

    def submit_fraud_proof(self, record_id: str, proof: str) -> bool:
        """
        Submit a fraud proof to block an unshield operation.

        Args:
            record_id: Record to challenge
            proof: Evidence of fraud

        Returns:
            True if fraud proof accepted
        """
        record = self._records.get(record_id)
        if not record:
            return False
        if record.status == BridgeStatus.EXECUTED:
            return False  # Already executed
        if not proof:
            return False

        # Check if within fraud window
        expiry = self._fraud_windows.get(record_id)
        if expiry is not None and int(time.time()) >= expiry:
            return False  # Window expired

        record.status = BridgeStatus.FRAUD
        logger.warning(f"Fraud proof accepted for record {record_id[:12]}...")
        return True

    def attest_unshield(self, record_id: str, proof: ValidatorProof) -> bool:
        """Apply oracle attestation to a pending unshield."""
        record = self._records.get(record_id)
        if not record:
            return False
        if record.operation != BridgeOperationType.UNSHIELD:
            return False
        if not proof.meets_threshold:
            return False
        # High-value: must pass fraud window
        if not self.check_fraud_window(record_id):
            return False
        record.status = BridgeStatus.ATTESTED
        return True

    def execute_unshield(self, record_id: str) -> bool:
        """
        Mark an unshield as executed after unlock on destination chain.
        """
        record = self._records.get(record_id)
        if not record:
            return False
        if record.status != BridgeStatus.ATTESTED:
            return False
        record.status = BridgeStatus.EXECUTED
        logger.info(f"Unshield executed: {record.amount} {record.token_symbol}")
        return True

    # ── Queries ─────────────────────────────────────────────────────

    def get_record(self, record_id: str) -> Optional[BridgeRecord]:
        return self._records.get(record_id)

    def get_records_by_address(self, qrdx_address: str) -> List[BridgeRecord]:
        return [
            r for r in self._records.values()
            if r.qrdx_address == qrdx_address
        ]

    def get_pending_records(self) -> List[BridgeRecord]:
        return [
            r for r in self._records.values()
            if r.status in (BridgeStatus.PENDING, BridgeStatus.CONFIRMING)
        ]

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_records": len(self._records),
            "pending": len(self.get_pending_records()),
            "doomsday": self.doomsday.get_status(),
            "minter": self.minter.get_stats(),
            "fraud_windows_active": len([
                rid for rid, exp in self._fraud_windows.items()
                if int(time.time()) < exp
            ]),
        }
