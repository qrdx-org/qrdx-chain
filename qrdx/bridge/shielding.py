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
import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Dict, List, Optional

from .types import (
    BridgeOperationType,
    BridgeRecord,
    BridgeStatus,
    BridgeTokenConfig,
    ChainId,
    ValidatorProof,
)
from ..logger import get_logger

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════════════

# Doomsday canary wallet — QRDX-native PQ address with 1M QRDX bounty.
# Generated at genesis; the private key is a publicly-known ECDSA key.
# A quantum attacker who can break ECDSA will drain this wallet, triggering
# the circuit breaker that halts new shielding.
DOOMSDAY_CANARY_ADDRESS = "0xPQdoomsday0canary0qrdx0genesis0bounty0wallet0a1b2c3"
DOOMSDAY_CANARY_BALANCE = Decimal("1000000")  # 1M QRDX

# Bridge fee basis points (0.1% = 10 bps)
BRIDGE_FEE_BPS = 10

# Fraud proof window for high-value unshields (7 days in seconds)
FRAUD_PROOF_WINDOW_SECONDS = 7 * 24 * 3600  # 604800

# Threshold above which fraud proof window applies (in USD)
HIGH_VALUE_THRESHOLD_USD = Decimal("100000")

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
#  DOOMSDAY PROTOCOL  (Whitepaper §8.5)
# ══════════════════════════════════════════════════════════════════════

class DoomsdayProtocol:
    """
    Circuit breaker that monitors a publicly-known ECDSA canary wallet.

    If the canary is drained (indicating a quantum attacker can break
    classical crypto), all new shield operations are BLOCKED while
    unshields remain permitted so users can withdraw to safety.

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

    def __init__(self):
        self._doomsday_active: bool = False
        self._triggered_at: int = 0
        self._trigger_proof: str = ""
        self._canary_address: str = DOOMSDAY_CANARY_ADDRESS
        self._canary_expected_balance: Decimal = DOOMSDAY_CANARY_BALANCE

    @property
    def canary_address(self) -> str:
        return self._canary_address

    @property
    def is_active(self) -> bool:
        """Check if doomsday mode is currently active."""
        return self._doomsday_active

    def trigger_doomsday(self, proof: str) -> bool:
        """
        Trigger the doomsday circuit breaker.

        Args:
            proof: Cryptographic proof that the canary has been drained.
                   In production: signed transaction showing canary balance
                   below threshold, attested by ≥ 2/3+1 validators.

        Returns:
            True if doomsday was triggered, False if already active
        """
        if self._doomsday_active:
            return False

        if not proof:
            return False

        self._doomsday_active = True
        self._triggered_at = int(time.time())
        self._trigger_proof = proof
        logger.critical(
            "DOOMSDAY PROTOCOL ACTIVATED — Shield operations BLOCKED. "
            "Unshield operations remain ALLOWED."
        )
        return True

    def check_canary(self, current_balance: Decimal) -> bool:
        """
        Check the canary wallet balance.

        If balance has been drained (< expected), automatically trigger
        doomsday.

        Args:
            current_balance: Current balance of the canary wallet

        Returns:
            True if canary is safe, False if doomsday was triggered
        """
        if self._doomsday_active:
            return False

        if current_balance < self._canary_expected_balance:
            proof = (
                f"canary_balance_drop:"
                f"{current_balance}<{self._canary_expected_balance}:"
                f"ts={int(time.time())}"
            )
            self.trigger_doomsday(proof)
            return False
        return True

    def can_shield(self) -> bool:
        """Check if shielding is permitted (blocked during doomsday)."""
        return not self._doomsday_active

    def can_unshield(self) -> bool:
        """Unshield is ALWAYS allowed, even during doomsday."""
        return True

    def get_status(self) -> Dict[str, Any]:
        return {
            "doomsday_active": self._doomsday_active,
            "triggered_at": self._triggered_at,
            "trigger_proof": self._trigger_proof,
            "canary_address": self._canary_address,
            "shield_allowed": self.can_shield(),
            "unshield_allowed": self.can_unshield(),
        }


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
    """

    def __init__(
        self,
        minter: Optional[BridgeMinter] = None,
        doomsday: Optional[DoomsdayProtocol] = None,
    ):
        self.minter = minter or BridgeMinter()
        self.doomsday = doomsday or DoomsdayProtocol()
        self._records: Dict[str, BridgeRecord] = {}
        self._fraud_windows: Dict[str, int] = {}  # record_id → expiry timestamp

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
