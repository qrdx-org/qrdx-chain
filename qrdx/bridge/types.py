"""
QRDX Cross-Chain Bridge Types

Core data structures for the cross-chain oracle and bridge infrastructure
(Whitepaper §3.8, §8, §10).

Defines:
  - ChainId enum for supported external chains
  - BridgeRecord for tracking lock/unlock operations
  - BlockHeightRecord for per-chain block height anchoring
  - ExecutionCondition for conditional cross-chain transactions
  - OracleTransaction envelope wrapping chain-specific sub-transactions
  - OracleAttestation for validator attestations of external chain state
  - ValidatorProof for threshold-signed bridge proofs
"""

import hashlib
import time
from dataclasses import dataclass, field
from decimal import Decimal
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple

from ..logger import get_logger

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════
#  CHAIN IDENTIFIERS
# ══════════════════════════════════════════════════════════════════════

class ChainId(IntEnum):
    """
    Identifiers for external chains supported by the bridge.
    Matches Whitepaper §10.1 chain adapter framework.
    """
    QRDX     = 0     # QRDX native (self-referential)
    ETHEREUM = 1
    BITCOIN  = 2
    SOLANA   = 3
    COSMOS   = 4


# Human-readable names
CHAIN_NAMES: Dict[int, str] = {
    ChainId.QRDX: "QRDX",
    ChainId.ETHEREUM: "Ethereum",
    ChainId.BITCOIN: "Bitcoin",
    ChainId.SOLANA: "Solana",
    ChainId.COSMOS: "Cosmos",
}


# ══════════════════════════════════════════════════════════════════════
#  BLOCK HEIGHT RECORD  (Whitepaper §8.4 / §10)
# ══════════════════════════════════════════════════════════════════════

@dataclass
class BlockHeightRecord:
    """
    Records the latest attested block height for an external chain.

    Stored per-chain in QRDX blocks to anchor cross-chain time.

    Attributes:
        chain_id: External chain identifier
        block_height: Latest confirmed block height on the external chain
        block_hash: Hash of that block (32 bytes hex)
        timestamp: When this record was created (unix seconds)
        attested: Whether the record has been attested by validator quorum
    """
    chain_id: ChainId
    block_height: int
    block_hash: str
    timestamp: int
    attested: bool = False

    def __post_init__(self):
        if self.block_height < 0:
            raise ValueError("block_height must be non-negative")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": int(self.chain_id),
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "timestamp": self.timestamp,
            "attested": self.attested,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'BlockHeightRecord':
        return cls(
            chain_id=ChainId(d["chain_id"]),
            block_height=d["block_height"],
            block_hash=d["block_hash"],
            timestamp=d["timestamp"],
            attested=d.get("attested", False),
        )


# ══════════════════════════════════════════════════════════════════════
#  BRIDGE RECORD  (Whitepaper §8.4)
# ══════════════════════════════════════════════════════════════════════

class BridgeOperationType(IntEnum):
    """Type of bridge operation."""
    SHIELD   = 1   # Classical → Quantum-resistant
    UNSHIELD = 2   # Quantum-resistant → Classical


class BridgeStatus(IntEnum):
    """Processing status of a bridge record."""
    PENDING     = 0  # Awaiting confirmations
    CONFIRMING  = 1  # Confirmation period in progress
    ATTESTED    = 2  # Validator quorum attested
    EXECUTED    = 3  # Mint/unlock completed
    FAILED      = 4  # Bridge operation failed
    FRAUD       = 5  # Fraud proof submitted, operation reverted


@dataclass
class BridgeRecord:
    """
    Records a single bridge operation (lock/unlock or mint/burn).

    Whitepaper §8.4 BridgeRecord struct.

    Attributes:
        record_id: Unique identifier (hash of source tx + chain)
        source_chain_id: Chain where the lock/burn happened
        dest_chain_id: Chain where the mint/unlock happens
        block_height: Block height on source chain when event occurred
        block_hash: Source chain block hash for verification
        source_tx_hash: Transaction hash on source chain
        amount: Amount bridged (in source token's smallest unit)
        source_address: Sender address on source chain
        qrdx_address: Address on QRDX chain
        operation: SHIELD or UNSHIELD
        status: Current processing status
        timestamp: Event timestamp (unix seconds)
        token_symbol: Token being bridged (e.g. "ETH", "BTC")
        confirmations_required: Source chain confirmations needed
        confirmations_received: Confirmations seen so far
    """
    record_id: str
    source_chain_id: ChainId
    dest_chain_id: ChainId
    block_height: int
    block_hash: str
    source_tx_hash: str
    amount: Decimal
    source_address: str
    qrdx_address: str
    operation: BridgeOperationType
    status: BridgeStatus = BridgeStatus.PENDING
    timestamp: int = 0
    token_symbol: str = "ETH"
    confirmations_required: int = 12
    confirmations_received: int = 0

    def __post_init__(self):
        if self.amount <= 0:
            raise ValueError("Bridge amount must be positive")
        if self.timestamp == 0:
            self.timestamp = int(time.time())
        if not self.record_id:
            self.record_id = self._compute_id()

    def _compute_id(self) -> str:
        """Derive deterministic record ID from source tx."""
        data = (
            int(self.source_chain_id).to_bytes(4, 'big') +
            self.source_tx_hash.encode('utf-8') +
            str(self.amount).encode('utf-8')
        )
        return hashlib.sha256(data).hexdigest()

    @property
    def is_shielding(self) -> bool:
        return self.operation == BridgeOperationType.SHIELD

    @property
    def is_confirmed(self) -> bool:
        return self.confirmations_received >= self.confirmations_required

    @property
    def is_complete(self) -> bool:
        return self.status == BridgeStatus.EXECUTED

    def add_confirmation(self) -> bool:
        """Add a confirmation. Returns True if threshold now met."""
        self.confirmations_received += 1
        if self.is_confirmed and self.status == BridgeStatus.PENDING:
            self.status = BridgeStatus.CONFIRMING
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "source_chain_id": int(self.source_chain_id),
            "dest_chain_id": int(self.dest_chain_id),
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "source_tx_hash": self.source_tx_hash,
            "amount": str(self.amount),
            "source_address": self.source_address,
            "qrdx_address": self.qrdx_address,
            "operation": int(self.operation),
            "status": int(self.status),
            "timestamp": self.timestamp,
            "token_symbol": self.token_symbol,
            "confirmations_required": self.confirmations_required,
            "confirmations_received": self.confirmations_received,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'BridgeRecord':
        return cls(
            record_id=d["record_id"],
            source_chain_id=ChainId(d["source_chain_id"]),
            dest_chain_id=ChainId(d["dest_chain_id"]),
            block_height=d["block_height"],
            block_hash=d["block_hash"],
            source_tx_hash=d["source_tx_hash"],
            amount=Decimal(d["amount"]),
            source_address=d["source_address"],
            qrdx_address=d["qrdx_address"],
            operation=BridgeOperationType(d["operation"]),
            status=BridgeStatus(d["status"]),
            timestamp=d["timestamp"],
            token_symbol=d.get("token_symbol", "ETH"),
            confirmations_required=d.get("confirmations_required", 12),
            confirmations_received=d.get("confirmations_received", 0),
        )


# ══════════════════════════════════════════════════════════════════════
#  VALIDATOR PROOF  (Whitepaper §10.3)
# ══════════════════════════════════════════════════════════════════════

@dataclass
class ValidatorProof:
    """
    Threshold-signed proof from validators attesting to an external event.

    Bridges and oracle precompiles require proofs carrying ≥ 2/3+1
    validator Dilithium signatures.

    Attributes:
        message_hash: SHA-256 hash of the message being attested
        signatures: List of Dilithium signature bytes (hex-encoded)
        signers: List of validator addresses that signed
        nonce: Replay-protection nonce
        threshold: Minimum signatures required (2/3+1)
    """
    message_hash: str
    signatures: List[str]
    signers: List[str]
    nonce: int
    threshold: int

    def __post_init__(self):
        if len(self.signatures) != len(self.signers):
            raise ValueError("signatures and signers must have equal length")
        if self.threshold < 1:
            raise ValueError("threshold must be >= 1")

    @property
    def signature_count(self) -> int:
        return len(self.signatures)

    @property
    def meets_threshold(self) -> bool:
        return self.signature_count >= self.threshold

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_hash": self.message_hash,
            "signatures": self.signatures,
            "signers": self.signers,
            "nonce": self.nonce,
            "threshold": self.threshold,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'ValidatorProof':
        return cls(
            message_hash=d["message_hash"],
            signatures=d["signatures"],
            signers=d["signers"],
            nonce=d["nonce"],
            threshold=d["threshold"],
        )


# ══════════════════════════════════════════════════════════════════════
#  ORACLE ATTESTATION  (Whitepaper §10.2)
# ══════════════════════════════════════════════════════════════════════

@dataclass
class OracleAttestation:
    """
    A single validator's attestation of external chain state.

    Validators running a chain adapter periodically submit attestations
    declaring the latest confirmed block height and state root.

    Attributes:
        validator_address: PQ address of the attesting validator
        chain_id: External chain being attested
        block_height: Attested block height
        block_hash: Block hash at that height
        state_root: State root (EVM chains) or equivalent
        timestamp: When the attestation was created
        signature: Dilithium signature over the attestation contents
    """
    validator_address: str
    chain_id: ChainId
    block_height: int
    block_hash: str
    state_root: str
    timestamp: int
    signature: str = ""

    def attestation_hash(self) -> str:
        """Compute hash of attestation contents for signing."""
        data = (
            self.validator_address.encode('utf-8') +
            int(self.chain_id).to_bytes(4, 'big') +
            self.block_height.to_bytes(8, 'big') +
            bytes.fromhex(self.block_hash.replace("0x", "")) +
            bytes.fromhex(self.state_root.replace("0x", "")) +
            self.timestamp.to_bytes(8, 'big')
        )
        return hashlib.sha256(data).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "validator_address": self.validator_address,
            "chain_id": int(self.chain_id),
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "state_root": self.state_root,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'OracleAttestation':
        return cls(
            validator_address=d["validator_address"],
            chain_id=ChainId(d["chain_id"]),
            block_height=d["block_height"],
            block_hash=d["block_hash"],
            state_root=d["state_root"],
            timestamp=d["timestamp"],
            signature=d.get("signature", ""),
        )


# ══════════════════════════════════════════════════════════════════════
#  EXECUTION CONDITION  (Whitepaper §3.8)
# ══════════════════════════════════════════════════════════════════════

class ConditionType(IntEnum):
    """Execution condition types for OracleTransactions."""
    IMMEDIATE             = 0x00  # Execute immediately
    AFTER_BLOCK_HEIGHT    = 0x01  # After external chain reaches block N
    AFTER_ORACLE_CONFIRMS = 0x02  # After another oracle tx is confirmed
    PRICE_THRESHOLD       = 0x03  # When price crosses threshold
    BALANCE_THRESHOLD     = 0x04  # When balance exceeds/drops below threshold


@dataclass
class ExecutionCondition:
    """
    A condition that must be met before an OracleTransaction executes.

    Attributes:
        condition_type: Type of condition
        chain_id: Relevant chain for the condition
        value: Numeric threshold or target
        reference: Hash reference (e.g., oracle tx hash, price feed)
    """
    condition_type: ConditionType
    chain_id: ChainId = ChainId.QRDX
    value: int = 0
    reference: str = ""

    def is_met(self, current_block_heights: Dict[ChainId, int] = None) -> bool:
        """
        Evaluate whether this condition is satisfied.

        Args:
            current_block_heights: Map of chain → latest block height

        Returns:
            True if condition is met
        """
        if self.condition_type == ConditionType.IMMEDIATE:
            return True

        if self.condition_type == ConditionType.AFTER_BLOCK_HEIGHT:
            if current_block_heights and self.chain_id in current_block_heights:
                return current_block_heights[self.chain_id] >= self.value
            return False

        # Other conditions require oracle data — checked at execution time
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "condition_type": int(self.condition_type),
            "chain_id": int(self.chain_id),
            "value": self.value,
            "reference": self.reference,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'ExecutionCondition':
        return cls(
            condition_type=ConditionType(d["condition_type"]),
            chain_id=ChainId(d.get("chain_id", 0)),
            value=d.get("value", 0),
            reference=d.get("reference", ""),
        )


# ══════════════════════════════════════════════════════════════════════
#  ORACLE TRANSACTION  (Whitepaper §3.8)
# ══════════════════════════════════════════════════════════════════════

class OracleTxType(IntEnum):
    """Sub-transaction type discriminants."""
    ETHEREUM = 0x01
    BITCOIN  = 0x02
    SOLANA   = 0x03
    COSMOS   = 0x04
    GENERIC  = 0xFF


class OracleTxStatus(IntEnum):
    """Lifecycle status of an OracleTransaction."""
    SUBMITTED  = 0   # In QRDX mempool
    PENDING    = 1   # Included in QRDX block, awaiting conditions
    BROADCAST  = 2   # Submitted to external chain
    CONFIRMING = 3   # Awaiting external chain confirmations
    CONFIRMED  = 4   # Oracle quorum attested external confirmation
    FAILED     = 5   # Execution failed
    EXPIRED    = 6   # Deadline passed


@dataclass
class OracleTransaction:
    """
    Cross-chain transaction envelope (Whitepaper §3.8).

    Wraps a chain-specific sub-transaction with QRDX metadata,
    execution conditions, and Dilithium outer signature.

    Lifecycle:
      Submit → Validate → Include in block (PENDING) →
      Check conditions each block → Broadcast via adapter →
      Monitor confirmation → Attest (2/3+1) → Execute callback (CONFIRMED)

    Attributes:
        nonce: QRDX sender nonce
        sender: QRDX address (PQ or multisig)
        target_chain_id: External chain identifier
        tx_type: Sub-transaction type discriminant
        inner_transaction: Fully-signed target chain transaction (bytes hex)
        conditions: List of execution conditions
        deadline: Unix timestamp after which tx expires (0 = no deadline)
        max_gas_subsidy: Max QRDX to spend on external chain gas (in smallest unit)
        callback_tx_hash: Optional QRDX tx to execute on confirmation
        callback_data: Optional data for the callback
        dilithium_signature: PQ outer envelope signature (hex)
        dilithium_pubkey: Signer's Dilithium public key (hex)
        status: Current lifecycle status
        tx_hash: QRDX-side transaction hash
        created_at: Creation timestamp
    """
    nonce: int
    sender: str
    target_chain_id: ChainId
    tx_type: OracleTxType
    inner_transaction: str  # hex-encoded
    conditions: List[ExecutionCondition] = field(default_factory=list)
    deadline: int = 0
    max_gas_subsidy: int = 0
    callback_tx_hash: str = ""
    callback_data: str = ""
    dilithium_signature: str = ""
    dilithium_pubkey: str = ""
    status: OracleTxStatus = OracleTxStatus.SUBMITTED
    tx_hash: str = ""
    created_at: int = 0

    def __post_init__(self):
        if self.created_at == 0:
            self.created_at = int(time.time())
        if not self.tx_hash:
            self.tx_hash = self.compute_hash()

    def compute_hash(self) -> str:
        """Compute deterministic transaction hash."""
        data = (
            self.nonce.to_bytes(8, 'big') +
            self.sender.encode('utf-8') +
            int(self.target_chain_id).to_bytes(4, 'big') +
            int(self.tx_type).to_bytes(1, 'big') +
            bytes.fromhex(self.inner_transaction) +
            self.deadline.to_bytes(8, 'big')
        )
        return hashlib.sha256(data).hexdigest()

    @property
    def is_expired(self) -> bool:
        """Check if the transaction has passed its deadline."""
        if self.deadline == 0:
            return False
        return int(time.time()) > self.deadline

    @property
    def is_complete(self) -> bool:
        return self.status in (OracleTxStatus.CONFIRMED, OracleTxStatus.FAILED, OracleTxStatus.EXPIRED)

    def conditions_met(self, block_heights: Dict[ChainId, int] = None) -> bool:
        """Check if all execution conditions are satisfied."""
        if not self.conditions:
            return True
        return all(c.is_met(block_heights) for c in self.conditions)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nonce": self.nonce,
            "sender": self.sender,
            "target_chain_id": int(self.target_chain_id),
            "tx_type": int(self.tx_type),
            "inner_transaction": self.inner_transaction,
            "conditions": [c.to_dict() for c in self.conditions],
            "deadline": self.deadline,
            "max_gas_subsidy": self.max_gas_subsidy,
            "callback_tx_hash": self.callback_tx_hash,
            "callback_data": self.callback_data,
            "dilithium_signature": self.dilithium_signature,
            "dilithium_pubkey": self.dilithium_pubkey,
            "status": int(self.status),
            "tx_hash": self.tx_hash,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'OracleTransaction':
        conditions = [
            ExecutionCondition.from_dict(c) for c in d.get("conditions", [])
        ]
        return cls(
            nonce=d["nonce"],
            sender=d["sender"],
            target_chain_id=ChainId(d["target_chain_id"]),
            tx_type=OracleTxType(d["tx_type"]),
            inner_transaction=d["inner_transaction"],
            conditions=conditions,
            deadline=d.get("deadline", 0),
            max_gas_subsidy=d.get("max_gas_subsidy", 0),
            callback_tx_hash=d.get("callback_tx_hash", ""),
            callback_data=d.get("callback_data", ""),
            dilithium_signature=d.get("dilithium_signature", ""),
            dilithium_pubkey=d.get("dilithium_pubkey", ""),
            status=OracleTxStatus(d.get("status", 0)),
            tx_hash=d.get("tx_hash", ""),
            created_at=d.get("created_at", 0),
        )


# ══════════════════════════════════════════════════════════════════════
#  TOKEN CONFIG  (Whitepaper §10.3)
# ══════════════════════════════════════════════════════════════════════

@dataclass
class BridgeTokenConfig:
    """
    Configuration for a bridgeable token.

    Attributes:
        symbol: Token symbol (e.g. "ETH", "BTC", "USDC")
        shielded_symbol: Shielded name on QRDX (e.g. "qETH", "qBTC")
        source_chain_id: Chain the token is native to
        source_token_address: Contract address on source chain ("native" for ETH/BTC)
        decimals: Token decimal places
        active: Whether shielding is currently enabled
        min_amount: Minimum bridge amount
        max_amount: Maximum bridge amount per operation
        confirmations_required: Source chain confirmations needed
    """
    symbol: str
    shielded_symbol: str
    source_chain_id: ChainId
    source_token_address: str = "native"
    decimals: int = 18
    active: bool = True
    min_amount: Decimal = Decimal("0.001")
    max_amount: Decimal = Decimal("1000000")
    confirmations_required: int = 12

    def to_dict(self) -> Dict[str, Any]:
        return {
            "symbol": self.symbol,
            "shielded_symbol": self.shielded_symbol,
            "source_chain_id": int(self.source_chain_id),
            "source_token_address": self.source_token_address,
            "decimals": self.decimals,
            "active": self.active,
            "min_amount": str(self.min_amount),
            "max_amount": str(self.max_amount),
            "confirmations_required": self.confirmations_required,
        }
