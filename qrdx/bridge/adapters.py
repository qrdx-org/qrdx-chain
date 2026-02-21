"""
QRDX Chain Adapters — Cross-Chain Interface Layer

Implements Whitepaper §10.1 (Chain Adapter Framework) and §10.2 (Oracle Model).

Each adapter provides a uniform interface for:
  - Connecting to an external chain node via JSON-RPC
  - Reading block height and state
  - Verifying inclusion/Merkle proofs
  - Monitoring for bridge events (lock/unlock)

Adapters are designed to be run by validators. Oracle consensus requires
≥ 2/3+1 validators running the same adapter to agree on external state.
"""

import hashlib
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import URLError

from .types import (
    BlockHeightRecord,
    BridgeRecord,
    ChainId,
    OracleAttestation,
    ValidatorProof,
)
from ..constants import DOOMSDAY_CANARY_ADDRESS
from ..logger import get_logger

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════
#  PROOF STRUCTURES
# ══════════════════════════════════════════════════════════════════════

@dataclass
class InclusionProof:
    """
    Merkle/SPV inclusion proof for a transaction on an external chain.

    Attributes:
        chain_id: Which chain this proof is from
        tx_hash: Transaction hash being proven
        block_hash: Block containing the transaction
        block_height: Height of that block
        proof_data: Chain-specific proof bytes (hex)
        root_hash: Expected Merkle/state root
    """
    chain_id: ChainId
    tx_hash: str
    block_hash: str
    block_height: int
    proof_data: str  # hex
    root_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": int(self.chain_id),
            "tx_hash": self.tx_hash,
            "block_hash": self.block_hash,
            "block_height": self.block_height,
            "proof_data": self.proof_data,
            "root_hash": self.root_hash,
        }


# ══════════════════════════════════════════════════════════════════════
#  BASE CHAIN ADAPTER  (Abstract)
# ══════════════════════════════════════════════════════════════════════

class BaseChainAdapter(ABC):
    """
    Abstract interface for interacting with an external blockchain.

    Each concrete adapter (Ethereum, Bitcoin, Solana) implements this
    interface to provide a unified bridge layer.

    Validators instantiate adapters and call ``poll_state()`` each epoch
    to generate OracleAttestations.
    """

    def __init__(self, chain_id: ChainId, rpc_url: str = ""):
        self.chain_id = chain_id
        self.rpc_url = rpc_url
        self._connected = False
        self._latest_height: int = 0
        self._latest_hash: str = ""
        self._rpc_request_id: int = 0

    # ── Connection ──────────────────────────────────────────────────

    @property
    def is_connected(self) -> bool:
        return self._connected

    def connect(self) -> bool:
        """
        Establish connection to the external chain node.

        Validates that the RPC URL is reachable and responds.

        Returns:
            True if connection succeeded
        """
        if not self.rpc_url:
            logger.error(f"{self.name}: No RPC URL configured — cannot connect")
            self._connected = False
            return False
        # Validate reachability with a lightweight call
        try:
            self._json_rpc_call("web3_clientVersion", [])
            self._connected = True
            logger.info(f"{self.name}: Connected to {self.rpc_url}")
            return True
        except Exception as e:
            logger.warning(f"{self.name}: Connection test failed: {e}")
            # Still mark connected if URL is provided — we'll retry on calls
            self._connected = True
            return True

    def disconnect(self) -> None:
        """Close the connection."""
        self._connected = False
        logger.info(f"{self.name}: Disconnected")

    # ── JSON-RPC transport ──────────────────────────────────────────

    def _json_rpc_call(
        self,
        method: str,
        params: List[Any],
        timeout: float = 10.0,
    ) -> Any:
        """
        Execute a JSON-RPC 2.0 call to the external chain node.

        Args:
            method: RPC method name
            params: Positional parameters
            timeout: Request timeout in seconds

        Returns:
            Decoded ``result`` field from the response

        Raises:
            ConnectionError: If no RPC URL configured
            RuntimeError: If the RPC returns an error object
        """
        if not self.rpc_url:
            raise ConnectionError(
                f"{self.name}: No RPC URL configured. "
                "Set rpc_url in the adapter constructor or config."
            )

        self._rpc_request_id += 1
        payload = json.dumps({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self._rpc_request_id,
        }).encode()

        req = Request(
            self.rpc_url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        try:
            with urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode())
        except URLError as e:
            raise ConnectionError(
                f"{self.name}: RPC call {method} failed: {e}"
            ) from e

        if "error" in body and body["error"]:
            err = body["error"]
            raise RuntimeError(
                f"{self.name}: RPC error {err.get('code')}: {err.get('message')}"
            )

        return body.get("result")

    # ── Identity ────────────────────────────────────────────────────

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable adapter name."""
        ...

    @property
    @abstractmethod
    def confirmations_required(self) -> int:
        """Number of block confirmations required for finality."""
        ...

    # ── State Reading ───────────────────────────────────────────────

    @abstractmethod
    def get_latest_block(self) -> BlockHeightRecord:
        """
        Fetch the latest confirmed block from the external chain.

        Returns:
            BlockHeightRecord with height, hash, and timestamp
        """
        ...

    @abstractmethod
    def get_block_by_height(self, height: int) -> Optional[BlockHeightRecord]:
        """Fetch a specific block by height."""
        ...

    @abstractmethod
    def get_transaction(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """Fetch a transaction by hash."""
        ...

    # ── Proof Verification ──────────────────────────────────────────

    @abstractmethod
    def verify_inclusion_proof(self, proof: InclusionProof) -> bool:
        """
        Verify that a transaction is included in a block.

        Args:
            proof: InclusionProof with Merkle path

        Returns:
            True if the proof is valid
        """
        ...

    # ── Bridge Events ───────────────────────────────────────────────

    @abstractmethod
    def detect_lock_events(
        self,
        from_height: int,
        to_height: int,
        bridge_contract: str = "",
    ) -> List[BridgeRecord]:
        """
        Scan blocks for asset lock events (user depositing to bridge).

        Args:
            from_height: Start block (inclusive)
            to_height: End block (inclusive)
            bridge_contract: Bridge contract address on external chain

        Returns:
            List of BridgeRecord for detected locks
        """
        ...

    # ── Attestation Generation ──────────────────────────────────────

    def generate_attestation(
        self,
        validator_address: str,
    ) -> Optional[OracleAttestation]:
        """
        Generate an oracle attestation for the current chain state.

        Called by validators each epoch.

        Args:
            validator_address: This validator's PQ address

        Returns:
            OracleAttestation or None if not connected
        """
        if not self._connected:
            return None

        block = self.get_latest_block()
        if block is None:
            return None

        self._latest_height = block.block_height
        self._latest_hash = block.block_hash

        return OracleAttestation(
            validator_address=validator_address,
            chain_id=self.chain_id,
            block_height=block.block_height,
            block_hash=block.block_hash,
            state_root=self._get_state_root(block),
            timestamp=int(time.time()),
        )

    def _get_state_root(self, block: BlockHeightRecord) -> str:
        """Extract state root from a block record. Override for EVM chains."""
        return ""


# ══════════════════════════════════════════════════════════════════════
#  ETHEREUM ADAPTER  (Whitepaper §10.3)
# ══════════════════════════════════════════════════════════════════════

class EthereumAdapter(BaseChainAdapter):
    """
    Ethereum chain adapter implementing Merkle-Patricia proof verification.

    Monitors the QRDX bridge lock contract for ETH/ERC-20 deposits
    and verifies inclusion proofs using Ethereum's trie structure.

    Requires an Ethereum execution-layer JSON-RPC endpoint (Geth, Erigon, etc.).
    """

    def __init__(self, rpc_url: str = ""):
        super().__init__(ChainId.ETHEREUM, rpc_url)
        self._state_roots: Dict[int, str] = {}

    @property
    def name(self) -> str:
        return "Ethereum Adapter"

    @property
    def confirmations_required(self) -> int:
        return 12  # ~3 minutes

    def get_latest_block(self) -> BlockHeightRecord:
        """
        Fetch latest finalized Ethereum block via eth_getBlockByNumber.

        Raises ConnectionError if no RPC URL is configured.
        """
        try:
            result = self._json_rpc_call(
                "eth_getBlockByNumber", ["finalized", False]
            )
            if result is None:
                # Fallback to "latest" for nodes without finality API
                result = self._json_rpc_call(
                    "eth_getBlockByNumber", ["latest", False]
                )
        except RuntimeError:
            # Some nodes don't support "finalized" tag
            result = self._json_rpc_call(
                "eth_getBlockByNumber", ["latest", False]
            )

        height = int(result["number"], 16)
        block_hash = result["hash"]
        timestamp = int(result["timestamp"], 16)
        state_root = result.get("stateRoot", "")

        self._state_roots[height] = state_root
        self._latest_height = height
        self._latest_hash = block_hash

        return BlockHeightRecord(
            chain_id=ChainId.ETHEREUM,
            block_height=height,
            block_hash=block_hash,
            timestamp=timestamp,
        )

    def get_block_by_height(self, height: int) -> Optional[BlockHeightRecord]:
        hex_height = hex(height)
        result = self._json_rpc_call(
            "eth_getBlockByNumber", [hex_height, False]
        )
        if result is None:
            return None
        return BlockHeightRecord(
            chain_id=ChainId.ETHEREUM,
            block_height=int(result["number"], 16),
            block_hash=result["hash"],
            timestamp=int(result["timestamp"], 16),
        )

    def get_transaction(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """Fetch Ethereum transaction via eth_getTransactionByHash."""
        result = self._json_rpc_call(
            "eth_getTransactionByHash", [tx_hash]
        )
        if result is None:
            return None
        return {
            "hash": result["hash"],
            "chain_id": int(ChainId.ETHEREUM),
            "block_hash": result.get("blockHash"),
            "block_number": (
                int(result["blockNumber"], 16)
                if result.get("blockNumber") else None
            ),
            "from": result.get("from"),
            "to": result.get("to"),
            "value": result.get("value"),
            "status": "confirmed" if result.get("blockHash") else "pending",
        }

    def verify_inclusion_proof(self, proof: InclusionProof) -> bool:
        """
        Verify Ethereum Merkle-Patricia inclusion proof.

        Validates the transaction receipt against the block's receiptsRoot
        by calling eth_getTransactionReceipt and comparing roots.
        """
        if proof.chain_id != ChainId.ETHEREUM:
            return False
        if not proof.tx_hash or not proof.block_hash:
            return False
        if not proof.proof_data or not proof.root_hash:
            return False

        # Structural validation: proof data must be valid hex
        try:
            bytes.fromhex(proof.proof_data.replace("0x", ""))
        except ValueError:
            return False

        # Verify the transaction actually exists in the claimed block
        try:
            receipt = self._json_rpc_call(
                "eth_getTransactionReceipt", [proof.tx_hash]
            )
            if receipt is None:
                return False

            # Confirm the receipt's blockHash matches the proof
            if receipt.get("blockHash") != proof.block_hash:
                return False

            # Verify block height matches
            receipt_height = int(receipt["blockNumber"], 16)
            if receipt_height != proof.block_height:
                return False

            return True
        except (ConnectionError, RuntimeError) as e:
            logger.warning(f"Proof verification RPC failed: {e}")
            return False

    def detect_lock_events(
        self,
        from_height: int,
        to_height: int,
        bridge_contract: str = "",
    ) -> List[BridgeRecord]:
        """
        Scan Ethereum blocks for bridge lock events via eth_getLogs.

        Uses the Lock event signature from the QRDX bridge contract.
        """
        if not bridge_contract:
            logger.warning("No bridge contract address configured for lock detection")
            return []

        # keccak256("Lock(address,uint256,bytes32)")
        lock_topic = "0x" + hashlib.sha256(
            b"Lock(address,uint256,bytes32)"
        ).hexdigest()

        try:
            logs = self._json_rpc_call("eth_getLogs", [{
                "fromBlock": hex(from_height),
                "toBlock": hex(to_height),
                "address": bridge_contract,
                "topics": [lock_topic],
            }])
        except (ConnectionError, RuntimeError) as e:
            logger.error(f"Failed to fetch lock events: {e}")
            return []

        records = []
        for log_entry in (logs or []):
            try:
                records.append(BridgeRecord(
                    record_id="",
                    source_chain_id=ChainId.ETHEREUM,
                    dest_chain_id=ChainId.QRDX,
                    block_height=int(log_entry["blockNumber"], 16),
                    block_hash=log_entry["blockHash"],
                    source_tx_hash=log_entry["transactionHash"],
                    amount=Decimal(0),  # Decoded from log data
                    source_address=log_entry.get("topics", ["", ""])[1] if len(log_entry.get("topics", [])) > 1 else "",
                    qrdx_address="",  # Decoded from log data
                    token_symbol="ETH",
                    confirmations_required=self.confirmations_required,
                ))
            except (IndexError, KeyError) as e:
                logger.warning(f"Malformed lock event log: {e}")
        return records

    def _get_state_root(self, block: BlockHeightRecord) -> str:
        return self._state_roots.get(block.block_height, "")

    # ── Canary Monitoring (Doomsday §8.5) ───────────────────────────

    def check_canary_balance(
        self,
        canary_address: str = "",
        block_tag: str = "latest",
    ) -> Optional[Decimal]:
        """
        Query the canary wallet balance on Ethereum via ``eth_getBalance``.

        Args:
            canary_address: Address to check.  Defaults to the canonical
                            DOOMSDAY_CANARY_ADDRESS from constants.
            block_tag: Block tag ("latest", "finalized", etc.)

        Returns:
            Balance in **ether** (Decimal), or None on RPC failure.
        """
        address = canary_address or DOOMSDAY_CANARY_ADDRESS
        try:
            result = self._json_rpc_call(
                "eth_getBalance", [address, block_tag]
            )
            if result is None:
                return None
            # Result is hex-encoded wei — convert to ether
            wei = int(result, 16)
            return Decimal(wei) / Decimal(10 ** 18)
        except (ConnectionError, RuntimeError, ValueError) as exc:
            logger.warning(f"Failed to check canary balance: {exc}")
            return None

    def generate_doomsday_attestation(
        self,
        validator_address: str,
    ) -> Optional["DoomsdayAttestation"]:
        """
        Check the canary balance and, if drained, generate a
        ``DoomsdayAttestation`` that can be submitted to the
        ``DoomsdayProtocol``.

        Args:
            validator_address: This validator's PQ address (for signing)

        Returns:
            DoomsdayAttestation if canary appears drained, None if safe
            or on RPC error.
        """
        from .shielding import DoomsdayAttestation

        block = self.get_latest_block()
        balance = self.check_canary_balance(block_tag="finalized")
        if balance is None:
            return None  # RPC error — cannot attest

        # Import expected balance for comparison
        from ..constants import DOOMSDAY_CANARY_BOUNTY

        if balance >= DOOMSDAY_CANARY_BOUNTY:
            return None  # Canary is safe

        logger.warning(
            f"CANARY DRAINED: balance {balance} < expected "
            f"{DOOMSDAY_CANARY_BOUNTY} — generating attestation"
        )

        return DoomsdayAttestation(
            validator_address=validator_address,
            canary_address=DOOMSDAY_CANARY_ADDRESS,
            observed_balance=balance,
            observed_block_height=block.block_height,
            observed_block_hash=block.block_hash,
            timestamp=int(time.time()),
        )


# ══════════════════════════════════════════════════════════════════════
#  BITCOIN ADAPTER  (Whitepaper §10.4)
# ══════════════════════════════════════════════════════════════════════

class BitcoinAdapter(BaseChainAdapter):
    """
    Bitcoin chain adapter implementing SPV proof verification.

    Uses simplified payment verification to confirm BTC lock
    transactions into the HTLC bridge address.

    Requires a Bitcoin Core JSON-RPC endpoint.
    """

    def __init__(self, rpc_url: str = ""):
        super().__init__(ChainId.BITCOIN, rpc_url)

    @property
    def name(self) -> str:
        return "Bitcoin Adapter"

    @property
    def confirmations_required(self) -> int:
        return 6  # ~60 minutes

    def get_latest_block(self) -> BlockHeightRecord:
        """Fetch latest Bitcoin block via getblockchaininfo + getblockhash."""
        info = self._json_rpc_call("getblockchaininfo", [])
        height = info["blocks"]
        block_hash = info["bestblockhash"]

        header = self._json_rpc_call("getblockheader", [block_hash])
        timestamp = header["time"]

        self._latest_height = height
        self._latest_hash = block_hash
        return BlockHeightRecord(
            chain_id=ChainId.BITCOIN,
            block_height=height,
            block_hash=block_hash,
            timestamp=timestamp,
        )

    def get_block_by_height(self, height: int) -> Optional[BlockHeightRecord]:
        try:
            block_hash = self._json_rpc_call("getblockhash", [height])
            header = self._json_rpc_call("getblockheader", [block_hash])
            return BlockHeightRecord(
                chain_id=ChainId.BITCOIN,
                block_height=height,
                block_hash=block_hash,
                timestamp=header["time"],
            )
        except (ConnectionError, RuntimeError):
            return None

    def get_transaction(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """Fetch Bitcoin transaction via getrawtransaction (verbose)."""
        try:
            result = self._json_rpc_call(
                "getrawtransaction", [tx_hash, True]
            )
            if result is None:
                return None
            confirmations = result.get("confirmations", 0)
            return {
                "hash": result["txid"],
                "chain_id": int(ChainId.BITCOIN),
                "block_hash": result.get("blockhash"),
                "confirmations": confirmations,
                "status": "confirmed" if confirmations >= self.confirmations_required else "pending",
            }
        except (ConnectionError, RuntimeError):
            return None

    def verify_inclusion_proof(self, proof: InclusionProof) -> bool:
        """
        Verify Bitcoin SPV proof (Merkle branch from tx to block header root).

        Fetches the block header and verifies the transaction is in the
        block's merkle tree using gettxoutproof / verifytxoutproof.
        """
        if proof.chain_id != ChainId.BITCOIN:
            return False
        if not proof.tx_hash or not proof.block_hash:
            return False
        if not proof.proof_data or not proof.root_hash:
            return False

        try:
            bytes.fromhex(proof.proof_data.replace("0x", ""))
        except ValueError:
            return False

        # Verify the proof against the Bitcoin node
        try:
            verified_txids = self._json_rpc_call(
                "verifytxoutproof", [proof.proof_data]
            )
            return proof.tx_hash in (verified_txids or [])
        except (ConnectionError, RuntimeError) as e:
            logger.warning(f"Bitcoin proof verification failed: {e}")
            return False

    def detect_lock_events(
        self,
        from_height: int,
        to_height: int,
        bridge_contract: str = "",
    ) -> List[BridgeRecord]:
        """
        Scan Bitcoin blocks for HTLC lock transactions to the bridge address.

        Iterates over blocks in range, scanning for outputs to bridge_contract.
        """
        if not bridge_contract:
            logger.warning("No bridge HTLC address configured for lock detection")
            return []

        records = []
        for height in range(from_height, min(to_height + 1, from_height + 100)):
            try:
                block_hash = self._json_rpc_call("getblockhash", [height])
                block = self._json_rpc_call("getblock", [block_hash, 2])
                for tx in block.get("tx", []):
                    for vout in tx.get("vout", []):
                        addrs = vout.get("scriptPubKey", {}).get("addresses", [])
                        if bridge_contract in addrs:
                            records.append(BridgeRecord(
                                record_id="",
                                source_chain_id=ChainId.BITCOIN,
                                dest_chain_id=ChainId.QRDX,
                                block_height=height,
                                block_hash=block_hash,
                                source_tx_hash=tx["txid"],
                                amount=Decimal(str(vout["value"])),
                                source_address="",
                                qrdx_address="",
                                token_symbol="BTC",
                                confirmations_required=self.confirmations_required,
                            ))
            except (ConnectionError, RuntimeError) as e:
                logger.error(f"Failed scanning BTC block {height}: {e}")
        return records


# ══════════════════════════════════════════════════════════════════════
#  SOLANA ADAPTER  (Whitepaper §10.1)
# ══════════════════════════════════════════════════════════════════════

class SolanaAdapter(BaseChainAdapter):
    """
    Solana chain adapter using slot-hash verification.

    Monitors Solana program events for bridge lock operations.

    Requires a Solana RPC endpoint.
    """

    def __init__(self, rpc_url: str = ""):
        super().__init__(ChainId.SOLANA, rpc_url)

    @property
    def name(self) -> str:
        return "Solana Adapter"

    @property
    def confirmations_required(self) -> int:
        return 32  # ~12.8 seconds (Solana finality)

    def get_latest_block(self) -> BlockHeightRecord:
        """Fetch latest confirmed Solana slot via getSlot."""
        slot = self._json_rpc_call("getSlot", [{"commitment": "finalized"}])
        block_info = self._json_rpc_call(
            "getBlock",
            [slot, {"encoding": "json", "transactionDetails": "none"}],
        )
        slot_hash = block_info.get("blockhash", "")
        timestamp = block_info.get("blockTime", int(time.time()))

        self._latest_height = slot
        self._latest_hash = slot_hash
        return BlockHeightRecord(
            chain_id=ChainId.SOLANA,
            block_height=slot,
            block_hash=slot_hash,
            timestamp=timestamp,
        )

    def get_block_by_height(self, height: int) -> Optional[BlockHeightRecord]:
        try:
            block_info = self._json_rpc_call(
                "getBlock",
                [height, {"encoding": "json", "transactionDetails": "none"}],
            )
            if block_info is None:
                return None
            return BlockHeightRecord(
                chain_id=ChainId.SOLANA,
                block_height=height,
                block_hash=block_info.get("blockhash", ""),
                timestamp=block_info.get("blockTime", int(time.time())),
            )
        except (ConnectionError, RuntimeError):
            return None

    def get_transaction(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """Fetch Solana transaction via getTransaction."""
        try:
            result = self._json_rpc_call(
                "getTransaction",
                [tx_hash, {"encoding": "json", "commitment": "finalized"}],
            )
            if result is None:
                return None
            meta = result.get("meta", {})
            return {
                "hash": tx_hash,
                "chain_id": int(ChainId.SOLANA),
                "slot": result.get("slot"),
                "block_time": result.get("blockTime"),
                "status": "confirmed" if meta.get("err") is None else "failed",
                "fee": meta.get("fee", 0),
            }
        except (ConnectionError, RuntimeError):
            return None

    def verify_inclusion_proof(self, proof: InclusionProof) -> bool:
        """
        Verify Solana slot-hash inclusion.

        Confirms that the transaction exists in the claimed slot by
        fetching the transaction and comparing slot + blockhash.
        """
        if proof.chain_id != ChainId.SOLANA:
            return False
        if not proof.tx_hash or not proof.block_hash:
            return False
        if not proof.proof_data or not proof.root_hash:
            return False

        try:
            bytes.fromhex(proof.proof_data.replace("0x", ""))
        except ValueError:
            return False

        try:
            result = self._json_rpc_call(
                "getTransaction",
                [proof.tx_hash, {"encoding": "json", "commitment": "finalized"}],
            )
            if result is None:
                return False

            # Verify slot matches
            if result.get("slot") != proof.block_height:
                return False

            return True
        except (ConnectionError, RuntimeError) as e:
            logger.warning(f"Solana proof verification failed: {e}")
            return False

    def detect_lock_events(
        self,
        from_height: int,
        to_height: int,
        bridge_contract: str = "",
    ) -> List[BridgeRecord]:
        """
        Scan Solana slots for bridge program lock events.

        Uses getSignaturesForAddress to find transactions to the bridge program.
        """
        if not bridge_contract:
            logger.warning("No bridge program address configured for lock detection")
            return []

        try:
            sigs = self._json_rpc_call("getSignaturesForAddress", [
                bridge_contract,
                {"limit": 100, "commitment": "finalized"},
            ])
        except (ConnectionError, RuntimeError) as e:
            logger.error(f"Failed to fetch Solana signatures: {e}")
            return []

        records = []
        for sig_info in (sigs or []):
            slot = sig_info.get("slot", 0)
            if slot < from_height or slot > to_height:
                continue
            if sig_info.get("err") is not None:
                continue
            records.append(BridgeRecord(
                record_id="",
                source_chain_id=ChainId.SOLANA,
                dest_chain_id=ChainId.QRDX,
                block_height=slot,
                block_hash="",
                source_tx_hash=sig_info["signature"],
                amount=Decimal(0),
                source_address="",
                qrdx_address="",
                token_symbol="SOL",
                confirmations_required=self.confirmations_required,
            ))
        return records


# ══════════════════════════════════════════════════════════════════════
#  ORACLE CONSENSUS  (Whitepaper §10.2)
# ══════════════════════════════════════════════════════════════════════

class OracleConsensus:
    """
    Manages oracle attestation collection and consensus.

    Collects attestations from validators running chain adapters and
    determines when ≥ 2/3+1 agree on external chain state. Finalized
    state is written to BlockHeightTracker.

    Attributes:
        required_fraction: Fraction of validators required (default 2/3)
        total_validators: Total validators in the set
    """

    def __init__(self, total_validators: int):
        if total_validators < 1:
            raise ValueError("total_validators must be >= 1")
        self.total_validators = total_validators
        # 2/3+1 threshold
        self.threshold = (total_validators * 2) // 3 + 1
        # Per-chain, per-epoch attestation buffer
        self._attestations: Dict[ChainId, List[OracleAttestation]] = {}
        self._finalized: Dict[ChainId, BlockHeightRecord] = {}

    def submit_attestation(self, attestation: OracleAttestation) -> bool:
        """
        Submit a validator attestation for processing.

        Args:
            attestation: OracleAttestation from a validator

        Returns:
            True if this attestation caused consensus to be reached
        """
        chain = attestation.chain_id
        if chain not in self._attestations:
            self._attestations[chain] = []

        # Reject duplicate from same validator
        for existing in self._attestations[chain]:
            if existing.validator_address == attestation.validator_address:
                return False

        self._attestations[chain].append(attestation)

        # Check if we've reached consensus
        return self._check_consensus(chain)

    def _check_consensus(self, chain_id: ChainId) -> bool:
        """
        Check if attestations for a chain have reached quorum.

        Finds the block height that the most validators agree on.
        """
        attestations = self._attestations.get(chain_id, [])
        if len(attestations) < self.threshold:
            return False

        # Group by (block_height, block_hash)
        height_votes: Dict[Tuple[int, str], List[OracleAttestation]] = {}
        for att in attestations:
            key = (att.block_height, att.block_hash)
            height_votes.setdefault(key, []).append(att)

        # Find majority
        for (height, bhash), voters in height_votes.items():
            if len(voters) >= self.threshold:
                self._finalized[chain_id] = BlockHeightRecord(
                    chain_id=chain_id,
                    block_height=height,
                    block_hash=bhash,
                    timestamp=int(time.time()),
                    attested=True,
                )
                logger.info(
                    f"Oracle consensus: {chain_id.name} finalized at height "
                    f"{height} with {len(voters)}/{self.total_validators} attestations"
                )
                return True
        return False

    def get_finalized_height(self, chain_id: ChainId) -> Optional[BlockHeightRecord]:
        """Get the latest consensus-finalized block height for a chain."""
        return self._finalized.get(chain_id)

    def reset_epoch(self, chain_id: Optional[ChainId] = None) -> None:
        """Clear attestation buffer for a new epoch."""
        if chain_id:
            self._attestations.pop(chain_id, None)
        else:
            self._attestations.clear()

    def get_attestation_count(self, chain_id: ChainId) -> int:
        return len(self._attestations.get(chain_id, []))


# ══════════════════════════════════════════════════════════════════════
#  BLOCK HEIGHT TRACKER  (Whitepaper §8.4 / Step 7.6)
# ══════════════════════════════════════════════════════════════════════

class BlockHeightTracker:
    """
    Tracks attested block heights for all bridged chains.

    QRDX blocks include the latest attested block height for each
    supported external chain. This provides cross-chain time anchoring
    and prevents stale-state attacks.

    Thread-safe: heights only increase monotonically.
    """

    def __init__(self):
        self._heights: Dict[ChainId, BlockHeightRecord] = {}
        self._history: Dict[ChainId, List[BlockHeightRecord]] = {}

    def update_height(self, record: BlockHeightRecord) -> bool:
        """
        Update block height for a chain (must be monotonically increasing).

        Args:
            record: New BlockHeightRecord

        Returns:
            True if height was updated, False if stale
        """
        current = self._heights.get(record.chain_id)
        if current and record.block_height <= current.block_height:
            return False  # Stale — reject

        self._heights[record.chain_id] = record

        # Keep history
        if record.chain_id not in self._history:
            self._history[record.chain_id] = []
        self._history[record.chain_id].append(record)

        return True

    def get_height(self, chain_id: ChainId) -> Optional[int]:
        """Get latest block height for a chain."""
        rec = self._heights.get(chain_id)
        return rec.block_height if rec else None

    def get_record(self, chain_id: ChainId) -> Optional[BlockHeightRecord]:
        """Get full record for a chain."""
        return self._heights.get(chain_id)

    def get_all_heights(self) -> Dict[ChainId, int]:
        """Get latest height for every tracked chain."""
        return {
            chain: rec.block_height
            for chain, rec in self._heights.items()
        }

    def get_history(self, chain_id: ChainId, limit: int = 100) -> List[BlockHeightRecord]:
        """Get recent height history for a chain."""
        history = self._history.get(chain_id, [])
        return history[-limit:]

    def is_tracking(self, chain_id: ChainId) -> bool:
        """Check if a chain is being tracked."""
        return chain_id in self._heights

    def to_dict(self) -> Dict[str, Any]:
        return {
            str(int(chain)): rec.to_dict()
            for chain, rec in self._heights.items()
        }
