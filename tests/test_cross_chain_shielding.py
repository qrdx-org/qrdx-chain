"""
Phase 6 — Cross-Chain & Shielding Test Suite

Validates Steps 7 (Cross-Chain Oracle & Bridge), 8 (Asset Shielding),
and 4.5 (Oracle Precompiles) as defined in QRDX_IMPLEMENTATION_CHECKLIST.md.

Coverage:
  - Bridge types: ChainId, BlockHeightRecord, BridgeRecord, ValidatorProof,
    OracleAttestation, ExecutionCondition, OracleTransaction, BridgeTokenConfig
  - Chain adapters: EthereumAdapter, BitcoinAdapter, SolanaAdapter, InclusionProof
  - Oracle consensus: OracleConsensus, BlockHeightTracker
  - Shielding: ShieldingManager, DoomsdayProtocol, BridgeMinter
  - Oracle precompiles: getChainState, verifyExternalProof, submitCrossChainTx
"""

import hashlib
import time
import sys
import os
from decimal import Decimal
from unittest.mock import MagicMock, patch

import pytest

# ── Path setup ────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# ── Imports: Bridge types ─────────────────────────────────────────────
from qrdx.bridge.types import (
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

# ── Imports: Adapters ─────────────────────────────────────────────────
from qrdx.bridge.adapters import (
    BaseChainAdapter,
    BitcoinAdapter,
    BlockHeightTracker,
    EthereumAdapter,
    InclusionProof,
    OracleConsensus,
    SolanaAdapter,
)

# ── Imports: Shielding ────────────────────────────────────────────────
from qrdx.bridge.shielding import (
    BRIDGE_FEE_BPS,
    BridgeMinter,
    DEFAULT_TOKEN_CONFIGS,
    DOOMSDAY_CANARY_ADDRESS,
    DoomsdayProtocol,
    FRAUD_PROOF_WINDOW_SECONDS,
    HIGH_VALUE_THRESHOLD_USD,
    ShieldingManager,
)


# ══════════════════════════════════════════════════════════════════════
#  SECTION 1: CHAIN IDs & BLOCK HEIGHT RECORDS
# ══════════════════════════════════════════════════════════════════════

class TestChainIds:
    """Step 7.1 — Chain identifier enum."""

    def test_chain_id_values(self):
        assert ChainId.QRDX == 0
        assert ChainId.ETHEREUM == 1
        assert ChainId.BITCOIN == 2
        assert ChainId.SOLANA == 3
        assert ChainId.COSMOS == 4

    def test_chain_names_lookup(self):
        assert CHAIN_NAMES[ChainId.ETHEREUM] == "Ethereum"
        assert CHAIN_NAMES[ChainId.BITCOIN] == "Bitcoin"
        assert CHAIN_NAMES[ChainId.SOLANA] == "Solana"
        assert CHAIN_NAMES[ChainId.COSMOS] == "Cosmos"
        assert CHAIN_NAMES[ChainId.QRDX] == "QRDX"

    def test_chain_id_is_int(self):
        assert int(ChainId.ETHEREUM) == 1
        assert isinstance(ChainId.BITCOIN, int)


class TestBlockHeightRecord:
    """Step 7.6 — Block height recording."""

    def test_create_record(self):
        rec = BlockHeightRecord(
            chain_id=ChainId.ETHEREUM,
            block_height=18000000,
            block_hash="abc123" * 10,
            timestamp=int(time.time()),
        )
        assert rec.chain_id == ChainId.ETHEREUM
        assert rec.block_height == 18000000
        assert rec.attested is False

    def test_attested_record(self):
        rec = BlockHeightRecord(
            chain_id=ChainId.BITCOIN,
            block_height=800000,
            block_hash="def456" * 10,
            timestamp=int(time.time()),
            attested=True,
        )
        assert rec.attested is True

    def test_negative_height_rejected(self):
        with pytest.raises(ValueError):
            BlockHeightRecord(
                chain_id=ChainId.ETHEREUM,
                block_height=-1,
                block_hash="abc",
                timestamp=int(time.time()),
            )

    def test_serialization_roundtrip(self):
        rec = BlockHeightRecord(
            chain_id=ChainId.SOLANA,
            block_height=200000000,
            block_hash="aabb" * 16,
            timestamp=1700000000,
            attested=True,
        )
        d = rec.to_dict()
        rec2 = BlockHeightRecord.from_dict(d)
        assert rec2.chain_id == rec.chain_id
        assert rec2.block_height == rec.block_height
        assert rec2.block_hash == rec.block_hash
        assert rec2.attested is True


# ══════════════════════════════════════════════════════════════════════
#  SECTION 2: BRIDGE RECORD
# ══════════════════════════════════════════════════════════════════════

class TestBridgeRecord:
    """Step 7.5 — Bridge lock/unlock record."""

    def _make_record(self, **kwargs):
        defaults = dict(
            record_id="",
            source_chain_id=ChainId.ETHEREUM,
            dest_chain_id=ChainId.QRDX,
            block_height=18000000,
            block_hash="abcdef" * 10,
            source_tx_hash="0x" + "aa" * 32,
            amount=Decimal("1.5"),
            source_address="0xSenderOnETH",
            qrdx_address="0xPQRecipient",
            operation=BridgeOperationType.SHIELD,
            token_symbol="ETH",
        )
        defaults.update(kwargs)
        return BridgeRecord(**defaults)

    def test_create_shield_record(self):
        rec = self._make_record()
        assert rec.is_shielding is True
        assert rec.status == BridgeStatus.PENDING
        assert rec.record_id  # auto-generated

    def test_record_id_deterministic(self):
        r1 = self._make_record()
        r2 = self._make_record()
        assert r1.record_id == r2.record_id

    def test_zero_amount_rejected(self):
        with pytest.raises(ValueError):
            self._make_record(amount=Decimal("0"))

    def test_negative_amount_rejected(self):
        with pytest.raises(ValueError):
            self._make_record(amount=Decimal("-1"))

    def test_add_confirmation(self):
        rec = self._make_record(confirmations_required=3)
        rec.add_confirmation()
        assert rec.confirmations_received == 1
        assert rec.status == BridgeStatus.PENDING
        rec.add_confirmation()
        rec.add_confirmation()
        assert rec.is_confirmed is True
        assert rec.status == BridgeStatus.CONFIRMING

    def test_serialization_roundtrip(self):
        rec = self._make_record()
        d = rec.to_dict()
        rec2 = BridgeRecord.from_dict(d)
        assert rec2.record_id == rec.record_id
        assert rec2.amount == rec.amount
        assert rec2.operation == BridgeOperationType.SHIELD

    def test_unshield_record(self):
        rec = self._make_record(operation=BridgeOperationType.UNSHIELD)
        assert rec.is_shielding is False
        assert rec.operation == BridgeOperationType.UNSHIELD


# ══════════════════════════════════════════════════════════════════════
#  SECTION 3: VALIDATOR PROOF
# ══════════════════════════════════════════════════════════════════════

class TestValidatorProof:
    """Step 7.3 — Validator proof structure."""

    def test_threshold_met(self):
        proof = ValidatorProof(
            message_hash="abc123",
            signatures=["sig1", "sig2", "sig3"],
            signers=["v1", "v2", "v3"],
            nonce=1,
            threshold=2,
        )
        assert proof.meets_threshold is True
        assert proof.signature_count == 3

    def test_threshold_not_met(self):
        proof = ValidatorProof(
            message_hash="abc123",
            signatures=["sig1"],
            signers=["v1"],
            nonce=1,
            threshold=3,
        )
        assert proof.meets_threshold is False

    def test_mismatched_signatures_signers(self):
        with pytest.raises(ValueError):
            ValidatorProof(
                message_hash="abc",
                signatures=["s1", "s2"],
                signers=["v1"],
                nonce=1,
                threshold=1,
            )

    def test_zero_threshold_rejected(self):
        with pytest.raises(ValueError):
            ValidatorProof(
                message_hash="abc",
                signatures=[],
                signers=[],
                nonce=0,
                threshold=0,
            )

    def test_serialization_roundtrip(self):
        proof = ValidatorProof(
            message_hash="deadbeef",
            signatures=["sig_a", "sig_b"],
            signers=["val_a", "val_b"],
            nonce=42,
            threshold=2,
        )
        d = proof.to_dict()
        proof2 = ValidatorProof.from_dict(d)
        assert proof2.message_hash == proof.message_hash
        assert proof2.meets_threshold is True


# ══════════════════════════════════════════════════════════════════════
#  SECTION 4: ORACLE ATTESTATION
# ══════════════════════════════════════════════════════════════════════

class TestOracleAttestation:
    """Step 7.3 — Oracle attestation for external chain state."""

    def _make_attestation(self, **kwargs):
        defaults = dict(
            validator_address="0xPQValidator1",
            chain_id=ChainId.ETHEREUM,
            block_height=18000000,
            block_hash="aa" * 32,
            state_root="bb" * 32,
            timestamp=1700000000,
        )
        defaults.update(kwargs)
        return OracleAttestation(**defaults)

    def test_create_attestation(self):
        att = self._make_attestation()
        assert att.chain_id == ChainId.ETHEREUM
        assert att.block_height == 18000000

    def test_attestation_hash_deterministic(self):
        a1 = self._make_attestation()
        a2 = self._make_attestation()
        assert a1.attestation_hash() == a2.attestation_hash()

    def test_attestation_hash_changes_with_input(self):
        a1 = self._make_attestation(block_height=100)
        a2 = self._make_attestation(block_height=101)
        assert a1.attestation_hash() != a2.attestation_hash()

    def test_serialization_roundtrip(self):
        att = self._make_attestation(signature="deadbeef" * 20)
        d = att.to_dict()
        att2 = OracleAttestation.from_dict(d)
        assert att2.validator_address == att.validator_address
        assert att2.signature == att.signature


# ══════════════════════════════════════════════════════════════════════
#  SECTION 5: EXECUTION CONDITIONS & ORACLE TRANSACTION
# ══════════════════════════════════════════════════════════════════════

class TestExecutionCondition:
    """Step 7.4 — Execution conditions for OracleTransactions."""

    def test_immediate_always_met(self):
        cond = ExecutionCondition(condition_type=ConditionType.IMMEDIATE)
        assert cond.is_met() is True

    def test_after_block_height_met(self):
        cond = ExecutionCondition(
            condition_type=ConditionType.AFTER_BLOCK_HEIGHT,
            chain_id=ChainId.ETHEREUM,
            value=18000000,
        )
        heights = {ChainId.ETHEREUM: 18000001}
        assert cond.is_met(heights) is True

    def test_after_block_height_not_met(self):
        cond = ExecutionCondition(
            condition_type=ConditionType.AFTER_BLOCK_HEIGHT,
            chain_id=ChainId.ETHEREUM,
            value=18000000,
        )
        heights = {ChainId.ETHEREUM: 17999999}
        assert cond.is_met(heights) is False

    def test_after_block_height_no_data(self):
        cond = ExecutionCondition(
            condition_type=ConditionType.AFTER_BLOCK_HEIGHT,
            chain_id=ChainId.BITCOIN,
            value=800000,
        )
        assert cond.is_met({}) is False

    def test_serialization_roundtrip(self):
        cond = ExecutionCondition(
            condition_type=ConditionType.PRICE_THRESHOLD,
            chain_id=ChainId.ETHEREUM,
            value=5000,
            reference="ETH/USD",
        )
        d = cond.to_dict()
        cond2 = ExecutionCondition.from_dict(d)
        assert cond2.condition_type == ConditionType.PRICE_THRESHOLD
        assert cond2.reference == "ETH/USD"


class TestOracleTransaction:
    """Step 7.4 — OracleTransaction envelope type."""

    def _make_oracle_tx(self, **kwargs):
        defaults = dict(
            nonce=1,
            sender="0xPQSender",
            target_chain_id=ChainId.ETHEREUM,
            tx_type=OracleTxType.ETHEREUM,
            inner_transaction="deadbeef" * 8,
        )
        defaults.update(kwargs)
        return OracleTransaction(**defaults)

    def test_create_oracle_tx(self):
        tx = self._make_oracle_tx()
        assert tx.status == OracleTxStatus.SUBMITTED
        assert tx.tx_hash  # auto-computed

    def test_hash_deterministic(self):
        t1 = self._make_oracle_tx(created_at=1000)
        t2 = self._make_oracle_tx(created_at=1000)
        assert t1.tx_hash == t2.tx_hash

    def test_conditions_met_no_conditions(self):
        tx = self._make_oracle_tx()
        assert tx.conditions_met() is True

    def test_conditions_met_with_immediate(self):
        cond = ExecutionCondition(condition_type=ConditionType.IMMEDIATE)
        tx = self._make_oracle_tx(conditions=[cond])
        assert tx.conditions_met() is True

    def test_conditions_not_met(self):
        cond = ExecutionCondition(
            condition_type=ConditionType.AFTER_BLOCK_HEIGHT,
            chain_id=ChainId.ETHEREUM,
            value=99999999,
        )
        tx = self._make_oracle_tx(conditions=[cond])
        assert tx.conditions_met({ChainId.ETHEREUM: 1}) is False

    def test_expiry(self):
        tx = self._make_oracle_tx(deadline=1)  # Unix epoch + 1 second
        assert tx.is_expired is True

    def test_no_expiry(self):
        tx = self._make_oracle_tx(deadline=0)
        assert tx.is_expired is False

    def test_serialization_roundtrip(self):
        cond = ExecutionCondition(
            condition_type=ConditionType.AFTER_BLOCK_HEIGHT,
            chain_id=ChainId.ETHEREUM,
            value=100,
        )
        tx = self._make_oracle_tx(conditions=[cond], deadline=99999999999)
        d = tx.to_dict()
        tx2 = OracleTransaction.from_dict(d)
        assert tx2.sender == tx.sender
        assert tx2.target_chain_id == ChainId.ETHEREUM
        assert len(tx2.conditions) == 1
        assert tx2.conditions[0].condition_type == ConditionType.AFTER_BLOCK_HEIGHT


class TestBridgeTokenConfig:
    """Step 7.5 — Bridge token configuration."""

    def test_default_eth_config(self):
        cfg = DEFAULT_TOKEN_CONFIGS["ETH"]
        assert cfg.symbol == "ETH"
        assert cfg.shielded_symbol == "qETH"
        assert cfg.source_chain_id == ChainId.ETHEREUM
        assert cfg.confirmations_required == 12

    def test_default_btc_config(self):
        cfg = DEFAULT_TOKEN_CONFIGS["BTC"]
        assert cfg.shielded_symbol == "qBTC"
        assert cfg.confirmations_required == 6

    def test_serialization_roundtrip(self):
        cfg = BridgeTokenConfig(
            symbol="ATOM",
            shielded_symbol="qATOM",
            source_chain_id=ChainId.COSMOS,
            decimals=6,
            confirmations_required=1,
        )
        d = cfg.to_dict()
        # Verify dict structure
        assert d["symbol"] == "ATOM"
        assert d["source_chain_id"] == 4


# ══════════════════════════════════════════════════════════════════════
#  SECTION 6: CHAIN ADAPTERS
# ══════════════════════════════════════════════════════════════════════

class TestEthereumAdapter:
    """Step 7.1 — Ethereum chain adapter."""

    def test_adapter_properties(self):
        adapter = EthereumAdapter()
        assert adapter.name == "Ethereum Adapter"
        assert adapter.chain_id == ChainId.ETHEREUM
        assert adapter.confirmations_required == 12

    def test_connect_without_url(self):
        adapter = EthereumAdapter()
        assert adapter.connect() is False
        assert adapter.is_connected is False

    def test_connect_with_url(self):
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")
        with patch.object(adapter, '_json_rpc_call', return_value="Geth/v1.0"):
            assert adapter.connect() is True
            assert adapter.is_connected is True

    def test_disconnect(self):
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")
        with patch.object(adapter, '_json_rpc_call', return_value="Geth/v1.0"):
            adapter.connect()
        adapter.disconnect()
        assert adapter.is_connected is False

    def test_get_latest_block(self):
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")
        with patch.object(adapter, '_json_rpc_call', side_effect=[
            "Geth/v1.0",  # connect
            {  # eth_getBlockByNumber
                'number': '0x1234',
                'hash': '0x' + 'ab' * 32,
                'timestamp': '0x60000000',
            },
        ]):
            adapter.connect()
            block = adapter.get_latest_block()
        assert block.chain_id == ChainId.ETHEREUM
        assert block.block_height > 0
        assert len(block.block_hash.replace('0x', '')) == 64  # 32 bytes hex

    def test_get_block_by_height(self):
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")
        with patch.object(adapter, '_json_rpc_call', side_effect=[
            "Geth/v1.0",  # connect
            {  # eth_getBlockByNumber
                'number': '0x112A880',
                'hash': '0x' + 'cc' * 32,
                'timestamp': '0x60000000',
            },
        ]):
            adapter.connect()
            block = adapter.get_block_by_height(18000000)
        assert block is not None
        assert block.block_height == 18000000

    def test_get_transaction(self):
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")
        with patch.object(adapter, '_json_rpc_call', side_effect=[
            "Geth/v1.0",  # connect
            {  # eth_getTransactionByHash
                'hash': '0xabcdef',
                'blockNumber': '0x100',
                'from': '0x1111',
                'to': '0x2222',
                'value': '0xde0b6b3a7640000',
            },
        ]):
            adapter.connect()
            tx = adapter.get_transaction("0xabcdef")
        assert tx is not None
        assert tx["hash"] == "0xabcdef"

    def test_verify_valid_proof(self):
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")
        with patch.object(adapter, '_json_rpc_call', side_effect=[
            "Geth/v1.0",  # connect
            {  # eth_getTransactionReceipt
                'blockHash': '0x' + 'bb' * 32,
                'blockNumber': '0x112A880',
                'status': '0x1',
            },
        ]):
            adapter.connect()
            proof = InclusionProof(
                chain_id=ChainId.ETHEREUM,
                tx_hash="0x" + "aa" * 32,
                block_hash="0x" + "bb" * 32,
                block_height=18000000,
                proof_data="cc" * 32,
                root_hash="dd" * 32,
            )
            assert adapter.verify_inclusion_proof(proof) is True

    def test_verify_wrong_chain_proof(self):
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")
        with patch.object(adapter, '_json_rpc_call', return_value="Geth/v1.0"):
            adapter.connect()
        proof = InclusionProof(
            chain_id=ChainId.BITCOIN,
            tx_hash="0x" + "aa" * 32,
            block_hash="0x" + "bb" * 32,
            block_height=800000,
            proof_data="cc" * 32,
            root_hash="dd" * 32,
        )
        assert adapter.verify_inclusion_proof(proof) is False

    def test_verify_empty_proof(self):
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")
        with patch.object(adapter, '_json_rpc_call', return_value="Geth/v1.0"):
            adapter.connect()
        proof = InclusionProof(
            chain_id=ChainId.ETHEREUM,
            tx_hash="",
            block_hash="",
            block_height=0,
            proof_data="",
            root_hash="",
        )
        assert adapter.verify_inclusion_proof(proof) is False

    def test_generate_attestation_not_connected(self):
        adapter = EthereumAdapter()
        att = adapter.generate_attestation("0xValidator")
        assert att is None

    def test_generate_attestation(self):
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")
        with patch.object(adapter, '_json_rpc_call', side_effect=[
            "Geth/v1.0",  # connect
            {  # eth_getBlockByNumber (called by get_latest_block inside generate_attestation)
                'number': '0x1234',
                'hash': '0x' + 'ab' * 32,
                'timestamp': '0x60000000',
            },
        ]):
            adapter.connect()
            att = adapter.generate_attestation("0xValidator")
        assert att is not None
        assert att.chain_id == ChainId.ETHEREUM
        assert att.validator_address == "0xValidator"
        assert att.block_height > 0

    def test_detect_lock_events_empty(self):
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")
        with patch.object(adapter, '_json_rpc_call', side_effect=[
            "Geth/v1.0",  # connect
            [],  # eth_getLogs
        ]):
            adapter.connect()
            events = adapter.detect_lock_events(0, 100)
        assert events == []


class TestBitcoinAdapter:
    """Step 7.1 — Bitcoin chain adapter."""

    def test_adapter_properties(self):
        adapter = BitcoinAdapter()
        assert adapter.name == "Bitcoin Adapter"
        assert adapter.chain_id == ChainId.BITCOIN
        assert adapter.confirmations_required == 6

    def test_get_latest_block(self):
        adapter = BitcoinAdapter(rpc_url="http://localhost:18443")
        with patch.object(adapter, '_json_rpc_call', side_effect=[
            "Bitcoin Core",  # connect
            {'blocks': 800123, 'bestblockhash': 'ab' * 32},  # getblockchaininfo
            {'height': 800123, 'hash': 'ab' * 32, 'time': 1700000000},  # getblockheader
        ]):
            adapter.connect()
            block = adapter.get_latest_block()
        assert block.chain_id == ChainId.BITCOIN
        assert block.block_height > 0

    def test_verify_valid_proof(self):
        adapter = BitcoinAdapter(rpc_url="http://localhost:18443")
        tx_hash = "0x" + "aa" * 32
        with patch.object(adapter, '_json_rpc_call', side_effect=[
            "Bitcoin Core",  # connect
            [tx_hash],  # verifytxoutproof returns a list of txids
        ]):
            adapter.connect()
            proof = InclusionProof(
                chain_id=ChainId.BITCOIN,
                tx_hash=tx_hash,
                block_hash="0x" + "bb" * 32,
                block_height=800000,
                proof_data="cc" * 32,
                root_hash="dd" * 32,
            )
            assert adapter.verify_inclusion_proof(proof) is True

    def test_verify_wrong_chain(self):
        adapter = BitcoinAdapter(rpc_url="http://localhost:18443")
        with patch.object(adapter, '_json_rpc_call', return_value="Bitcoin Core"):
            adapter.connect()
        proof = InclusionProof(
            chain_id=ChainId.ETHEREUM,
            tx_hash="tx",
            block_hash="bh",
            block_height=1,
            proof_data="proof",
            root_hash="root",
        )
        assert adapter.verify_inclusion_proof(proof) is False


class TestSolanaAdapter:
    """Step 7.1 — Solana chain adapter."""

    def test_adapter_properties(self):
        adapter = SolanaAdapter()
        assert adapter.name == "Solana Adapter"
        assert adapter.chain_id == ChainId.SOLANA
        assert adapter.confirmations_required == 32

    def test_get_latest_block(self):
        adapter = SolanaAdapter(rpc_url="http://localhost:8899")
        with patch.object(adapter, '_json_rpc_call', side_effect=[
            "Solana/v1.0",  # connect
            200000123,  # getSlot
            {  # getBlock
                'blockhash': 'dd' * 32,
                'blockTime': 1700000000,
                'blockHeight': 200000123,
            },
        ]):
            adapter.connect()
            block = adapter.get_latest_block()
        assert block.chain_id == ChainId.SOLANA
        assert block.block_height > 0

    def test_verify_valid_proof(self):
        adapter = SolanaAdapter(rpc_url="http://localhost:8899")
        with patch.object(adapter, '_json_rpc_call', side_effect=[
            "Solana/v1.0",  # connect
            {  # getTransaction
                'slot': 200000000,
                'transaction': {'signatures': ['aa' * 32]},
                'meta': {'err': None},
            },
        ]):
            adapter.connect()
            proof = InclusionProof(
                chain_id=ChainId.SOLANA,
                tx_hash="0x" + "aa" * 32,
                block_hash="0x" + "bb" * 32,
                block_height=200000000,
                proof_data="cc" * 32,
                root_hash="dd" * 32,
            )
            assert adapter.verify_inclusion_proof(proof) is True


class TestInclusionProof:
    """Step 7.2 — Inclusion proof structure."""

    def test_create_proof(self):
        proof = InclusionProof(
            chain_id=ChainId.ETHEREUM,
            tx_hash="0xdeadbeef",
            block_hash="0xblockh",
            block_height=100,
            proof_data="aabb",
            root_hash="ccdd",
        )
        assert proof.chain_id == ChainId.ETHEREUM

    def test_proof_serialization(self):
        proof = InclusionProof(
            chain_id=ChainId.BITCOIN,
            tx_hash="0xtx",
            block_hash="0xbh",
            block_height=50,
            proof_data="1122",
            root_hash="3344",
        )
        d = proof.to_dict()
        assert d["chain_id"] == 2
        assert d["block_height"] == 50


# ══════════════════════════════════════════════════════════════════════
#  SECTION 7: ORACLE CONSENSUS
# ══════════════════════════════════════════════════════════════════════

class TestOracleConsensus:
    """Step 7.3 — Oracle attestation consensus (2/3+1)."""

    def _make_attestation(self, validator_id, block_height=18000000, block_hash="aa" * 32):
        return OracleAttestation(
            validator_address=f"0xValidator{validator_id}",
            chain_id=ChainId.ETHEREUM,
            block_height=block_height,
            block_hash=block_hash,
            state_root="bb" * 32,
            timestamp=int(time.time()),
        )

    def test_consensus_threshold(self):
        """2/3+1 of 9 validators = 7"""
        oc = OracleConsensus(total_validators=9)
        assert oc.threshold == 7

    def test_consensus_threshold_small(self):
        """2/3+1 of 3 = 3"""
        oc = OracleConsensus(total_validators=3)
        assert oc.threshold == 3

    def test_consensus_threshold_single(self):
        """2/3+1 of 1 = 1"""
        oc = OracleConsensus(total_validators=1)
        assert oc.threshold == 1

    def test_invalid_validator_count(self):
        with pytest.raises(ValueError):
            OracleConsensus(total_validators=0)

    def test_submit_attestations_reach_consensus(self):
        oc = OracleConsensus(total_validators=3)
        # Need 3 attestations (2/3+1 of 3 = 3)
        assert oc.submit_attestation(self._make_attestation(1)) is False
        assert oc.submit_attestation(self._make_attestation(2)) is False
        assert oc.submit_attestation(self._make_attestation(3)) is True

    def test_duplicate_validator_rejected(self):
        oc = OracleConsensus(total_validators=3)
        oc.submit_attestation(self._make_attestation(1))
        assert oc.submit_attestation(self._make_attestation(1)) is False
        assert oc.get_attestation_count(ChainId.ETHEREUM) == 1

    def test_split_votes_no_consensus(self):
        oc = OracleConsensus(total_validators=3)
        oc.submit_attestation(self._make_attestation(1, block_height=100, block_hash="aa" * 32))
        oc.submit_attestation(self._make_attestation(2, block_height=101, block_hash="bb" * 32))
        oc.submit_attestation(self._make_attestation(3, block_height=102, block_hash="cc" * 32))
        assert oc.get_finalized_height(ChainId.ETHEREUM) is None

    def test_finalized_height(self):
        oc = OracleConsensus(total_validators=3)
        oc.submit_attestation(self._make_attestation(1))
        oc.submit_attestation(self._make_attestation(2))
        oc.submit_attestation(self._make_attestation(3))
        rec = oc.get_finalized_height(ChainId.ETHEREUM)
        assert rec is not None
        assert rec.block_height == 18000000
        assert rec.attested is True

    def test_reset_epoch(self):
        oc = OracleConsensus(total_validators=3)
        oc.submit_attestation(self._make_attestation(1))
        oc.reset_epoch(ChainId.ETHEREUM)
        assert oc.get_attestation_count(ChainId.ETHEREUM) == 0


# ══════════════════════════════════════════════════════════════════════
#  SECTION 8: BLOCK HEIGHT TRACKER
# ══════════════════════════════════════════════════════════════════════

class TestBlockHeightTracker:
    """Step 7.6 — Block height recording and tracking."""

    def test_update_height(self):
        tracker = BlockHeightTracker()
        rec = BlockHeightRecord(
            chain_id=ChainId.ETHEREUM,
            block_height=18000000,
            block_hash="aa" * 32,
            timestamp=int(time.time()),
            attested=True,
        )
        assert tracker.update_height(rec) is True
        assert tracker.get_height(ChainId.ETHEREUM) == 18000000

    def test_monotonic_increase(self):
        tracker = BlockHeightTracker()
        r1 = BlockHeightRecord(ChainId.ETHEREUM, 100, "h1", int(time.time()))
        r2 = BlockHeightRecord(ChainId.ETHEREUM, 101, "h2", int(time.time()))
        r3 = BlockHeightRecord(ChainId.ETHEREUM, 100, "h3", int(time.time()))
        assert tracker.update_height(r1) is True
        assert tracker.update_height(r2) is True
        assert tracker.update_height(r3) is False  # Stale!
        assert tracker.get_height(ChainId.ETHEREUM) == 101

    def test_multiple_chains(self):
        tracker = BlockHeightTracker()
        eth = BlockHeightRecord(ChainId.ETHEREUM, 100, "e", int(time.time()))
        btc = BlockHeightRecord(ChainId.BITCOIN, 800000, "b", int(time.time()))
        tracker.update_height(eth)
        tracker.update_height(btc)
        heights = tracker.get_all_heights()
        assert heights[ChainId.ETHEREUM] == 100
        assert heights[ChainId.BITCOIN] == 800000

    def test_is_tracking(self):
        tracker = BlockHeightTracker()
        assert tracker.is_tracking(ChainId.ETHEREUM) is False
        tracker.update_height(BlockHeightRecord(ChainId.ETHEREUM, 1, "h", 0))
        assert tracker.is_tracking(ChainId.ETHEREUM) is True

    def test_history(self):
        tracker = BlockHeightTracker()
        for i in range(5):
            tracker.update_height(
                BlockHeightRecord(ChainId.ETHEREUM, i + 1, f"h{i}", int(time.time()))
            )
        history = tracker.get_history(ChainId.ETHEREUM)
        assert len(history) == 5
        assert history[0].block_height == 1
        assert history[4].block_height == 5

    def test_serialization(self):
        tracker = BlockHeightTracker()
        tracker.update_height(BlockHeightRecord(ChainId.ETHEREUM, 100, "h", 1000))
        d = tracker.to_dict()
        assert str(int(ChainId.ETHEREUM)) in d


# ══════════════════════════════════════════════════════════════════════
#  SECTION 9: DOOMSDAY PROTOCOL
# ══════════════════════════════════════════════════════════════════════

class TestDoomsdayProtocol:
    """Step 8.3 — Doomsday Protocol."""

    def test_initial_state(self):
        dp = DoomsdayProtocol()
        assert dp.is_active is False
        assert dp.can_shield() is True
        assert dp.can_unshield() is True

    def test_canary_address(self):
        dp = DoomsdayProtocol()
        assert dp.canary_address == DOOMSDAY_CANARY_ADDRESS

    def test_trigger_doomsday(self):
        dp = DoomsdayProtocol()
        result = dp.trigger_doomsday("canary_drained_proof_xyz")
        assert result is True
        assert dp.is_active is True
        assert dp.can_shield() is False
        assert dp.can_unshield() is True  # Always allowed

    def test_trigger_without_proof_rejected(self):
        dp = DoomsdayProtocol()
        assert dp.trigger_doomsday("") is False
        assert dp.is_active is False

    def test_double_trigger_rejected(self):
        dp = DoomsdayProtocol()
        dp.trigger_doomsday("proof1")
        assert dp.trigger_doomsday("proof2") is False

    def test_check_canary_safe(self):
        dp = DoomsdayProtocol()
        assert dp.check_canary(Decimal("1000000")) is True
        assert dp.is_active is False

    def test_check_canary_drained(self):
        dp = DoomsdayProtocol()
        assert dp.check_canary(Decimal("0")) is False
        assert dp.is_active is True

    def test_status_dict(self):
        dp = DoomsdayProtocol()
        status = dp.get_status()
        assert status["doomsday_active"] is False
        assert status["shield_allowed"] is True
        assert status["unshield_allowed"] is True

    def test_post_doomsday_behavior(self):
        """Whitepaper §8.5: shields BLOCKED, unshields ALLOWED, QRDX normal."""
        dp = DoomsdayProtocol()
        dp.trigger_doomsday("quantum_attack_proof")
        status = dp.get_status()
        assert status["doomsday_active"] is True
        assert status["shield_allowed"] is False
        assert status["unshield_allowed"] is True


# ══════════════════════════════════════════════════════════════════════
#  SECTION 10: BRIDGE MINTER
# ══════════════════════════════════════════════════════════════════════

class TestBridgeMinter:
    """Step 8.1/8.2 — Token minting and burning for bridge."""

    def test_mint_tokens(self):
        minter = BridgeMinter()
        ok = minter.mint("ETH", Decimal("1.5"), "0xRecipient", "rec_001")
        assert ok is True
        assert minter.get_outstanding("qETH") == Decimal("1.5")

    def test_mint_unknown_token(self):
        minter = BridgeMinter()
        assert minter.mint("UNKNOWN", Decimal("1"), "addr", "rec") is False

    def test_mint_zero_rejected(self):
        minter = BridgeMinter()
        assert minter.mint("ETH", Decimal("0"), "addr", "rec") is False

    def test_burn_tokens(self):
        minter = BridgeMinter()
        minter.mint("ETH", Decimal("10"), "0xAddr", "rec_001")
        ok = minter.burn("ETH", Decimal("3"), "0xAddr", "rec_002")
        assert ok is True
        assert minter.get_outstanding("qETH") == Decimal("7")

    def test_burn_more_than_outstanding(self):
        minter = BridgeMinter()
        minter.mint("ETH", Decimal("1"), "addr", "rec1")
        assert minter.burn("ETH", Decimal("2"), "addr", "rec2") is False

    def test_register_custom_token(self):
        minter = BridgeMinter()
        cfg = BridgeTokenConfig(
            symbol="ATOM",
            shielded_symbol="qATOM",
            source_chain_id=ChainId.COSMOS,
            decimals=6,
        )
        minter.register_token(cfg)
        assert minter.get_token_config("ATOM") is not None
        ok = minter.mint("ATOM", Decimal("100"), "addr", "rec")
        assert ok is True

    def test_stats(self):
        minter = BridgeMinter()
        minter.mint("ETH", Decimal("5"), "addr", "r1")
        minter.burn("ETH", Decimal("2"), "addr", "r2")
        stats = minter.get_stats()
        assert "qETH" in stats["outstanding"]
        assert Decimal(stats["outstanding"]["qETH"]) == Decimal("3")


# ══════════════════════════════════════════════════════════════════════
#  SECTION 11: SHIELDING MANAGER — SHIELD FLOW
# ══════════════════════════════════════════════════════════════════════

class TestShieldFlow:
    """Step 8.1 — Shield: Classical → Quantum-Resistant."""

    def _make_manager(self):
        return ShieldingManager()

    def test_initiate_shield(self):
        mgr = self._make_manager()
        record = mgr.initiate_shield(
            source_chain=ChainId.ETHEREUM,
            source_tx_hash="0x" + "aa" * 32,
            amount=Decimal("1.5"),
            source_address="0xEthSender",
            qrdx_address="0xPQRecipient",
            token_symbol="ETH",
            block_height=18000000,
            block_hash="bb" * 32,
        )
        assert record is not None
        assert record.operation == BridgeOperationType.SHIELD
        assert record.status == BridgeStatus.PENDING

    def test_shield_below_minimum_rejected(self):
        mgr = self._make_manager()
        record = mgr.initiate_shield(
            source_chain=ChainId.ETHEREUM,
            source_tx_hash="0xtx",
            amount=Decimal("0.001"),  # Below 0.01 ETH minimum
            source_address="addr",
            qrdx_address="pq_addr",
        )
        assert record is None

    def test_shield_unknown_token_rejected(self):
        mgr = self._make_manager()
        record = mgr.initiate_shield(
            source_chain=ChainId.ETHEREUM,
            source_tx_hash="0xtx",
            amount=Decimal("1"),
            source_address="addr",
            qrdx_address="pq_addr",
            token_symbol="FAKE",
        )
        assert record is None

    def test_shield_blocked_during_doomsday(self):
        mgr = self._make_manager()
        mgr.doomsday.trigger_doomsday("quantum_proof")
        record = mgr.initiate_shield(
            source_chain=ChainId.ETHEREUM,
            source_tx_hash="0xtx",
            amount=Decimal("1"),
            source_address="addr",
            qrdx_address="pq_addr",
        )
        assert record is None

    def test_full_shield_lifecycle(self):
        """Lock → Confirm → Attest → Execute (mint)."""
        mgr = self._make_manager()

        # 1. Initiate
        record = mgr.initiate_shield(
            source_chain=ChainId.ETHEREUM,
            source_tx_hash="0x" + "aa" * 32,
            amount=Decimal("10"),
            source_address="0xEthSender",
            qrdx_address="0xPQRecipient",
            token_symbol="ETH",
        )
        assert record is not None
        rid = record.record_id

        # 2. Add confirmations until threshold
        for _ in range(12):
            mgr.confirm_shield(rid)
        assert mgr.get_record(rid).is_confirmed is True

        # 3. Attest with valid proof
        proof = ValidatorProof(
            message_hash=rid,
            signatures=["s1", "s2", "s3"],
            signers=["v1", "v2", "v3"],
            nonce=1,
            threshold=2,
        )
        assert mgr.attest_shield(rid, proof) is True
        assert mgr.get_record(rid).status == BridgeStatus.ATTESTED

        # 4. Execute (mint)
        assert mgr.execute_shield(rid) is True
        assert mgr.get_record(rid).status == BridgeStatus.EXECUTED

        # Verify minted amount (minus 0.1% fee)
        expected = Decimal("10") - (Decimal("10") * BRIDGE_FEE_BPS / Decimal("10000"))
        assert mgr.minter.get_outstanding("qETH") == expected

    def test_cannot_execute_unattested(self):
        mgr = self._make_manager()
        record = mgr.initiate_shield(
            source_chain=ChainId.ETHEREUM,
            source_tx_hash="0xtx",
            amount=Decimal("1"),
            source_address="addr",
            qrdx_address="pq",
        )
        assert mgr.execute_shield(record.record_id) is False


# ══════════════════════════════════════════════════════════════════════
#  SECTION 12: SHIELDING MANAGER — UNSHIELD FLOW
# ══════════════════════════════════════════════════════════════════════

class TestUnshieldFlow:
    """Step 8.2 — Unshield: Quantum-Resistant → Classical."""

    def _setup_with_minted(self, amount=Decimal("10")):
        mgr = ShieldingManager()
        mgr.minter.mint("ETH", amount, "0xPQHolder", "bootstrap_mint")
        return mgr

    def test_initiate_unshield(self):
        mgr = self._setup_with_minted()
        record = mgr.initiate_unshield(
            dest_chain=ChainId.ETHEREUM,
            amount=Decimal("5"),
            qrdx_address="0xPQHolder",
            dest_address="0xEthDest",
            token_symbol="ETH",
        )
        assert record is not None
        assert record.operation == BridgeOperationType.UNSHIELD

    def test_unshield_more_than_outstanding(self):
        mgr = self._setup_with_minted(amount=Decimal("1"))
        record = mgr.initiate_unshield(
            dest_chain=ChainId.ETHEREUM,
            amount=Decimal("2"),
            qrdx_address="0xPQHolder",
            dest_address="0xEthDest",
        )
        assert record is None

    def test_unshield_allowed_during_doomsday(self):
        """Whitepaper §8.5: unshield ALWAYS allowed."""
        mgr = self._setup_with_minted()
        mgr.doomsday.trigger_doomsday("quantum_proof")
        record = mgr.initiate_unshield(
            dest_chain=ChainId.ETHEREUM,
            amount=Decimal("5"),
            qrdx_address="0xPQHolder",
            dest_address="0xEthDest",
        )
        assert record is not None

    def test_high_value_fraud_window(self):
        """Amounts >= $100K get 7-day fraud proof window."""
        mgr = ShieldingManager()
        # Use USDC which has max_amount of 10M
        mgr.minter.mint("USDC", Decimal("500000"), "holder", "init")
        record = mgr.initiate_unshield(
            dest_chain=ChainId.ETHEREUM,
            amount=Decimal("200000"),
            qrdx_address="holder",
            dest_address="0xDest",
            token_symbol="USDC",
        )
        assert record is not None
        assert record.status == BridgeStatus.CONFIRMING
        # Fraud window not yet expired
        assert mgr.check_fraud_window(record.record_id) is False

    def test_fraud_proof_submission(self):
        mgr = ShieldingManager()
        mgr.minter.mint("USDC", Decimal("500000"), "holder", "init")
        record = mgr.initiate_unshield(
            dest_chain=ChainId.ETHEREUM,
            amount=Decimal("200000"),
            qrdx_address="holder",
            dest_address="0xDest",
            token_symbol="USDC",
        )
        ok = mgr.submit_fraud_proof(record.record_id, "fraud_evidence_xyz")
        assert ok is True
        assert mgr.get_record(record.record_id).status == BridgeStatus.FRAUD

    def test_full_unshield_lifecycle(self):
        """Burn → Attest → Execute."""
        mgr = self._setup_with_minted(Decimal("10"))
        record = mgr.initiate_unshield(
            dest_chain=ChainId.ETHEREUM,
            amount=Decimal("5"),
            qrdx_address="0xPQHolder",
            dest_address="0xEthDest",
        )
        rid = record.record_id

        proof = ValidatorProof(
            message_hash=rid,
            signatures=["s1", "s2"],
            signers=["v1", "v2"],
            nonce=1,
            threshold=2,
        )
        assert mgr.attest_unshield(rid, proof) is True
        assert mgr.execute_unshield(rid) is True
        assert mgr.get_record(rid).status == BridgeStatus.EXECUTED


# ══════════════════════════════════════════════════════════════════════
#  SECTION 13: SHIELDING MANAGER — QUERIES
# ══════════════════════════════════════════════════════════════════════

class TestShieldingQueries:
    """Query and stats tests for ShieldingManager."""

    def test_get_records_by_address(self):
        mgr = ShieldingManager()
        mgr.initiate_shield(
            source_chain=ChainId.ETHEREUM,
            source_tx_hash="0xtx1",
            amount=Decimal("1"),
            source_address="eth1",
            qrdx_address="0xPQ1",
        )
        mgr.initiate_shield(
            source_chain=ChainId.ETHEREUM,
            source_tx_hash="0xtx2",
            amount=Decimal("2"),
            source_address="eth2",
            qrdx_address="0xPQ1",
        )
        records = mgr.get_records_by_address("0xPQ1")
        assert len(records) == 2

    def test_get_pending_records(self):
        mgr = ShieldingManager()
        mgr.initiate_shield(
            source_chain=ChainId.ETHEREUM,
            source_tx_hash="0xtx1",
            amount=Decimal("1"),
            source_address="eth1",
            qrdx_address="pq1",
        )
        pending = mgr.get_pending_records()
        assert len(pending) == 1

    def test_stats(self):
        mgr = ShieldingManager()
        stats = mgr.get_stats()
        assert "total_records" in stats
        assert "doomsday" in stats
        assert "minter" in stats


# ══════════════════════════════════════════════════════════════════════
#  SECTION 14: ORACLE PRECOMPILES (Step 4.5)
# ══════════════════════════════════════════════════════════════════════

class MockComputation:
    """Mock ComputationAPI for precompile testing."""

    def __init__(self, input_data: bytes):
        self.msg = MagicMock()
        self.msg.data = input_data
        self.output = b''
        self._gas_consumed = 0

    def consume_gas(self, amount: int, reason: str = ""):
        self._gas_consumed += amount


# Dynamic import to handle py-evm path
import importlib
import importlib.util

_precompiles_path = os.path.join(
    ROOT, "py-evm", "eth", "vm", "forks", "qrdx", "precompiles.py"
)


def _load_precompiles():
    """Load precompiles module from py-evm path."""
    spec = importlib.util.spec_from_file_location("qrdx_precompiles", _precompiles_path)
    mod = importlib.util.module_from_spec(spec)
    # Save any existing modules so we can restore them
    _saved = {}
    _to_mock = ['eth', 'eth.abc', 'eth_typing', 'eth.crypto']
    for name in _to_mock:
        _saved[name] = sys.modules.get(name, None)

    # We need to mock the imports that precompiles.py requires
    sys.modules['eth'] = MagicMock()
    sys.modules['eth.abc'] = MagicMock()
    sys.modules['eth_typing'] = MagicMock()
    sys.modules['eth.crypto'] = MagicMock()

    # Mock Address so it returns bytes
    sys.modules['eth_typing'].Address = lambda x: x

    spec.loader.exec_module(mod)

    # Restore original modules to avoid contaminating other test files
    for name in _to_mock:
        if _saved[name] is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = _saved[name]

    return mod


_precompiles_mod = _load_precompiles()

# Extract functions and constants we need
get_chain_state_precompile = _precompiles_mod.get_chain_state_precompile
verify_external_proof_precompile = _precompiles_mod.verify_external_proof_precompile
submit_cross_chain_tx_precompile = _precompiles_mod.submit_cross_chain_tx_precompile
oracle_set_chain_state = _precompiles_mod.oracle_set_chain_state
GAS_ORACLE_GET_CHAIN_STATE = _precompiles_mod.GAS_ORACLE_GET_CHAIN_STATE
GAS_ORACLE_VERIFY_PROOF = _precompiles_mod.GAS_ORACLE_VERIFY_PROOF
GAS_ORACLE_SUBMIT_CROSS_CHAIN_TX = _precompiles_mod.GAS_ORACLE_SUBMIT_CROSS_CHAIN_TX
QRDX_PRECOMPILES = _precompiles_mod.QRDX_PRECOMPILES


class TestGetChainStatePrecompile:
    """Step 4.5 — Oracle precompile 0x0200: getChainState."""

    def test_empty_input_returns_zeros(self):
        comp = MockComputation(b'')
        get_chain_state_precompile(comp)
        assert comp.output == b'\x00' * 80
        assert comp._gas_consumed == GAS_ORACLE_GET_CHAIN_STATE

    def test_unknown_chain_returns_zeros(self):
        chain_id = (99).to_bytes(4, 'big')
        comp = MockComputation(chain_id)
        get_chain_state_precompile(comp)
        assert comp.output == b'\x00' * 80

    def test_known_chain_returns_state(self):
        # Inject state
        oracle_set_chain_state(
            chain_id=1,  # Ethereum
            block_height=18000000,
            block_hash=b'\xaa' * 32,
            state_root=b'\xbb' * 32,
            timestamp=1700000000,
        )
        chain_id = (1).to_bytes(4, 'big')
        comp = MockComputation(chain_id)
        get_chain_state_precompile(comp)

        assert len(comp.output) == 80
        # Parse output
        height = int.from_bytes(comp.output[0:8], 'big')
        block_hash = comp.output[8:40]
        state_root = comp.output[40:72]
        timestamp = int.from_bytes(comp.output[72:80], 'big')

        assert height == 18000000
        assert block_hash == b'\xaa' * 32
        assert state_root == b'\xbb' * 32
        assert timestamp == 1700000000


class TestVerifyExternalProofPrecompile:
    """Step 4.5 — Oracle precompile 0x0201: verifyExternalProof."""

    def test_short_input_invalid(self):
        comp = MockComputation(b'\x00' * 10)
        verify_external_proof_precompile(comp)
        assert comp.output == b'\x00'
        assert comp._gas_consumed == GAS_ORACLE_VERIFY_PROOF

    def test_unknown_chain_invalid(self):
        # chain_id=99, plus 32 bytes proof
        data = (99).to_bytes(4, 'big') + b'\xaa' * 32
        comp = MockComputation(data)
        verify_external_proof_precompile(comp)
        assert comp.output == b'\x00'

    def test_all_zero_proof_invalid(self):
        data = (1).to_bytes(4, 'big') + b'\x00' * 32
        comp = MockComputation(data)
        verify_external_proof_precompile(comp)
        assert comp.output == b'\x00'

    def test_valid_proof_accepted(self):
        data = (1).to_bytes(4, 'big') + b'\xaa' * 32
        comp = MockComputation(data)
        verify_external_proof_precompile(comp)
        assert comp.output == b'\x01'

    def test_bitcoin_proof_accepted(self):
        data = (2).to_bytes(4, 'big') + b'\xbb' * 64
        comp = MockComputation(data)
        verify_external_proof_precompile(comp)
        assert comp.output == b'\x01'

    def test_solana_proof_accepted(self):
        data = (3).to_bytes(4, 'big') + b'\xcc' * 32
        comp = MockComputation(data)
        verify_external_proof_precompile(comp)
        assert comp.output == b'\x01'


class TestSubmitCrossChainTxPrecompile:
    """Step 4.5 — Oracle precompile 0x0202: submitCrossChainTx."""

    def test_empty_input_returns_zeros(self):
        comp = MockComputation(b'')
        submit_cross_chain_tx_precompile(comp)
        assert comp.output == b'\x00' * 32
        assert comp._gas_consumed == GAS_ORACLE_SUBMIT_CROSS_CHAIN_TX

    def test_qrdx_self_reference_rejected(self):
        data = (0).to_bytes(4, 'big') + b'\xaa' * 32
        comp = MockComputation(data)
        submit_cross_chain_tx_precompile(comp)
        assert comp.output == b'\x00' * 32

    def test_unknown_chain_rejected(self):
        data = (99).to_bytes(4, 'big') + b'\xaa' * 32
        comp = MockComputation(data)
        submit_cross_chain_tx_precompile(comp)
        assert comp.output == b'\x00' * 32

    def test_valid_submission_returns_hash(self):
        input_data = (1).to_bytes(4, 'big') + b'\xaa' * 32
        comp = MockComputation(input_data)
        submit_cross_chain_tx_precompile(comp)
        assert len(comp.output) == 32
        assert comp.output != b'\x00' * 32
        # Verify it's SHA-256 of input
        expected = hashlib.sha256(input_data).digest()
        assert comp.output == expected

    def test_bitcoin_submission(self):
        input_data = (2).to_bytes(4, 'big') + b'\xbb' * 64
        comp = MockComputation(input_data)
        submit_cross_chain_tx_precompile(comp)
        assert len(comp.output) == 32
        assert comp.output != b'\x00' * 32

    def test_gas_consumed(self):
        input_data = (1).to_bytes(4, 'big') + b'\xaa' * 32
        comp = MockComputation(input_data)
        submit_cross_chain_tx_precompile(comp)
        assert comp._gas_consumed == GAS_ORACLE_SUBMIT_CROSS_CHAIN_TX


# ══════════════════════════════════════════════════════════════════════
#  SECTION 15: PRECOMPILE REGISTRY
# ══════════════════════════════════════════════════════════════════════

class TestPrecompileRegistry:
    """Step 4.5 — Verify all 12 precompiles are registered."""

    def test_total_precompile_count(self):
        assert len(QRDX_PRECOMPILES) == 12

    def test_oracle_precompiles_registered(self):
        # Oracle addresses should be in the registry
        oracle_addrs = [
            _precompiles_mod.ORACLE_GET_CHAIN_STATE_ADDRESS,
            _precompiles_mod.ORACLE_VERIFY_PROOF_ADDRESS,
            _precompiles_mod.ORACLE_SUBMIT_CROSS_CHAIN_TX_ADDRESS,
        ]
        for addr in oracle_addrs:
            assert addr in QRDX_PRECOMPILES

    def test_original_precompiles_still_registered(self):
        assert _precompiles_mod.DILITHIUM_VERIFY_ADDRESS in QRDX_PRECOMPILES
        assert _precompiles_mod.KYBER_ENCAPSULATE_ADDRESS in QRDX_PRECOMPILES
        assert _precompiles_mod.KYBER_DECAPSULATE_ADDRESS in QRDX_PRECOMPILES
        assert _precompiles_mod.BLAKE3_HASH_ADDRESS in QRDX_PRECOMPILES


# ══════════════════════════════════════════════════════════════════════
#  SECTION 16: BRIDGE CONSTANTS
# ══════════════════════════════════════════════════════════════════════

class TestBridgeConstants:
    """Verify bridge/oracle constants in qrdx.constants."""

    def test_slashing_bridge_fraud(self):
        from qrdx.constants import SLASHING_BRIDGE_FRAUD
        assert SLASHING_BRIDGE_FRAUD == Decimal("1.00")

    def test_spending_scope_bridge(self):
        from qrdx.constants import SPENDING_SCOPE_BRIDGE
        assert SPENDING_SCOPE_BRIDGE == 8

    def test_chain_ids(self):
        from qrdx.constants import (
            BRIDGE_CHAIN_QRDX,
            BRIDGE_CHAIN_ETHEREUM,
            BRIDGE_CHAIN_BITCOIN,
            BRIDGE_CHAIN_SOLANA,
            BRIDGE_CHAIN_COSMOS,
        )
        assert BRIDGE_CHAIN_QRDX == 0
        assert BRIDGE_CHAIN_ETHEREUM == 1
        assert BRIDGE_CHAIN_BITCOIN == 2
        assert BRIDGE_CHAIN_SOLANA == 3
        assert BRIDGE_CHAIN_COSMOS == 4

    def test_confirmation_counts(self):
        from qrdx.constants import (
            BRIDGE_CONFIRMATIONS_ETH,
            BRIDGE_CONFIRMATIONS_BTC,
            BRIDGE_CONFIRMATIONS_SOL,
        )
        assert BRIDGE_CONFIRMATIONS_ETH == 12
        assert BRIDGE_CONFIRMATIONS_BTC == 6
        assert BRIDGE_CONFIRMATIONS_SOL == 32

    def test_bridge_fee(self):
        from qrdx.constants import BRIDGE_FEE_BPS
        assert BRIDGE_FEE_BPS == 10

    def test_doomsday_constants(self):
        from qrdx.constants import (
            DOOMSDAY_CANARY_ADDRESS as CONST_CANARY,
            DOOMSDAY_CANARY_BOUNTY,
        )
        assert CONST_CANARY == "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1"
        assert DOOMSDAY_CANARY_BOUNTY == Decimal("1000000")

    def test_fraud_proof_window(self):
        from qrdx.constants import FRAUD_PROOF_WINDOW_SECONDS
        assert FRAUD_PROOF_WINDOW_SECONDS == 604800  # 7 days

    def test_oracle_precompile_addresses(self):
        from qrdx.constants import (
            ORACLE_PRECOMPILE_GET_CHAIN_STATE,
            ORACLE_PRECOMPILE_VERIFY_PROOF,
            ORACLE_PRECOMPILE_SUBMIT_CROSS_CHAIN_TX,
        )
        assert ORACLE_PRECOMPILE_GET_CHAIN_STATE == 0x0200
        assert ORACLE_PRECOMPILE_VERIFY_PROOF == 0x0201
        assert ORACLE_PRECOMPILE_SUBMIT_CROSS_CHAIN_TX == 0x0202

    def test_oracle_gas_costs(self):
        from qrdx.constants import (
            ORACLE_GAS_GET_CHAIN_STATE,
            ORACLE_GAS_VERIFY_PROOF,
            ORACLE_GAS_SUBMIT_CROSS_CHAIN_TX,
        )
        assert ORACLE_GAS_GET_CHAIN_STATE == 100_000
        assert ORACLE_GAS_VERIFY_PROOF == 200_000
        assert ORACLE_GAS_SUBMIT_CROSS_CHAIN_TX == 500_000


# ══════════════════════════════════════════════════════════════════════
#  SECTION 17: INTEGRATION — END-TO-END BRIDGE FLOWS
# ══════════════════════════════════════════════════════════════════════

class TestEndToEndBridge:
    """Integration tests combining adapters, oracle, and shielding."""

    def test_eth_adapter_to_oracle_consensus(self):
        """Adapter generates attestation → OracleConsensus reaches quorum."""
        adapter = EthereumAdapter(rpc_url="http://localhost:8545")

        # Mock RPC: connect + 3 × get_latest_block (one per validator attestation)
        rpc_responses = [
            "Geth/v1.0",  # connect
        ]
        for _ in range(3):
            rpc_responses.append({  # eth_getBlockByNumber
                'number': '0x112A880',
                'hash': '0x' + 'ab' * 32,
                'timestamp': '0x60000000',
                'stateRoot': '0x' + 'cd' * 32,
            })

        with patch.object(adapter, '_json_rpc_call', side_effect=rpc_responses):
            adapter.connect()

            oc = OracleConsensus(total_validators=3)
            # 3 validators all use the adapter
            for i in range(3):
                att = adapter.generate_attestation(f"0xValidator{i}")
                assert att is not None
                oc.submit_attestation(att)

        rec = oc.get_finalized_height(ChainId.ETHEREUM)
        assert rec is not None
        assert rec.attested is True

    def test_oracle_to_height_tracker(self):
        """Oracle consensus → BlockHeightTracker update."""
        oc = OracleConsensus(total_validators=1)
        att = OracleAttestation(
            validator_address="v1",
            chain_id=ChainId.ETHEREUM,
            block_height=18000000,
            block_hash="aa" * 32,
            state_root="bb" * 32,
            timestamp=int(time.time()),
        )
        oc.submit_attestation(att)
        finalized = oc.get_finalized_height(ChainId.ETHEREUM)

        tracker = BlockHeightTracker()
        tracker.update_height(finalized)
        assert tracker.get_height(ChainId.ETHEREUM) == 18000000

    def test_full_shield_with_oracle(self):
        """Complete: adapter → oracle → shield → mint."""
        mgr = ShieldingManager()

        # 1. Shield initiated from ETH
        record = mgr.initiate_shield(
            source_chain=ChainId.ETHEREUM,
            source_tx_hash="0x" + "ff" * 32,
            amount=Decimal("2.0"),
            source_address="0xEthUser",
            qrdx_address="0xPQUser",
            token_symbol="ETH",
        )
        rid = record.record_id

        # 2. 12 confirmations
        for _ in range(12):
            mgr.confirm_shield(rid)

        # 3. Oracle attestation
        proof = ValidatorProof(
            message_hash=rid,
            signatures=["sig"] * 3,
            signers=["v1", "v2", "v3"],
            nonce=1,
            threshold=2,
        )
        mgr.attest_shield(rid, proof)

        # 4. Execute
        mgr.execute_shield(rid)
        assert mgr.get_record(rid).status == BridgeStatus.EXECUTED
        assert mgr.minter.get_outstanding("qETH") > 0

    def test_full_unshield_with_fraud_window_bypass(self):
        """Small unshield (no fraud window) completes immediately."""
        mgr = ShieldingManager()
        mgr.minter.mint("ETH", Decimal("10"), "holder", "init")

        record = mgr.initiate_unshield(
            dest_chain=ChainId.ETHEREUM,
            amount=Decimal("5"),
            qrdx_address="holder",
            dest_address="0xEthDest",
        )
        assert record is not None
        # No fraud window for < $100K
        assert mgr.check_fraud_window(record.record_id) is True

        proof = ValidatorProof(
            message_hash=record.record_id,
            signatures=["s1", "s2"],
            signers=["v1", "v2"],
            nonce=1,
            threshold=2,
        )
        mgr.attest_unshield(record.record_id, proof)
        mgr.execute_unshield(record.record_id)
        assert mgr.get_record(record.record_id).status == BridgeStatus.EXECUTED

    def test_multi_chain_tracking(self):
        """Track multiple chains simultaneously."""
        tracker = BlockHeightTracker()

        eth_adapter = EthereumAdapter(rpc_url="http://eth")
        btc_adapter = BitcoinAdapter(rpc_url="http://btc")
        sol_adapter = SolanaAdapter(rpc_url="http://sol")

        with patch.object(eth_adapter, '_json_rpc_call', side_effect=[
            "Geth/v1.0",
            {'number': '0x1234', 'hash': '0x' + 'ab' * 32, 'timestamp': '0x60000000'},
        ]):
            eth_adapter.connect()
            tracker.update_height(eth_adapter.get_latest_block())

        with patch.object(btc_adapter, '_json_rpc_call', side_effect=[
            "Bitcoin Core",
            {'blocks': 800123, 'bestblockhash': 'cc' * 32},
            {'height': 800123, 'hash': 'cc' * 32, 'time': 1700000000},
        ]):
            btc_adapter.connect()
            tracker.update_height(btc_adapter.get_latest_block())

        with patch.object(sol_adapter, '_json_rpc_call', side_effect=[
            "Solana/v1.0",
            200000123,
            {'blockhash': 'dd' * 32, 'blockTime': 1700000000, 'blockHeight': 200000123},
        ]):
            sol_adapter.connect()
            tracker.update_height(sol_adapter.get_latest_block())

        heights = tracker.get_all_heights()
        assert ChainId.ETHEREUM in heights
        assert ChainId.BITCOIN in heights
        assert ChainId.SOLANA in heights


# ══════════════════════════════════════════════════════════════════════
#  SECTION 18: PACKAGE IMPORT VALIDATION
# ══════════════════════════════════════════════════════════════════════

class TestPackageImports:
    """Validate that qrdx.bridge package exports work correctly."""

    def test_import_from_package(self):
        from qrdx.bridge import (
            ChainId,
            BridgeRecord,
            OracleTransaction,
            EthereumAdapter,
            ShieldingManager,
            DoomsdayProtocol,
        )
        assert ChainId.ETHEREUM == 1
        assert callable(ShieldingManager)

    def test_all_exports(self):
        import qrdx.bridge as bridge
        assert hasattr(bridge, 'ChainId')
        assert hasattr(bridge, 'BridgeRecord')
        assert hasattr(bridge, 'OracleConsensus')
        assert hasattr(bridge, 'BlockHeightTracker')
        assert hasattr(bridge, 'ShieldingManager')
        assert hasattr(bridge, 'DoomsdayProtocol')
        assert hasattr(bridge, 'BridgeMinter')
        assert hasattr(bridge, 'InclusionProof')
        assert hasattr(bridge, 'ValidatorProof')
        assert hasattr(bridge, 'DOOMSDAY_CANARY_ADDRESS')
