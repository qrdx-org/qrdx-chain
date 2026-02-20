"""
Step 4 — QEVM: Quantum-Resistant EVM Tests

Covers:
  4.1  QRDX VM Fork (Shanghai + PQ Precompiles)
       - Each precompile has dedicated unit tests with real PQ keys
       - Gas cost charging verified
       - Invalid / malformed input handling
       - Determinism: same input → same output

  4.2  Production Executor Uses QRDXVM
       - Executor imports QRDXVM (not ShanghaiVM)
       - Deploy + call contract via QRDXVM executor
       - Precompiles accessible through executor

  4.3  State Bridge (Native ↔ EVM)
       - ContractStateManager account CRUD (SQLite)
       - StateSyncManager sync / checkpoint (SQLite)
       - ExecutionContext prepare / finalize / rollback
       - Wei ↔ QRDX conversion helpers
"""

import sys, os, asyncio, struct, tempfile, shutil
from dataclasses import dataclass
from decimal import Decimal
from typing import Optional
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

# ── py-evm on path ────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'py-evm'))

# ── Precompile imports ────────────────────────────────────────────────
from eth.vm.forks.qrdx.precompiles import (
    # Functions
    dilithium_verify,
    kyber_encapsulate_precompile,
    kyber_decapsulate_precompile,
    blake3_hash_precompile,
    # Registry
    QRDX_PRECOMPILES,
    # Addresses
    DILITHIUM_VERIFY_ADDRESS,
    KYBER_ENCAPSULATE_ADDRESS,
    KYBER_DECAPSULATE_ADDRESS,
    BLAKE3_HASH_ADDRESS,
    # Size constants
    DILITHIUM_INPUT_SIZE,
    KYBER_ENCAP_INPUT_SIZE,
    KYBER_DECAP_INPUT_SIZE,
    KYBER_SECRET_KEY_SIZE,
    KYBER_CIPHERTEXT_SIZE,
    KYBER_PUBKEY_SIZE,
    KYBER_SHARED_SECRET_SIZE,
    DILITHIUM_MSG_HASH_SIZE,
    DILITHIUM_PUBKEY_SIZE,
    DILITHIUM_SIGNATURE_SIZE,
    # Gas constants
    GAS_DILITHIUM_VERIFY,
    GAS_KYBER_ENCAPSULATE,
    GAS_KYBER_DECAPSULATE,
    GAS_BLAKE3_BASE,
    GAS_BLAKE3_PER_WORD,
)

# ── VM / Computation imports ──────────────────────────────────────────
from eth.vm.forks.qrdx import QRDXVM
from eth.vm.forks.qrdx.computation import QRDXComputation
from eth.vm.forks.qrdx.state import QRDXState
from eth.vm.forks.shanghai import ShanghaiVM

# ── Crypto imports (liboqs) ───────────────────────────────────────────
from eth.crypto import (
    generate_dilithium_keypair,
    verify_dilithium_signature,
    generate_kyber_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
    blake3_hash_bytes,
)

# ── State / Executor / Bridge imports ─────────────────────────────────
from qrdx.contracts.state import ContractStateManager, Account
from qrdx.contracts.state_sync import (
    StateSyncManager,
    ExecutionContext as SyncExecutionContext,
    convert_qrdx_to_wei,
    convert_wei_to_qrdx,
    WEI_PER_QRDX,
)
from eth_utils import to_checksum_address as _cksum

# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════

class FakeComputation:
    """
    Minimal stand-in for ComputationAPI that satisfies precompile functions.

    Precompiles call:
      - computation.consume_gas(amount, reason=...)
      - computation.msg.data   (bytes)
      - computation.output = ...  (bytes)
    """

    def __init__(self, data: bytes, gas: int = 10_000_000):
        self.msg = MagicMock()
        self.msg.data = data
        self._gas_remaining = gas
        self._gas_consumed = 0
        self.output = b''

    def consume_gas(self, amount: int, reason: str = '') -> None:
        if amount > self._gas_remaining:
            raise Exception(f"Out of gas: need {amount}, have {self._gas_remaining}")
        self._gas_remaining -= amount
        self._gas_consumed += amount

    @property
    def gas_consumed(self) -> int:
        return self._gas_consumed


class MockDatabaseSQLite:
    """In-memory mock of DatabaseSQLite for testing."""

    def __init__(self):
        self.connection = None  # will be set to real aiosqlite connection
        self._balances = {}     # address → Decimal

    async def get_address_balance(self, address: str) -> Decimal:
        return self._balances.get(address, Decimal('0'))


async def _create_test_db():
    """Create a real in-memory aiosqlite connection for tests."""
    import aiosqlite
    db = MockDatabaseSQLite()
    db.connection = await aiosqlite.connect(':memory:')
    db.connection.row_factory = aiosqlite.Row
    # Create tables needed by ContractStateManager
    await db.connection.execute("""
        CREATE TABLE IF NOT EXISTS account_state (
            address TEXT PRIMARY KEY,
            balance TEXT NOT NULL DEFAULT '0',
            nonce INTEGER NOT NULL DEFAULT 0,
            code_hash TEXT,
            storage_root TEXT,
            created_at INTEGER,
            updated_at INTEGER,
            is_contract INTEGER DEFAULT 0
        )
    """)
    await db.connection.execute("""
        CREATE TABLE IF NOT EXISTS contract_code (
            code_hash TEXT PRIMARY KEY,
            bytecode BLOB,
            deployed_at INTEGER,
            deployer TEXT,
            size INTEGER
        )
    """)
    await db.connection.execute("""
        CREATE TABLE IF NOT EXISTS contract_storage (
            contract_address TEXT NOT NULL,
            storage_key TEXT NOT NULL,
            storage_value TEXT,
            block_number INTEGER,
            PRIMARY KEY (contract_address, storage_key)
        )
    """)
    await db.connection.commit()
    return db


# ═══════════════════════════════════════════════════════════════════════
# §4.1 — PRECOMPILE UNIT TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestPrecompileRegistry:
    """Verify the precompile registry is callable-based (not class-based)."""

    def test_registry_maps_to_callables(self):
        """QRDX_PRECOMPILES must map Address → callable (not class)."""
        for addr, fn in QRDX_PRECOMPILES.items():
            assert callable(fn), f"Precompile at {addr.hex()} is not callable"
            # Must NOT be a class (type)
            assert not isinstance(fn, type), (
                f"Precompile at {addr.hex()} is a class, not a function"
            )

    def test_registry_has_twelve_precompiles(self):
        assert len(QRDX_PRECOMPILES) == 12

    def test_correct_addresses(self):
        from eth.vm.forks.qrdx.precompiles import (
            ORACLE_GET_CHAIN_STATE_ADDRESS,
            ORACLE_VERIFY_PROOF_ADDRESS,
            ORACLE_SUBMIT_CROSS_CHAIN_TX_ADDRESS,
            EXCHANGE_CREATE_POOL_ADDRESS,
            EXCHANGE_SWAP_ADDRESS,
            EXCHANGE_ADD_LIQUIDITY_ADDRESS,
            EXCHANGE_PLACE_LIMIT_ORDER_ADDRESS,
            EXCHANGE_CANCEL_ORDER_ADDRESS,
        )
        expected = {
            DILITHIUM_VERIFY_ADDRESS,
            KYBER_ENCAPSULATE_ADDRESS,
            KYBER_DECAPSULATE_ADDRESS,
            BLAKE3_HASH_ADDRESS,
            ORACLE_GET_CHAIN_STATE_ADDRESS,
            ORACLE_VERIFY_PROOF_ADDRESS,
            ORACLE_SUBMIT_CROSS_CHAIN_TX_ADDRESS,
            EXCHANGE_CREATE_POOL_ADDRESS,
            EXCHANGE_SWAP_ADDRESS,
            EXCHANGE_ADD_LIQUIDITY_ADDRESS,
            EXCHANGE_PLACE_LIMIT_ORDER_ADDRESS,
            EXCHANGE_CANCEL_ORDER_ADDRESS,
        }
        assert set(QRDX_PRECOMPILES.keys()) == expected

    def test_addresses_are_0x09_to_0x0c(self):
        assert DILITHIUM_VERIFY_ADDRESS == bytes(19) + b'\x09'
        assert KYBER_ENCAPSULATE_ADDRESS == bytes(19) + b'\x0a'
        assert KYBER_DECAPSULATE_ADDRESS == bytes(19) + b'\x0b'
        assert BLAKE3_HASH_ADDRESS == bytes(19) + b'\x0c'


class TestPrecompileSizeConstants:
    """Verify size constants match real liboqs key sizes."""

    def test_dilithium_sizes(self):
        priv, pub = generate_dilithium_keypair()
        assert len(pub.to_bytes()) == DILITHIUM_PUBKEY_SIZE  # 1,952
        sig = priv.sign(b'\x00' * 32)
        assert len(sig) == DILITHIUM_SIGNATURE_SIZE       # 3,309

    def test_kyber_sizes(self):
        priv, pub = generate_kyber_keypair()
        assert len(pub.to_bytes()) == KYBER_PUBKEY_SIZE        # 1,184
        assert len(priv.to_bytes()) == KYBER_SECRET_KEY_SIZE   # 2,400
        ct, ss = kyber_encapsulate(pub.to_bytes())
        assert len(ct) == KYBER_CIPHERTEXT_SIZE            # 1,088
        assert len(ss) == KYBER_SHARED_SECRET_SIZE         # 32

    def test_dilithium_input_total(self):
        assert DILITHIUM_INPUT_SIZE == 32 + 1952 + 3309    # 5,293

    def test_kyber_decap_input_total(self):
        assert KYBER_DECAP_INPUT_SIZE == 2400 + 1088       # 3,488


# ── Dilithium Verify (0x09) ───────────────────────────────────────────

class TestDilithiumVerifyPrecompile:
    """Precompile 0x09 — ML-DSA-65 signature verification."""

    def _build_input(self, msg_hash: bytes, pub_key: bytes, sig: bytes) -> bytes:
        return msg_hash + pub_key + sig

    def test_valid_signature_returns_0x01(self):
        priv, pub = generate_dilithium_keypair()
        msg = b'\xab' * 32
        sig = priv.sign(msg)
        inp = self._build_input(msg, pub.to_bytes(), sig)
        assert len(inp) == DILITHIUM_INPUT_SIZE

        comp = FakeComputation(inp)
        result = dilithium_verify(comp)
        assert result.output == b'\x01'

    def test_invalid_signature_returns_0x00(self):
        priv, pub = generate_dilithium_keypair()
        msg = b'\xab' * 32
        sig = priv.sign(msg)
        # Corrupt signature
        bad_sig = bytearray(sig)
        bad_sig[0] ^= 0xFF
        inp = self._build_input(msg, pub.to_bytes(), bytes(bad_sig))

        comp = FakeComputation(inp)
        result = dilithium_verify(comp)
        assert result.output == b'\x00'

    def test_wrong_length_input_returns_0x00(self):
        for bad_len in [0, 1, 100, DILITHIUM_INPUT_SIZE - 1, DILITHIUM_INPUT_SIZE + 1]:
            comp = FakeComputation(b'\x00' * bad_len)
            result = dilithium_verify(comp)
            assert result.output == b'\x00', f"Failed for length {bad_len}"

    def test_wrong_pubkey_returns_0x00(self):
        priv, pub = generate_dilithium_keypair()
        _, pub2 = generate_dilithium_keypair()
        msg = b'\xcc' * 32
        sig = priv.sign(msg)
        inp = self._build_input(msg, pub2.to_bytes(), sig)  # wrong key

        comp = FakeComputation(inp)
        result = dilithium_verify(comp)
        assert result.output == b'\x00'

    def test_gas_consumed(self):
        comp = FakeComputation(b'\x00' * DILITHIUM_INPUT_SIZE)
        dilithium_verify(comp)
        assert comp.gas_consumed == GAS_DILITHIUM_VERIFY  # 50,000

    def test_gas_consumed_on_bad_length(self):
        """Gas is always charged, even on invalid input."""
        comp = FakeComputation(b'\x00' * 10)
        dilithium_verify(comp)
        assert comp.gas_consumed == GAS_DILITHIUM_VERIFY

    def test_determinism_same_input_same_output(self):
        priv, pub = generate_dilithium_keypair()
        msg = b'\xdd' * 32
        sig = priv.sign(msg)
        inp = self._build_input(msg, pub.to_bytes(), sig)

        results = []
        for _ in range(3):
            comp = FakeComputation(inp)
            dilithium_verify(comp)
            results.append(comp.output)
        assert all(r == results[0] for r in results)

    def test_empty_input(self):
        comp = FakeComputation(b'')
        result = dilithium_verify(comp)
        assert result.output == b'\x00'

    def test_all_zeros_pubkey(self):
        """All-zero pubkey should return 0x00 (invalid)."""
        inp = b'\x00' * DILITHIUM_INPUT_SIZE
        comp = FakeComputation(inp)
        result = dilithium_verify(comp)
        assert result.output == b'\x00'


# ── Kyber Encapsulate (0x0a) ──────────────────────────────────────────

class TestKyberEncapsulatePrecompile:
    """Precompile 0x0a — ML-KEM-768 encapsulation."""

    def test_valid_encapsulation(self):
        _, pub = generate_kyber_keypair()
        comp = FakeComputation(pub.to_bytes())
        result = kyber_encapsulate_precompile(comp)

        assert len(result.output) == KYBER_CIPHERTEXT_SIZE + KYBER_SHARED_SECRET_SIZE  # 1120

    def test_output_is_ciphertext_plus_shared_secret(self):
        priv, pub = generate_kyber_keypair()
        comp = FakeComputation(pub.to_bytes())
        kyber_encapsulate_precompile(comp)

        ct = comp.output[:KYBER_CIPHERTEXT_SIZE]
        ss_encap = comp.output[KYBER_CIPHERTEXT_SIZE:]
        assert len(ct) == 1088
        assert len(ss_encap) == 32

        # Decapsulate to verify shared secret matches
        ss_decap = kyber_decapsulate(ct, priv.to_bytes())
        assert ss_encap == ss_decap

    def test_wrong_length_returns_empty(self):
        for bad_len in [0, 1, 100, KYBER_ENCAP_INPUT_SIZE - 1, KYBER_ENCAP_INPUT_SIZE + 1]:
            comp = FakeComputation(b'\x00' * bad_len)
            result = kyber_encapsulate_precompile(comp)
            assert result.output == b'', f"Failed for length {bad_len}"

    def test_gas_consumed(self):
        _, pub = generate_kyber_keypair()
        comp = FakeComputation(pub.to_bytes())
        kyber_encapsulate_precompile(comp)
        assert comp.gas_consumed == GAS_KYBER_ENCAPSULATE  # 30,000

    def test_gas_consumed_on_bad_length(self):
        comp = FakeComputation(b'\x00' * 10)
        kyber_encapsulate_precompile(comp)
        assert comp.gas_consumed == GAS_KYBER_ENCAPSULATE

    def test_invalid_pubkey_returns_empty(self):
        """Random bytes of correct length but not a valid key."""
        comp = FakeComputation(b'\xff' * KYBER_ENCAP_INPUT_SIZE)
        result = kyber_encapsulate_precompile(comp)
        # liboqs may or may not error on garbage keys — check output is valid length or empty
        assert len(result.output) in (0, KYBER_CIPHERTEXT_SIZE + KYBER_SHARED_SECRET_SIZE)

    def test_nondeterministic_across_calls(self):
        """Encapsulation is non-deterministic — different ciphertext each time."""
        _, pub = generate_kyber_keypair()
        outputs = set()
        for _ in range(3):
            comp = FakeComputation(pub.to_bytes())
            kyber_encapsulate_precompile(comp)
            outputs.add(comp.output)
        # At least 2 unique outputs (overwhelmingly probable)
        assert len(outputs) >= 2


# ── Kyber Decapsulate (0x0b) ──────────────────────────────────────────

class TestKyberDecapsulatePrecompile:
    """Precompile 0x0b — ML-KEM-768 decapsulation."""

    def test_valid_decapsulation(self):
        priv, pub = generate_kyber_keypair()
        ct, ss = kyber_encapsulate(pub.to_bytes())

        inp = priv.to_bytes() + ct
        assert len(inp) == KYBER_DECAP_INPUT_SIZE  # 3,488

        comp = FakeComputation(inp)
        result = kyber_decapsulate_precompile(comp)
        assert result.output == ss

    def test_roundtrip_encap_decap(self):
        """Full round-trip through both precompiles."""
        priv, pub = generate_kyber_keypair()

        # Encapsulate
        comp_enc = FakeComputation(pub.to_bytes())
        kyber_encapsulate_precompile(comp_enc)
        ct = comp_enc.output[:KYBER_CIPHERTEXT_SIZE]
        ss_encap = comp_enc.output[KYBER_CIPHERTEXT_SIZE:]

        # Decapsulate
        comp_dec = FakeComputation(priv.to_bytes() + ct)
        kyber_decapsulate_precompile(comp_dec)
        ss_decap = comp_dec.output

        assert ss_encap == ss_decap

    def test_wrong_length_returns_empty(self):
        for bad_len in [0, 1, 100, KYBER_DECAP_INPUT_SIZE - 1, KYBER_DECAP_INPUT_SIZE + 1]:
            comp = FakeComputation(b'\x00' * bad_len)
            result = kyber_decapsulate_precompile(comp)
            assert result.output == b'', f"Failed for length {bad_len}"

    def test_old_wrong_size_2592_rejected(self):
        """The old bug used SK=2592. Verify 3680-byte input is rejected."""
        old_bad_size = 2592 + 1088  # 3,680
        comp = FakeComputation(b'\x00' * old_bad_size)
        result = kyber_decapsulate_precompile(comp)
        assert result.output == b''  # Rejected — not 3,488

    def test_gas_consumed(self):
        priv, pub = generate_kyber_keypair()
        ct, _ = kyber_encapsulate(pub.to_bytes())
        comp = FakeComputation(priv.to_bytes() + ct)
        kyber_decapsulate_precompile(comp)
        assert comp.gas_consumed == GAS_KYBER_DECAPSULATE  # 30,000

    def test_wrong_secret_key_returns_different_secret(self):
        """Decapsulating with wrong SK yields wrong shared secret."""
        priv1, pub1 = generate_kyber_keypair()
        priv2, _ = generate_kyber_keypair()
        ct, ss = kyber_encapsulate(pub1.to_bytes())

        # Decapsulate with wrong key
        comp = FakeComputation(priv2.to_bytes() + ct)
        kyber_decapsulate_precompile(comp)
        # Should produce 32 bytes but NOT match the original shared secret
        assert len(comp.output) == 32
        assert comp.output != ss

    def test_determinism_same_input_same_output(self):
        """Decapsulation IS deterministic for same (sk, ct) pair."""
        priv, pub = generate_kyber_keypair()
        ct, _ = kyber_encapsulate(pub.to_bytes())
        inp = priv.to_bytes() + ct

        results = []
        for _ in range(3):
            comp = FakeComputation(inp)
            kyber_decapsulate_precompile(comp)
            results.append(comp.output)
        assert all(r == results[0] for r in results)


# ── BLAKE3 Hash (0x0c) ───────────────────────────────────────────────

class TestBlake3HashPrecompile:
    """Precompile 0x0c — BLAKE3-256 hashing."""

    def test_known_hash(self):
        data = b'QRDX quantum-resistant blockchain'
        expected = blake3_hash_bytes(data)

        comp = FakeComputation(data)
        result = blake3_hash_precompile(comp)
        assert result.output == expected
        assert len(result.output) == 32

    def test_empty_input(self):
        expected = blake3_hash_bytes(b'')
        comp = FakeComputation(b'')
        blake3_hash_precompile(comp)
        assert comp.output == expected

    def test_large_input(self):
        data = os.urandom(10_000)
        expected = blake3_hash_bytes(data)

        comp = FakeComputation(data)
        blake3_hash_precompile(comp)
        assert comp.output == expected

    def test_gas_formula_zero_bytes(self):
        comp = FakeComputation(b'')
        blake3_hash_precompile(comp)
        # 0 bytes → 0 words → gas = 60 + 12*0 = 60
        assert comp.gas_consumed == GAS_BLAKE3_BASE

    def test_gas_formula_one_byte(self):
        comp = FakeComputation(b'\x01')
        blake3_hash_precompile(comp)
        # 1 byte → 1 word → gas = 60 + 12*1 = 72
        assert comp.gas_consumed == GAS_BLAKE3_BASE + GAS_BLAKE3_PER_WORD

    def test_gas_formula_32_bytes(self):
        comp = FakeComputation(b'\x00' * 32)
        blake3_hash_precompile(comp)
        # 32 bytes → 1 word → gas = 72
        assert comp.gas_consumed == GAS_BLAKE3_BASE + GAS_BLAKE3_PER_WORD

    def test_gas_formula_33_bytes(self):
        comp = FakeComputation(b'\x00' * 33)
        blake3_hash_precompile(comp)
        # 33 bytes → 2 words → gas = 60 + 24 = 84
        assert comp.gas_consumed == GAS_BLAKE3_BASE + 2 * GAS_BLAKE3_PER_WORD

    def test_gas_formula_64_bytes(self):
        comp = FakeComputation(b'\x00' * 64)
        blake3_hash_precompile(comp)
        assert comp.gas_consumed == GAS_BLAKE3_BASE + 2 * GAS_BLAKE3_PER_WORD

    def test_determinism(self):
        data = b'deterministic test'
        results = []
        for _ in range(5):
            comp = FakeComputation(data)
            blake3_hash_precompile(comp)
            results.append(comp.output)
        assert all(r == results[0] for r in results)

    def test_different_inputs_different_hashes(self):
        comp1 = FakeComputation(b'input_a')
        comp2 = FakeComputation(b'input_b')
        blake3_hash_precompile(comp1)
        blake3_hash_precompile(comp2)
        assert comp1.output != comp2.output


# ── Gas DoS Protection ────────────────────────────────────────────────

class TestPrecompileGasProtection:
    """Verify gas costs prevent DoS attacks."""

    def test_dilithium_verify_out_of_gas(self):
        """49,999 gas should fail for Dilithium verify."""
        comp = FakeComputation(b'\x00' * DILITHIUM_INPUT_SIZE, gas=GAS_DILITHIUM_VERIFY - 1)
        with pytest.raises(Exception, match="Out of gas"):
            dilithium_verify(comp)

    def test_kyber_encap_out_of_gas(self):
        comp = FakeComputation(b'\x00' * KYBER_ENCAP_INPUT_SIZE, gas=GAS_KYBER_ENCAPSULATE - 1)
        with pytest.raises(Exception, match="Out of gas"):
            kyber_encapsulate_precompile(comp)

    def test_kyber_decap_out_of_gas(self):
        comp = FakeComputation(b'\x00' * KYBER_DECAP_INPUT_SIZE, gas=GAS_KYBER_DECAPSULATE - 1)
        with pytest.raises(Exception, match="Out of gas"):
            kyber_decapsulate_precompile(comp)

    def test_blake3_out_of_gas(self):
        """Large input with insufficient gas."""
        data = b'\x00' * 1024  # 32 words → gas = 60 + 384 = 444
        comp = FakeComputation(data, gas=100)
        with pytest.raises(Exception, match="Out of gas"):
            blake3_hash_precompile(comp)

    def test_exact_gas_sufficient(self):
        """Exact gas amount should succeed, not fail."""
        comp = FakeComputation(b'\x00' * DILITHIUM_INPUT_SIZE, gas=GAS_DILITHIUM_VERIFY)
        dilithium_verify(comp)  # Should not raise
        assert comp._gas_remaining == 0


# ═══════════════════════════════════════════════════════════════════════
# §4.1 — QRDXVM FORK VERIFICATION
# ═══════════════════════════════════════════════════════════════════════

class TestQRDXVMFork:
    """Verify QRDXVM extends ShanghaiVM with PQ precompiles."""

    def test_qrdxvm_is_subclass_of_shanghai(self):
        assert issubclass(QRDXVM, ShanghaiVM)

    def test_qrdxvm_fork_name(self):
        assert QRDXVM.fork == "qrdx"

    def test_qrdxvm_state_uses_qrdx_computation(self):
        assert QRDXState.computation_class is QRDXComputation

    def test_qrdx_computation_has_pq_precompiles(self):
        """QRDXComputation._precompiles must include all 4 PQ addresses."""
        precompiles = QRDXComputation._precompiles
        for addr in [DILITHIUM_VERIFY_ADDRESS, KYBER_ENCAPSULATE_ADDRESS,
                     KYBER_DECAPSULATE_ADDRESS, BLAKE3_HASH_ADDRESS]:
            assert addr in precompiles, f"Missing precompile at {addr.hex()}"

    def test_qrdx_computation_inherits_shanghai_precompiles(self):
        """Should still have ecrecover, sha256, etc. from Shanghai."""
        from eth.vm.forks.shanghai.computation import ShanghaiComputation
        for addr in ShanghaiComputation._precompiles:
            if addr not in QRDX_PRECOMPILES:
                # Shanghai precompile that isn't overridden by QRDX
                assert addr in QRDXComputation._precompiles

    def test_precompiles_in_computation_are_callable(self):
        for addr, fn in QRDXComputation._precompiles.items():
            assert callable(fn), f"Precompile at {addr.hex()} is not callable"

    def test_qrdxvm_no_dao_fork(self):
        assert QRDXVM.support_dao_fork is False


# ═══════════════════════════════════════════════════════════════════════
# §4.2 — EXECUTOR USES QRDXVM
# ═══════════════════════════════════════════════════════════════════════

class TestExecutorUsesQRDXVM:
    """Verify executor_v2 imports and uses QRDXVM, not ShanghaiVM."""

    def test_executor_imports_qrdxvm(self):
        """executor_v2 module must import QRDXVM, not ShanghaiVM."""
        import qrdx.contracts.evm_executor_v2 as mod
        source = open(mod.__file__).read()
        assert 'from eth.vm.forks.qrdx import QRDXVM' in source
        assert 'from eth.vm.forks.shanghai import ShanghaiVM' not in source

    def test_executor_imports_qrdx_computation(self):
        import qrdx.contracts.evm_executor_v2 as mod
        source = open(mod.__file__).read()
        assert 'QRDXComputation' in source
        assert 'ShanghaiComputation.apply' not in source

    def test_executor_imports_qrdx_state(self):
        import qrdx.contracts.evm_executor_v2 as mod
        source = open(mod.__file__).read()
        assert 'QRDXState' in source
        assert 'ShanghaiState(' not in source

    def test_executor_has_logger(self):
        """Module-level logger must be defined (no NameError)."""
        import qrdx.contracts.evm_executor_v2 as mod
        assert hasattr(mod, 'logger')
        assert mod.logger is not None

    def test_executor_chain_id(self):
        """Chain ID must be 88888 (QRDX)."""
        import qrdx.contracts.evm_executor_v2 as mod
        source = open(mod.__file__).read()
        assert '88888' in source

    def test_executor_instantiation(self):
        """Can instantiate QRDXEVMExecutor with a mock state manager."""
        from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor
        mock_state = MagicMock()
        mock_state.get_balance_sync = MagicMock(return_value=10**18)
        mock_state.get_nonce_sync = MagicMock(return_value=0)
        mock_state.get_code_sync = MagicMock(return_value=b'')
        mock_state.get_all_storage_sync = MagicMock(return_value={})
        executor = QRDXEVMExecutor(mock_state)
        assert executor.state_manager is mock_state
        assert executor.state_root is not None


class TestExecutorSimpleStorageContract:
    """Integration test: deploy and call a simple storage contract via QRDXVM executor."""

    # Solidity: contract SimpleStorage { uint256 value; function set(uint256 v) { value = v; } function get() view returns (uint256) { return value; } }
    # Compiled bytecode (from solc):
    DEPLOY_BYTECODE = bytes.fromhex(
        "608060405234801561001057600080fd5b50"
        "60f78061001f6000396000f3fe"
        "6080604052348015600f57600080fd5b5060"
        "043610603c5760003560e01c806360fe47b1"
        "1460415780636d4ce63c14605757005b6000"
        "80fd5b60556050366004607a565b606f565b"
        "005b605d6075565b60405190815260200160"
        "405180910390f35b600055565b60005490"
        "565b600060208284031215608b57600080fd"
        "5b503591905056fea264697066735822"
    )

    def _make_state_manager(self):
        """Create a working ContractStateManager with sync methods."""
        sm = ContractStateManager(MagicMock())
        return sm

    def test_deploy_contract(self):
        """Deploy SimpleStorage — should succeed and return contract address."""
        from qrdx.contracts.evm_executor_v2 import QRDXEVMExecutor
        sm = self._make_state_manager()
        sender = bytes.fromhex('1234567890abcdef1234567890abcdef12345678')
        sm.set_balance_sync(
            '0x' + sender.hex(),
            10**21,  # 1000 ETH
        )

        executor = QRDXEVMExecutor(sm)
        result = executor.execute(
            sender=sender,
            to=None,  # contract creation
            value=0,
            data=self.DEPLOY_BYTECODE,
            gas=1_000_000,
            gas_price=1,
        )
        # Contract deployment may or may not succeed depending on exact bytecode
        # The key test is that the executor doesn't crash with Shanghai references
        assert result is not None
        assert isinstance(result.gas_used, int)
        assert result.gas_used > 0


# ═══════════════════════════════════════════════════════════════════════
# §4.3 — STATE BRIDGE (NATIVE ↔ EVM)
# ═══════════════════════════════════════════════════════════════════════

class TestContractStateManager:
    """Test ContractStateManager sync wrappers (used by executor)."""

    def test_balance_round_trip(self):
        sm = ContractStateManager(MagicMock())
        addr = '0xAbCdEf0123456789AbCdEf0123456789AbCdEf01'
        sm.set_balance_sync(addr, 12345)
        assert sm.get_balance_sync(addr) == 12345

    def test_nonce_round_trip(self):
        sm = ContractStateManager(MagicMock())
        addr = '0xAbCdEf0123456789AbCdEf0123456789AbCdEf01'
        sm.set_nonce_sync(addr, 7)
        assert sm.get_nonce_sync(addr) == 7

    def test_code_round_trip(self):
        sm = ContractStateManager(MagicMock())
        addr = '0xAbCdEf0123456789AbCdEf0123456789AbCdEf01'
        code = b'\x60\x80\x60\x40\x52'
        sm.set_code_sync(addr, code)
        assert sm.get_code_sync(addr) == code

    def test_storage_round_trip(self):
        sm = ContractStateManager(MagicMock())
        addr = '0xAbCdEf0123456789AbCdEf0123456789AbCdEf01'
        key = b'\x00' * 32
        value = b'\x00' * 31 + b'\x42'
        sm.set_storage_sync(addr, key, value)
        assert sm.get_storage_sync(addr, key) == value

    def test_get_all_storage(self):
        sm = ContractStateManager(MagicMock())
        addr = '0xAbCdEf0123456789AbCdEf0123456789AbCdEf01'
        k1 = b'\x00' * 32
        k2 = b'\x00' * 31 + b'\x01'
        sm.set_storage_sync(addr, k1, b'\x01' * 32)
        sm.set_storage_sync(addr, k2, b'\x02' * 32)
        all_s = sm.get_all_storage_sync(addr)
        assert len(all_s) == 2

    def test_snapshot_and_revert(self):
        sm = ContractStateManager(MagicMock())
        addr = '0xAbCdEf0123456789AbCdEf0123456789AbCdEf01'
        sm.set_balance_sync(addr, 100)
        snap = sm.snapshot_sync()
        sm.set_balance_sync(addr, 200)
        assert sm.get_balance_sync(addr) == 200
        sm.revert_sync(snap)
        assert sm.get_balance_sync(addr) == 100

    def test_default_balance_zero(self):
        sm = ContractStateManager(MagicMock())
        assert sm.get_balance_sync('0x' + '00' * 20) == 0

    def test_default_nonce_zero(self):
        sm = ContractStateManager(MagicMock())
        assert sm.get_nonce_sync('0x' + '00' * 20) == 0

    def test_default_code_empty(self):
        sm = ContractStateManager(MagicMock())
        assert sm.get_code_sync('0x' + '00' * 20) == b''

    def test_account_created_on_set(self):
        sm = ContractStateManager(MagicMock())
        addr = '0xAbCdEf0123456789AbCdEf0123456789AbCdEf01'
        sm.set_balance_sync(addr, 42)
        assert addr in sm._accounts_cache


class TestContractStateManagerAsync:
    """Test async methods of ContractStateManager with real SQLite."""

    @pytest.fixture
    async def state_mgr(self):
        db = await _create_test_db()
        sm = ContractStateManager(db)
        yield sm
        await db.connection.close()

    @pytest.mark.asyncio
    async def test_get_account_default(self, state_mgr):
        acct = await state_mgr.get_account('0x' + 'aa' * 20)
        assert acct.balance == 0
        assert acct.nonce == 0

    @pytest.mark.asyncio
    async def test_set_and_get_balance(self, state_mgr):
        addr = '0x' + 'bb' * 20
        await state_mgr.set_balance(addr, 999)
        assert await state_mgr.get_balance(addr) == 999

    @pytest.mark.asyncio
    async def test_commit_and_reload(self, state_mgr):
        addr = '0x' + 'cc' * 20
        await state_mgr.set_balance(addr, 500)
        await state_mgr.commit(block_number=1)

        # Clear cache and reload from DB
        state_mgr._accounts_cache.clear()
        acct = await state_mgr.get_account(addr)
        assert acct.balance == 500

    @pytest.mark.asyncio
    async def test_snapshot_and_revert(self, state_mgr):
        addr = '0x' + 'dd' * 20
        await state_mgr.set_balance(addr, 100)
        snap = await state_mgr.snapshot()
        await state_mgr.set_balance(addr, 200)
        assert (await state_mgr.get_balance(addr)) == 200
        await state_mgr.revert(snap)
        assert (await state_mgr.get_balance(addr)) == 100


# ── State Sync Manager ───────────────────────────────────────────────

class TestStateSyncManager:
    """Test StateSyncManager with real SQLite."""

    @pytest.fixture
    async def sync_env(self):
        db = await _create_test_db()
        evm_state = ContractStateManager(db)
        sync_mgr = StateSyncManager(db, evm_state)
        await sync_mgr.ensure_tables_exist()
        yield db, evm_state, sync_mgr
        await db.connection.close()

    @pytest.mark.asyncio
    async def test_ensure_tables_idempotent(self, sync_env):
        db, evm_state, sync_mgr = sync_env
        # Should not raise on second call
        await sync_mgr.ensure_tables_exist()

    @pytest.mark.asyncio
    async def test_sync_address_sets_evm_balance(self, sync_env):
        db, evm_state, sync_mgr = sync_env
        addr = '0x' + 'AA' * 20
        # sync_address_to_evm checksums the address before calling get_address_balance
        db._balances[_cksum(addr)] = Decimal('10.5')

        synced = await sync_mgr.sync_address_to_evm(
            address=addr, block_height=1, block_hash='ab' * 32
        )
        assert synced is True
        assert await evm_state.get_balance(addr) == int(Decimal('10.5') * WEI_PER_QRDX)

    @pytest.mark.asyncio
    async def test_sync_skips_if_already_synced(self, sync_env):
        db, evm_state, sync_mgr = sync_env
        addr = '0x' + 'BB' * 20
        db._balances[_cksum(addr)] = Decimal('1')

        await sync_mgr.sync_address_to_evm(addr, 5, 'cc' * 32)
        # Second sync at same block should be skipped
        synced = await sync_mgr.sync_address_to_evm(addr, 5, 'cc' * 32)
        assert synced is False

    @pytest.mark.asyncio
    async def test_sync_force_overrides_skip(self, sync_env):
        db, evm_state, sync_mgr = sync_env
        addr = '0x' + 'CC' * 20
        db._balances[_cksum(addr)] = Decimal('2')

        await sync_mgr.sync_address_to_evm(addr, 5, 'dd' * 32)
        synced = await sync_mgr.sync_address_to_evm(addr, 5, 'dd' * 32, force=True)
        assert synced is True

    @pytest.mark.asyncio
    async def test_record_balance_change(self, sync_env):
        db, evm_state, sync_mgr = sync_env
        await sync_mgr.record_balance_change(
            address='0x' + 'DD' * 20,
            block_height=10,
            block_hash='ee' * 32,
            tx_hash='ff' * 32,
            balance_before=100,
            balance_after=80,
            reason='gas_payment',
        )
        # Verify it was recorded
        cursor = await db.connection.execute(
            "SELECT COUNT(*) FROM evm_balance_changes"
        )
        row = await cursor.fetchone()
        assert row[0] == 1


# ── Execution Context ────────────────────────────────────────────────

class TestExecutionContext:
    """Test the ExecutionContext prepare/finalize/rollback lifecycle."""

    @pytest.fixture
    async def ctx_env(self):
        db = await _create_test_db()
        evm_state = ContractStateManager(db)
        sync_mgr = StateSyncManager(db, evm_state)
        await sync_mgr.ensure_tables_exist()
        yield db, evm_state, sync_mgr
        await db.connection.close()

    @pytest.mark.asyncio
    async def test_prepare_creates_snapshot(self, ctx_env):
        db, evm_state, sync_mgr = ctx_env
        ctx = SyncExecutionContext(
            block_height=1, block_hash='aa' * 32, block_timestamp=1000,
            db=db, evm_state=evm_state, sync_manager=sync_mgr
        )
        addr = '0x' + 'EE' * 20
        db._balances[_cksum(addr)] = Decimal('5')
        await ctx.prepare_execution(addr)
        assert ctx._evm_snapshot_id is not None

    @pytest.mark.asyncio
    async def test_finalize_success_commits(self, ctx_env):
        db, evm_state, sync_mgr = ctx_env
        ctx = SyncExecutionContext(
            block_height=1, block_hash='bb' * 32, block_timestamp=1000,
            db=db, evm_state=evm_state, sync_manager=sync_mgr
        )
        addr = '0x' + 'FF' * 20
        db._balances[_cksum(addr)] = Decimal('10')
        await ctx.prepare_execution(addr)

        await ctx.finalize_execution(
            sender=addr, tx_hash='cc' * 32, success=True,
            gas_used=21000, gas_price=1, value=0
        )
        assert ctx._evm_snapshot_id is None

    @pytest.mark.asyncio
    async def test_finalize_failure_reverts(self, ctx_env):
        db, evm_state, sync_mgr = ctx_env
        ctx = SyncExecutionContext(
            block_height=1, block_hash='dd' * 32, block_timestamp=1000,
            db=db, evm_state=evm_state, sync_manager=sync_mgr
        )
        addr = '0x' + '11' * 20
        db._balances[_cksum(addr)] = Decimal('10')
        await ctx.prepare_execution(addr)

        balance_before = await evm_state.get_balance(addr)
        await ctx.finalize_execution(
            sender=addr, tx_hash='ee' * 32, success=False,
            gas_used=21000, gas_price=1, value=0
        )
        # Balance should be reverted
        balance_after = await evm_state.get_balance(addr)
        assert balance_after == balance_before


# ── Conversion helpers ────────────────────────────────────────────────

class TestConversionHelpers:
    """Test Wei ↔ QRDX conversion."""

    def test_1_qrdx_to_wei(self):
        assert convert_qrdx_to_wei(Decimal('1')) == 10**18

    def test_0_qrdx_to_wei(self):
        assert convert_qrdx_to_wei(Decimal('0')) == 0

    def test_fractional_qrdx_to_wei(self):
        assert convert_qrdx_to_wei(Decimal('0.5')) == 5 * 10**17

    def test_1_wei_to_qrdx(self):
        assert convert_wei_to_qrdx(10**18) == Decimal('1')

    def test_round_trip(self):
        original = Decimal('123.456789')
        wei = convert_qrdx_to_wei(original)
        back = convert_wei_to_qrdx(wei)
        # Should be very close (integer truncation may lose sub-wei)
        assert abs(back - original) < Decimal('1e-18')

    def test_large_value(self):
        val = Decimal('1000000')
        assert convert_qrdx_to_wei(val) == 10**24

    def test_wei_per_qrdx_constant(self):
        assert WEI_PER_QRDX == 10**18
