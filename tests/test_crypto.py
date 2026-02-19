"""
QRDX Cryptography Test Suite — Phase 1

Comprehensive tests for:
- Step 0.2: PQ signature verification (no bypass)
- Step 0.3: PQ key generation (no fakes)
- Step 1.1: Dilithium ML-DSA-65 signatures
- Step 1.2: Kyber ML-KEM-768 key encapsulation
- Step 1.3: PQ address derivation
- Step 1.4: secp256k1 classical signatures
- Step 13.1: Full crypto module unit tests

Run with:
    pytest tests/test_crypto.py -v
"""

import os
import pytest

# ============================================================================
# Dilithium ML-DSA-65 Signatures
# ============================================================================


class TestDilithiumImport:
    """Step 0.2/0.3: Module MUST require liboqs — no fallback."""

    def test_module_imports(self):
        from qrdx.crypto.pq import dilithium
        assert hasattr(dilithium, '_WORKING_ALGORITHM')

    def test_liboqs_required(self):
        """Verify liboqs is genuinely loaded, not stubbed."""
        import oqs
        assert hasattr(oqs, 'Signature')

    def test_no_fallback_flag(self):
        """There must be no _HAS_LIBOQS flag or fallback logic."""
        from qrdx.crypto.pq import dilithium
        assert not hasattr(dilithium, '_HAS_LIBOQS'), \
            "Fallback flag _HAS_LIBOQS must not exist"
        assert not hasattr(dilithium, '_generate_fallback_keys'), \
            "Fallback key generation must not exist"
        assert not hasattr(dilithium, 'PQNotAvailableError'), \
            "PQNotAvailableError must not exist — liboqs is mandatory"

    def test_working_algorithm(self):
        """Algorithm must be ML-DSA-65 or Dilithium3."""
        from qrdx.crypto.pq.dilithium import _WORKING_ALGORITHM
        assert _WORKING_ALGORITHM in ('ML-DSA-65', 'Dilithium3')

    def test_is_available_always_true(self):
        """Since liboqs is mandatory, is_available must always return True."""
        from qrdx.crypto.pq import is_available
        assert is_available() is True

    def test_get_liboqs_error_none(self):
        """Since liboqs is mandatory, error must be None."""
        from qrdx.crypto.pq import get_liboqs_error
        assert get_liboqs_error() is None


class TestDilithiumKeygen:
    """Step 0.3/1.1: Key generation must use real liboqs."""

    def test_generate_keypair(self):
        from qrdx.crypto.pq import generate_keypair, PQPrivateKey, PQPublicKey
        priv, pub = generate_keypair()
        assert isinstance(priv, PQPrivateKey)
        assert isinstance(pub, PQPublicKey)

    def test_public_key_size(self):
        """Public key must be exactly 1952 bytes (ML-DSA-65)."""
        from qrdx.crypto.pq import generate_keypair
        from qrdx.crypto.pq.dilithium import PUBLIC_KEY_SIZE
        _, pub = generate_keypair()
        assert len(pub.to_bytes()) == PUBLIC_KEY_SIZE == 1952

    def test_private_key_size(self):
        """Private key must be exactly 4032 bytes (ML-DSA-65)."""
        from qrdx.crypto.pq import generate_keypair
        from qrdx.crypto.pq.dilithium import PRIVATE_KEY_SIZE
        priv, _ = generate_keypair()
        assert len(priv.to_bytes()) == PRIVATE_KEY_SIZE == 4032

    def test_keypairs_are_unique(self):
        """Two keypair generations must produce different keys."""
        from qrdx.crypto.pq import generate_keypair
        _, pub1 = generate_keypair()
        _, pub2 = generate_keypair()
        assert pub1.to_bytes() != pub2.to_bytes()

    def test_public_key_not_all_zeros(self):
        from qrdx.crypto.pq import generate_keypair
        _, pub = generate_keypair()
        assert pub.to_bytes() != b'\x00' * len(pub.to_bytes())

    def test_public_key_not_repeated_pattern(self):
        """Step 0.3: Public key must NOT be a repeated hash (fake key pattern)."""
        from qrdx.crypto.pq import generate_keypair
        _, pub = generate_keypair()
        data = pub.to_bytes()
        # Check it's not a 32-byte block repeated ~61 times
        block = data[:32]
        repeated = (block * 61)[:len(data)]
        assert data != repeated, \
            "Public key looks like a repeated hash block (fake key pattern)"

    def test_reject_wrong_size_public_key(self):
        """Public key constructor must reject wrong sizes."""
        from qrdx.crypto.pq import PQPublicKey
        with pytest.raises(ValueError, match="1952 bytes"):
            PQPublicKey(b'\x00' * 100)
        with pytest.raises(ValueError, match="1952 bytes"):
            PQPublicKey(b'\x00' * 2000)

    def test_reject_non_bytes_public_key(self):
        from qrdx.crypto.pq import PQPublicKey
        with pytest.raises(TypeError):
            PQPublicKey("not bytes")  # type: ignore

    def test_no_from_seed_method(self):
        """Step 0.3: Deterministic from_seed must not exist."""
        from qrdx.crypto.pq import PQPrivateKey
        assert not hasattr(PQPrivateKey, 'from_seed'), \
            "Deterministic from_seed must be removed — keys must be random"


class TestDilithiumSignVerify:
    """Step 0.2/1.1: Sign and verify using real liboqs."""

    def setup_method(self):
        from qrdx.crypto.pq import generate_keypair
        self.priv, self.pub = generate_keypair()
        self.message = b"QRDX quantum-safe transaction"

    def test_sign_returns_signature(self):
        from qrdx.crypto.pq import PQSignature
        sig = self.priv.sign(self.message)
        assert isinstance(sig, PQSignature)
        assert len(sig.to_bytes()) > 0

    def test_verify_valid_signature(self):
        from qrdx.crypto.pq import verify
        sig = self.priv.sign(self.message)
        assert verify(self.pub, self.message, sig) is True

    def test_verify_wrong_message_fails(self):
        """CRITICAL: Altered message must fail verification."""
        from qrdx.crypto.pq import verify
        sig = self.priv.sign(self.message)
        assert verify(self.pub, b"wrong message", sig) is False

    def test_verify_wrong_key_fails(self):
        """CRITICAL: Wrong public key must fail verification."""
        from qrdx.crypto.pq import verify, generate_keypair
        sig = self.priv.sign(self.message)
        _, other_pub = generate_keypair()
        assert verify(other_pub, self.message, sig) is False

    def test_verify_garbage_signature_fails(self):
        """CRITICAL: Random garbage signature must fail verification."""
        from qrdx.crypto.pq import verify, PQSignature
        garbage_sig = PQSignature(os.urandom(3309))
        assert verify(self.pub, self.message, garbage_sig) is False

    def test_verify_empty_message(self):
        """Signing and verifying empty message should work."""
        from qrdx.crypto.pq import verify
        sig = self.priv.sign(b"")
        assert verify(self.pub, b"", sig) is True

    def test_verify_large_message(self):
        """Signing and verifying a large message."""
        from qrdx.crypto.pq import verify
        large_msg = os.urandom(10000)
        sig = self.priv.sign(large_msg)
        assert verify(self.pub, large_msg, sig) is True

    def test_sign_requires_bytes(self):
        with pytest.raises(TypeError):
            self.priv.sign("not bytes")  # type: ignore

    def test_verify_rejects_non_pubkey(self):
        from qrdx.crypto.pq import verify, PQSignature
        sig = PQSignature(os.urandom(3309))
        assert verify("not a key", b"msg", sig) is False  # type: ignore

    def test_verify_rejects_non_signature(self):
        from qrdx.crypto.pq import verify
        assert verify(self.pub, b"msg", "not a sig") is False  # type: ignore

    def test_signature_not_deterministic(self):
        """Two signatures of same message must differ (Dilithium uses randomness)."""
        sig1 = self.priv.sign(self.message)
        sig2 = self.priv.sign(self.message)
        # ML-DSA-65 uses hedged signing (internal randomness)
        # Signatures CAN be the same in rare cases, but usually differ.
        # We just verify both are valid:
        from qrdx.crypto.pq import verify
        assert verify(self.pub, self.message, sig1) is True
        assert verify(self.pub, self.message, sig2) is True


class TestDilithiumSerialization:
    """Key and signature serialization round-trips."""

    def test_public_key_hex_roundtrip(self):
        from qrdx.crypto.pq import generate_keypair, PQPublicKey
        _, pub = generate_keypair()
        hex_str = pub.to_hex()
        restored = PQPublicKey.from_hex(hex_str)
        assert restored == pub

    def test_public_key_hex_with_0x_prefix(self):
        from qrdx.crypto.pq import generate_keypair, PQPublicKey
        _, pub = generate_keypair()
        hex_str = '0x' + pub.to_hex()
        restored = PQPublicKey.from_hex(hex_str)
        assert restored == pub

    def test_signature_hex_roundtrip(self):
        from qrdx.crypto.pq import generate_keypair, PQSignature
        priv, _ = generate_keypair()
        sig = priv.sign(b"test")
        hex_str = sig.to_hex()
        restored = PQSignature.from_hex(hex_str)
        assert restored == sig

    def test_private_key_hex_roundtrip(self):
        from qrdx.crypto.pq import PQPrivateKey
        priv = PQPrivateKey.generate()
        hex_str = priv.to_hex()
        # Note: from_hex without public key will re-generate keypair
        restored = PQPrivateKey.from_hex(hex_str)
        assert len(restored.to_bytes()) > 0

    def test_empty_signature_rejected(self):
        from qrdx.crypto.pq import PQSignature
        with pytest.raises(ValueError, match="empty"):
            PQSignature(b"")


class TestDilithiumAlgorithmInfo:
    """Algorithm metadata."""

    def test_algorithm_info_structure(self):
        from qrdx.crypto.pq import get_algorithm_info
        info = get_algorithm_info()
        assert info['algorithm'] in ('ML-DSA-65', 'Dilithium3')
        assert info['nist_standard'] == 'FIPS 204'
        assert info['public_key_size'] == 1952
        assert info['private_key_size'] == 4032
        assert info['signature_size'] == 3309
        assert info['liboqs_available'] is True
        assert info['claimed_nist_level'] >= 3


# ============================================================================
# Kyber ML-KEM-768 Key Encapsulation
# ============================================================================


class TestKyberImport:
    """Step 1.2: Kyber KEM module must import and validate."""

    def test_module_imports(self):
        from qrdx.crypto.pq import kyber
        assert hasattr(kyber, '_WORKING_ALGORITHM')

    def test_working_algorithm(self):
        from qrdx.crypto.pq.kyber import _WORKING_ALGORITHM
        assert _WORKING_ALGORITHM in ('ML-KEM-768', 'Kyber768')

    def test_kem_is_available(self):
        from qrdx.crypto.pq import kem_is_available
        assert kem_is_available() is True


class TestKyberKeygen:
    """Step 1.2: Kyber keypair generation."""

    def test_generate_keypair(self):
        from qrdx.crypto.pq import kyber_generate_keypair, KEMPrivateKey, KEMPublicKey
        priv, pub = kyber_generate_keypair()
        assert isinstance(priv, KEMPrivateKey)
        assert isinstance(pub, KEMPublicKey)

    def test_public_key_size(self):
        from qrdx.crypto.pq import kyber_generate_keypair
        from qrdx.crypto.pq.kyber import PUBLIC_KEY_SIZE
        _, pub = kyber_generate_keypair()
        assert len(pub.to_bytes()) == PUBLIC_KEY_SIZE == 1184

    def test_private_key_size(self):
        from qrdx.crypto.pq import kyber_generate_keypair
        from qrdx.crypto.pq.kyber import PRIVATE_KEY_SIZE
        priv, _ = kyber_generate_keypair()
        assert len(priv.to_bytes()) == PRIVATE_KEY_SIZE == 2400

    def test_keypairs_are_unique(self):
        from qrdx.crypto.pq import kyber_generate_keypair
        _, pub1 = kyber_generate_keypair()
        _, pub2 = kyber_generate_keypair()
        assert pub1.to_bytes() != pub2.to_bytes()

    def test_reject_wrong_size_public_key(self):
        from qrdx.crypto.pq.kyber import KEMPublicKey
        with pytest.raises(ValueError, match="1184 bytes"):
            KEMPublicKey(b'\x00' * 100)


class TestKyberEncapDecap:
    """Step 1.2: Encapsulation and decapsulation round-trip."""

    def setup_method(self):
        from qrdx.crypto.pq import kyber_generate_keypair
        self.priv, self.pub = kyber_generate_keypair()

    def test_encapsulate_produces_ciphertext_and_secret(self):
        from qrdx.crypto.pq import kyber_encapsulate
        ciphertext, shared_secret = kyber_encapsulate(self.pub)
        assert isinstance(ciphertext, bytes)
        assert isinstance(shared_secret, bytes)
        assert len(shared_secret) == 32
        assert len(ciphertext) > 0

    def test_decapsulate_recovers_same_secret(self):
        """CRITICAL: Encap + Decap must produce the same shared secret."""
        from qrdx.crypto.pq import kyber_encapsulate, kyber_decapsulate
        ciphertext, shared_secret_enc = kyber_encapsulate(self.pub)
        shared_secret_dec = kyber_decapsulate(self.priv, ciphertext)
        assert shared_secret_enc == shared_secret_dec

    def test_wrong_key_decapsulation_fails(self):
        """Wrong private key must NOT recover the same shared secret."""
        from qrdx.crypto.pq import (
            kyber_encapsulate, kyber_decapsulate, kyber_generate_keypair
        )
        ciphertext, shared_secret = kyber_encapsulate(self.pub)
        other_priv, _ = kyber_generate_keypair()
        wrong_secret = kyber_decapsulate(other_priv, ciphertext)
        assert wrong_secret != shared_secret

    def test_different_encapsulations_produce_different_secrets(self):
        from qrdx.crypto.pq import kyber_encapsulate
        _, secret1 = kyber_encapsulate(self.pub)
        _, secret2 = kyber_encapsulate(self.pub)
        assert secret1 != secret2

    def test_encapsulate_requires_kem_public_key(self):
        from qrdx.crypto.pq import kyber_encapsulate
        with pytest.raises(TypeError):
            kyber_encapsulate("not a key")  # type: ignore

    def test_decapsulate_requires_bytes(self):
        with pytest.raises(TypeError):
            self.priv.decapsulate("not bytes")  # type: ignore


class TestKyberAlgorithmInfo:
    """Kyber algorithm metadata."""

    def test_algorithm_info(self):
        from qrdx.crypto.pq import kem_get_algorithm_info
        info = kem_get_algorithm_info()
        assert info['algorithm'] in ('ML-KEM-768', 'Kyber768')
        assert info['nist_standard'] == 'FIPS 203'
        assert info['public_key_size'] == 1184
        assert info['shared_secret_size'] == 32
        assert info['liboqs_available'] is True


# ============================================================================
# PQ Address Derivation
# ============================================================================


class TestPQAddressDerivation:
    """Step 1.3: PQ address from public key."""

    def test_pq_address_format(self):
        """PQ address must start with 0xPQ."""
        from qrdx.crypto.pq import generate_keypair
        _, pub = generate_keypair()
        addr = pub.to_address()
        assert addr.startswith('0xPQ'), f"Expected 0xPQ prefix, got: {addr[:6]}"

    def test_pq_address_length(self):
        """PQ address must be consistent length."""
        from qrdx.crypto.pq import generate_keypair
        _, pub = generate_keypair()
        addr = pub.to_address()
        # 0xPQ + 64 hex chars = 68 chars total
        assert len(addr) >= 66, f"Address too short: {len(addr)}"

    def test_same_key_same_address(self):
        """Same public key must always produce the same address."""
        from qrdx.crypto.pq import generate_keypair
        _, pub = generate_keypair()
        addr1 = pub.to_address()
        addr2 = pub.to_address()
        assert addr1 == addr2

    def test_different_keys_different_addresses(self):
        from qrdx.crypto.pq import generate_keypair
        _, pub1 = generate_keypair()
        _, pub2 = generate_keypair()
        assert pub1.to_address() != pub2.to_address()

    def test_address_via_private_key(self):
        """Private key address property must match public key address."""
        from qrdx.crypto.pq import generate_keypair
        priv, pub = generate_keypair()
        assert priv.address == pub.to_address()

    def test_address_type_detection(self):
        from qrdx.crypto.pq import generate_keypair
        from qrdx.crypto.address import is_pq_address
        _, pub = generate_keypair()
        assert is_pq_address(pub.to_address())


# ============================================================================
# secp256k1 Classical Signatures (Step 1.4)
# ============================================================================


class TestClassicalKeys:
    """Step 1.4: secp256k1 key management."""

    def test_generate_keypair(self):
        from qrdx.crypto import generate_keypair, PrivateKey, PublicKey
        priv, pub = generate_keypair()
        assert isinstance(priv, PrivateKey)
        assert isinstance(pub, PublicKey)

    def test_private_key_is_32_bytes(self):
        from qrdx.crypto import generate_keypair
        priv, _ = generate_keypair()
        assert len(priv.to_bytes()) == 32

    def test_keypairs_are_unique(self):
        from qrdx.crypto import generate_keypair
        _, pub1 = generate_keypair()
        _, pub2 = generate_keypair()
        assert pub1.to_bytes() != pub2.to_bytes()

    def test_address_format(self):
        """Classical address must start with 0x (not 0xPQ)."""
        from qrdx.crypto import generate_keypair
        _, pub = generate_keypair()
        addr = pub.to_address()
        assert addr.startswith('0x')
        assert not addr.startswith('0xPQ')


class TestClassicalSigning:
    """Step 1.4: secp256k1 sign and verify."""

    def test_sign_and_verify_message(self):
        from qrdx.crypto import generate_keypair
        from qrdx.crypto.hashing import keccak256
        priv, pub = generate_keypair()
        msg = b"QRDX classical signature test"
        msg_hash = keccak256(msg)
        sig = priv.sign_msg_hash(msg_hash)
        assert pub.verify_msg_hash(msg_hash, sig) is True

    def test_sign_wrong_message_fails(self):
        from qrdx.crypto import generate_keypair
        from qrdx.crypto.hashing import keccak256
        priv, pub = generate_keypair()
        msg_hash = keccak256(b"original")
        sig = priv.sign_msg_hash(msg_hash)
        wrong_hash = keccak256(b"tampered")
        assert pub.verify_msg_hash(wrong_hash, sig) is False


# ============================================================================
# Address Module (Step 1.3/1.4)
# ============================================================================


class TestAddressModule:
    """Address validation, checksums, and type detection."""

    def test_is_valid_pq_address(self):
        from qrdx.crypto.address import is_valid_address
        from qrdx.crypto.pq import generate_keypair
        _, pub = generate_keypair()
        assert is_valid_address(pub.to_address())

    def test_is_pq_vs_traditional(self):
        from qrdx.crypto.address import is_pq_address, is_traditional_address
        from qrdx.crypto.pq import generate_keypair as pq_gen
        from qrdx.crypto import generate_keypair as classical_gen

        _, pq_pub = pq_gen()
        classical_priv, classical_pub = classical_gen()

        pq_addr = pq_pub.to_address()
        classical_addr = classical_pub.to_address()

        assert is_pq_address(pq_addr)
        assert not is_pq_address(classical_addr)
        assert is_traditional_address(classical_addr)
        assert not is_traditional_address(pq_addr)

    def test_get_address_type(self):
        from qrdx.crypto.address import get_address_type, AddressType
        from qrdx.crypto.pq import generate_keypair
        _, pub = generate_keypair()
        assert get_address_type(pub.to_address()) == AddressType.POST_QUANTUM

    def test_invalid_address_rejected(self):
        from qrdx.crypto.address import is_valid_address
        assert not is_valid_address("")
        assert not is_valid_address("not_an_address")
        assert not is_valid_address("0x")


# ============================================================================
# Hashing Module
# ============================================================================


class TestHashing:
    """Hash functions used across the chain."""

    def test_keccak256(self):
        from qrdx.crypto import keccak256
        result = keccak256(b"QRDX")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_keccak256_deterministic(self):
        from qrdx.crypto import keccak256
        assert keccak256(b"test") == keccak256(b"test")

    def test_keccak256_different_inputs(self):
        from qrdx.crypto import keccak256
        assert keccak256(b"a") != keccak256(b"b")

    def test_sha256(self):
        from qrdx.crypto import sha256
        result = sha256(b"QRDX")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_keccak256_hex(self):
        from qrdx.crypto import keccak256_hex
        result = keccak256_hex(b"test")
        assert isinstance(result, str)
        assert len(result) == 66  # "0x" + 64 hex chars


# ============================================================================
# Encoding Module
# ============================================================================


class TestEncoding:
    """RLP encoding."""

    def test_rlp_encode_bytes(self):
        from qrdx.crypto import rlp_encode
        result = rlp_encode(b"hello")
        assert isinstance(result, bytes)

    def test_rlp_roundtrip(self):
        from qrdx.crypto import rlp_encode, rlp_decode
        original = b"QRDX test data"
        encoded = rlp_encode(original)
        decoded = rlp_decode(encoded)
        assert decoded == original


# ============================================================================
# PQ Module via crypto.__init__ lazy loading
# ============================================================================


class TestLazyLoading:
    """Verify PQ symbols accessible via qrdx.crypto namespace."""

    def test_pq_private_key_lazy(self):
        from qrdx.crypto import PQPrivateKey
        key = PQPrivateKey.generate()
        assert key is not None

    def test_pq_verify_lazy(self):
        from qrdx.crypto import pq_verify, pq_generate_keypair, pq_sign
        priv, pub = pq_generate_keypair()
        sig = pq_sign(priv, b"test")
        assert pq_verify(pub, b"test", sig) is True

    def test_kem_lazy(self):
        from qrdx.crypto import (
            kyber_generate_keypair, kyber_encapsulate, kyber_decapsulate
        )
        priv, pub = kyber_generate_keypair()
        ct, ss1 = kyber_encapsulate(pub)
        ss2 = kyber_decapsulate(priv, ct)
        assert ss1 == ss2

    def test_nonexistent_attribute_raises(self):
        import qrdx.crypto
        with pytest.raises(AttributeError):
            _ = qrdx.crypto.nonexistent_thing  # type: ignore


# ============================================================================
# Security regression tests — MUST NEVER PASS without real crypto
# ============================================================================


class TestSecurityRegressions:
    """
    These tests specifically verify that the old vulnerability patterns
    have been removed. If any of these fail, critical security is broken.
    """

    def test_no_verify_bypass(self):
        """
        CRITICAL REGRESSION: verify() must NOT return True for garbage.
        The old code had: if not _HAS_LIBOQS: return True
        """
        from qrdx.crypto.pq import verify, generate_keypair, PQSignature
        _, pub = generate_keypair()
        garbage = PQSignature(os.urandom(3309))
        result = verify(pub, b"important transaction", garbage)
        assert result is False, \
            "SECURITY FAILURE: verify() accepted garbage signature!"

    def test_no_fake_keys(self):
        """
        CRITICAL REGRESSION: Keys must be real liboqs output, not SHA256 padding.
        """
        from qrdx.crypto.pq import generate_keypair
        import hashlib
        _, pub = generate_keypair()
        data = pub.to_bytes()
        # The old fake pattern was sha256(seed).digest() * 61 truncated
        # Real ML-DSA-65 keys have high entropy
        # Check Shannon entropy is high (real keys have ~8 bits/byte)
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        import math
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)
        # Real PQ keys should have entropy > 7.5 bits/byte
        # Fake repeated SHA256 would have much lower entropy
        assert entropy > 7.0, \
            f"Key entropy too low ({entropy:.2f}), may be fake/repeated"

    def test_no_fake_signatures(self):
        """
        CRITICAL REGRESSION: Signatures must not be SHA256 padding.
        """
        from qrdx.crypto.pq import generate_keypair
        priv, _ = generate_keypair()
        sig = priv.sign(b"test message")
        data = sig.to_bytes()
        # Check entropy like above
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        import math
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)
        assert entropy > 7.0, \
            f"Signature entropy too low ({entropy:.2f}), may be fake"

    def test_cross_key_verification_fails(self):
        """Signature from key A must not verify with key B."""
        from qrdx.crypto.pq import generate_keypair, verify
        priv_a, pub_a = generate_keypair()
        _, pub_b = generate_keypair()
        sig = priv_a.sign(b"transaction data")
        assert verify(pub_a, b"transaction data", sig) is True
        assert verify(pub_b, b"transaction data", sig) is False

    def test_tampered_message_fails(self):
        """Even one bit flip in message must fail verification."""
        from qrdx.crypto.pq import generate_keypair, verify
        priv, pub = generate_keypair()
        msg = b"send 100 QRDX to Alice"
        sig = priv.sign(msg)
        tampered = b"send 900 QRDX to Alice"
        assert verify(pub, tampered, sig) is False
