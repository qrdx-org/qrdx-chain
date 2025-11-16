"""
Tests for CRYSTALS-Kyber post-quantum key encapsulation.

Tests key generation, encapsulation, decapsulation, and error handling.
"""

import pytest

from trinity.crypto.pq.kyber import (
    KyberPrivateKey,
    KyberPublicKey,
    KYBER_VARIANT,
    KYBER_PUBKEY_SIZE,
    KYBER_PRIVKEY_SIZE,
    KYBER_CIPHERTEXT_SIZE,
    KYBER_SHARED_SECRET_SIZE,
)
from trinity.crypto.pq.exceptions import (
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidCiphertext,
    KyberError,
)


class TestKyberKeyGeneration:
    """Test Kyber key pair generation"""
    
    def test_generate_key_pair(self):
        """Test basic key generation"""
        privkey = KyberPrivateKey.generate()
        pubkey = privkey.public_key()
        
        assert isinstance(privkey, KyberPrivateKey)
        assert isinstance(pubkey, KyberPublicKey)
    
    def test_key_sizes(self):
        """Test that generated keys have correct sizes"""
        privkey = KyberPrivateKey.generate()
        pubkey = privkey.public_key()
        
        assert len(privkey.to_bytes()) == KYBER_PRIVKEY_SIZE
        assert len(pubkey.to_bytes()) == KYBER_PUBKEY_SIZE
    
    def test_key_pair_consistency(self):
        """Test that public key derived from private key is consistent"""
        privkey = KyberPrivateKey.generate()
        pubkey1 = privkey.public_key()
        pubkey2 = privkey.public_key()
        
        assert pubkey1.to_bytes() == pubkey2.to_bytes()


class TestKyberKEM:
    """Test Kyber key encapsulation mechanism"""
    
    def test_encapsulate_decapsulate(self):
        """Test basic encapsulate and decapsulate"""
        privkey = KyberPrivateKey.generate()
        pubkey = privkey.public_key()
        
        # Encapsulate
        ciphertext, shared_secret1 = pubkey.encapsulate()
        
        # Decapsulate
        shared_secret2 = privkey.decapsulate(ciphertext)
        
        # Secrets should match
        assert shared_secret1 == shared_secret2
    
    def test_ciphertext_size(self):
        """Test that ciphertext has correct size"""
        privkey = KyberPrivateKey.generate()
        pubkey = privkey.public_key()
        
        ciphertext, _ = pubkey.encapsulate()
        
        assert len(ciphertext) == KYBER_CIPHERTEXT_SIZE
    
    def test_shared_secret_size(self):
        """Test that shared secret is 32 bytes"""
        privkey = KyberPrivateKey.generate()
        pubkey = privkey.public_key()
        
        _, shared_secret = pubkey.encapsulate()
        
        assert len(shared_secret) == KYBER_SHARED_SECRET_SIZE
        assert len(shared_secret) == 32  # Always 32 bytes
    
    def test_different_encapsulations_different_secrets(self):
        """Test that multiple encapsulations produce different secrets"""
        privkey = KyberPrivateKey.generate()
        pubkey = privkey.public_key()
        
        ct1, secret1 = pubkey.encapsulate()
        ct2, secret2 = pubkey.encapsulate()
        
        # Different ciphertexts and secrets (randomized)
        assert ct1 != ct2
        assert secret1 != secret2
    
    def test_wrong_private_key_gives_different_secret(self):
        """Test that wrong private key produces different secret"""
        privkey1 = KyberPrivateKey.generate()
        privkey2 = KyberPrivateKey.generate()
        
        pubkey1 = privkey1.public_key()
        
        ciphertext, secret1 = pubkey1.encapsulate()
        
        # Try to decapsulate with wrong key
        secret2 = privkey2.decapsulate(ciphertext)
        
        # Secrets should be different
        assert secret1 != secret2
    
    def test_invalid_ciphertext_size(self):
        """Test that invalid ciphertext size raises error"""
        privkey = KyberPrivateKey.generate()
        
        with pytest.raises(InvalidCiphertext):
            privkey.decapsulate(b"too_short")
    
    def test_corrupted_ciphertext(self):
        """Test that corrupted ciphertext produces different secret"""
        privkey = KyberPrivateKey.generate()
        pubkey = privkey.public_key()
        
        ciphertext, secret1 = pubkey.encapsulate()
        
        # Corrupt ciphertext
        bad_ciphertext = bytearray(ciphertext)
        bad_ciphertext[0] ^= 0x01
        bad_ciphertext = bytes(bad_ciphertext)
        
        # Decapsulation should succeed but give different secret
        # (Kyber has implicit rejection - doesn't fail, gives pseudo-random secret)
        secret2 = privkey.decapsulate(bad_ciphertext)
        
        # Secrets should be different
        assert secret1 != secret2


class TestKyberSerialization:
    """Test key serialization and deserialization"""
    
    def test_private_key_serialization(self):
        """Test private key to_bytes and from_bytes"""
        privkey1 = KyberPrivateKey.generate()
        key_bytes = privkey1.to_bytes()
        privkey2 = KyberPrivateKey.from_bytes(key_bytes)
        
        # Both keys should decapsulate to same secret
        pubkey = privkey1.public_key()
        ciphertext, _ = pubkey.encapsulate()
        
        secret1 = privkey1.decapsulate(ciphertext)
        secret2 = privkey2.decapsulate(ciphertext)
        
        assert secret1 == secret2
    
    def test_public_key_serialization(self):
        """Test public key to_bytes and from_bytes"""
        privkey = KyberPrivateKey.generate()
        pubkey1 = privkey.public_key()
        
        pubkey_bytes = pubkey1.to_bytes()
        pubkey2 = KyberPublicKey.from_bytes(pubkey_bytes)
        
        # Both should encapsulate successfully
        ct1, secret1 = pubkey1.encapsulate()
        ct2, secret2 = pubkey2.encapsulate()
        
        # Should be able to decapsulate both
        dec_secret1 = privkey.decapsulate(ct1)
        dec_secret2 = privkey.decapsulate(ct2)
        
        assert dec_secret1 == secret1
        assert dec_secret2 == secret2
    
    def test_invalid_private_key_size(self):
        """Test that invalid private key size raises error"""
        with pytest.raises(InvalidPrivateKey):
            KyberPrivateKey.from_bytes(b"too_short")
    
    def test_invalid_public_key_size(self):
        """Test that invalid public key size raises error"""
        with pytest.raises(InvalidPublicKey):
            KyberPublicKey.from_bytes(b"too_short")


class TestKyberEdgeCases:
    """Test edge cases and error conditions"""
    
    def test_multiple_decapsulations(self):
        """Test that same ciphertext can be decapsulated multiple times"""
        privkey = KyberPrivateKey.generate()
        pubkey = privkey.public_key()
        
        ciphertext, secret1 = pubkey.encapsulate()
        
        secret2 = privkey.decapsulate(ciphertext)
        secret3 = privkey.decapsulate(ciphertext)
        
        # All should be the same
        assert secret1 == secret2 == secret3
    
    def test_empty_ciphertext_fails(self):
        """Test that empty ciphertext raises error"""
        privkey = KyberPrivateKey.generate()
        
        with pytest.raises(InvalidCiphertext):
            privkey.decapsulate(b"")


class TestKyberConstants:
    """Test that constants match expected values"""
    
    def test_variant(self):
        """Test that default variant is Kyber1024"""
        assert KYBER_VARIANT == "Kyber1024"
    
    def test_key_size_constants(self):
        """Test that size constants are correct for Kyber1024"""
        assert KYBER_PUBKEY_SIZE == 1568
        assert KYBER_PRIVKEY_SIZE == 3168
        assert KYBER_CIPHERTEXT_SIZE == 1568
        assert KYBER_SHARED_SECRET_SIZE == 32
