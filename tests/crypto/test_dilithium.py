"""
Tests for CRYSTALS-Dilithium post-quantum signatures.

Tests key generation, signing, verification, and error handling.
"""

import pytest

from trinity.crypto.pq.dilithium import (
    DilithiumPrivateKey,
    DilithiumPublicKey,
    DILITHIUM_VARIANT,
    DILITHIUM_PUBKEY_SIZE,
    DILITHIUM_PRIVKEY_SIZE,
    DILITHIUM_SIGNATURE_SIZE,
)
from trinity.crypto.pq.exceptions import (
    InvalidPublicKey,
    InvalidPrivateKey,
    DilithiumError,
)


class TestDilithiumKeyGeneration:
    """Test Dilithium key pair generation"""
    
    def test_generate_key_pair(self):
        """Test basic key generation"""
        privkey = DilithiumPrivateKey.generate()
        pubkey = privkey.public_key()
        
        assert isinstance(privkey, DilithiumPrivateKey)
        assert isinstance(pubkey, DilithiumPublicKey)
    
    def test_key_sizes(self):
        """Test that generated keys have correct sizes"""
        privkey = DilithiumPrivateKey.generate()
        pubkey = privkey.public_key()
        
        assert len(privkey.to_bytes()) == DILITHIUM_PRIVKEY_SIZE
        assert len(pubkey.to_bytes()) == DILITHIUM_PUBKEY_SIZE
    
    def test_key_pair_consistency(self):
        """Test that public key derived from private key is consistent"""
        privkey = DilithiumPrivateKey.generate()
        pubkey1 = privkey.public_key()
        pubkey2 = privkey.public_key()
        
        assert pubkey1.to_bytes() == pubkey2.to_bytes()


class TestDilithiumSigning:
    """Test Dilithium signature operations"""
    
    def test_sign_and_verify(self):
        """Test basic sign and verify"""
        message = b"hello world"
        privkey = DilithiumPrivateKey.generate()
        pubkey = privkey.public_key()
        
        signature = privkey.sign(message)
        
        assert len(signature) == DILITHIUM_SIGNATURE_SIZE
        assert pubkey.verify(message, signature) is True
    
    def test_signature_size(self):
        """Test that signatures have correct size"""
        message = b"test message"
        privkey = DilithiumPrivateKey.generate()
        
        signature = privkey.sign(message)
        
        assert len(signature) == DILITHIUM_SIGNATURE_SIZE
    
    def test_deterministic_signing(self):
        """Test that signing same message produces same signature (deterministic)"""
        message = b"deterministic test"
        privkey = DilithiumPrivateKey.generate()
        
        sig1 = privkey.sign(message)
        sig2 = privkey.sign(message)
        
        # Dilithium in liboqs is deterministic
        assert sig1 == sig2
    
    def test_different_messages_different_signatures(self):
        """Test that different messages produce different signatures"""
        privkey = DilithiumPrivateKey.generate()
        
        sig1 = privkey.sign(b"message 1")
        sig2 = privkey.sign(b"message 2")
        
        assert sig1 != sig2
    
    def test_invalid_signature_fails(self):
        """Test that invalid signature fails verification"""
        message = b"test"
        privkey = DilithiumPrivateKey.generate()
        pubkey = privkey.public_key()
        
        signature = privkey.sign(message)
        
        # Flip a bit in signature
        bad_signature = bytearray(signature)
        bad_signature[0] ^= 0x01
        bad_signature = bytes(bad_signature)
        
        assert pubkey.verify(message, bad_signature) is False
    
    def test_wrong_message_fails_verification(self):
        """Test that signature for different message fails"""
        privkey = DilithiumPrivateKey.generate()
        pubkey = privkey.public_key()
        
        signature = privkey.sign(b"original message")
        
        assert pubkey.verify(b"different message", signature) is False
    
    def test_wrong_public_key_fails(self):
        """Test that signature fails with wrong public key"""
        message = b"test"
        
        privkey1 = DilithiumPrivateKey.generate()
        privkey2 = DilithiumPrivateKey.generate()
        
        signature = privkey1.sign(message)
        
        assert privkey2.public_key().verify(message, signature) is False


class TestDilithiumSerialization:
    """Test key serialization and deserialization"""
    
    def test_private_key_serialization(self):
        """Test private key to_bytes and from_bytes"""
        privkey1 = DilithiumPrivateKey.generate()
        key_bytes = privkey1.to_bytes()
        privkey2 = DilithiumPrivateKey.from_bytes(key_bytes)
        
        # Both keys should produce same signatures
        message = b"test"
        sig1 = privkey1.sign(message)
        sig2 = privkey2.sign(message)
        
        assert sig1 == sig2
    
    def test_public_key_serialization(self):
        """Test public key to_bytes and from_bytes"""
        privkey = DilithiumPrivateKey.generate()
        pubkey1 = privkey.public_key()
        
        pubkey_bytes = pubkey1.to_bytes()
        pubkey2 = DilithiumPublicKey.from_bytes(pubkey_bytes)
        
        # Both should verify same signature
        message = b"test"
        signature = privkey.sign(message)
        
        assert pubkey1.verify(message, signature) is True
        assert pubkey2.verify(message, signature) is True
    
    def test_invalid_private_key_size(self):
        """Test that invalid private key size raises error"""
        with pytest.raises(InvalidPrivateKey):
            DilithiumPrivateKey.from_bytes(b"too_short")
    
    def test_invalid_public_key_size(self):
        """Test that invalid public key size raises error"""
        with pytest.raises(InvalidPublicKey):
            DilithiumPublicKey.from_bytes(b"too_short")


class TestDilithiumEdgeCases:
    """Test edge cases and error conditions"""
    
    def test_empty_message(self):
        """Test signing empty message"""
        privkey = DilithiumPrivateKey.generate()
        pubkey = privkey.public_key()
        
        signature = privkey.sign(b"")
        
        assert pubkey.verify(b"", signature) is True
    
    def test_large_message(self):
        """Test signing large message"""
        large_message = b"x" * 1_000_000  # 1 MB
        privkey = DilithiumPrivateKey.generate()
        pubkey = privkey.public_key()
        
        signature = privkey.sign(large_message)
        
        assert pubkey.verify(large_message, signature) is True
    
    def test_empty_signature_fails(self):
        """Test that empty signature fails verification"""
        privkey = DilithiumPrivateKey.generate()
        pubkey = privkey.public_key()
        
        assert pubkey.verify(b"message", b"") is False
    
    def test_wrong_size_signature_fails(self):
        """Test that wrong size signature fails"""
        privkey = DilithiumPrivateKey.generate()
        pubkey = privkey.public_key()
        
        # Too short signature
        assert pubkey.verify(b"message", b"x" * 100) is False


class TestDilithiumConstants:
    """Test that constants match expected values"""
    
    def test_variant(self):
        """Test that default variant is Dilithium5"""
        assert DILITHIUM_VARIANT == "Dilithium5"
    
    def test_key_size_constants(self):
        """Test that size constants are correct for Dilithium5"""
        assert DILITHIUM_PUBKEY_SIZE == 2592
        assert DILITHIUM_PRIVKEY_SIZE == 4864
        assert DILITHIUM_SIGNATURE_SIZE == 4595
