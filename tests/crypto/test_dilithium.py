"""
Unit tests for CRYSTALS-Dilithium implementation.
"""

import pytest
from eth.crypto.dilithium import (
    DilithiumPrivateKey,
    DilithiumPublicKey,
    generate_dilithium_keypair,
    verify_dilithium_signature,
    DILITHIUM_PUBLIC_KEY_SIZE,
    DILITHIUM_SECRET_KEY_SIZE,
    DILITHIUM_SIGNATURE_SIZE,
)
from eth_utils import ValidationError


class TestDilithiumKeypairGeneration:
    """Test Dilithium key pair generation."""
    
    def test_generate_keypair_returns_correct_types(self):
        """Generated keys should be correct types."""
        private_key, public_key = generate_dilithium_keypair()
        
        assert isinstance(private_key, DilithiumPrivateKey)
        assert isinstance(public_key, DilithiumPublicKey)
    
    def test_generated_keys_have_correct_sizes(self):
        """Generated keys should have correct byte sizes."""
        private_key, public_key = generate_dilithium_keypair()
        
        assert len(private_key.to_bytes()) == DILITHIUM_SECRET_KEY_SIZE
        assert len(public_key.to_bytes()) == DILITHIUM_PUBLIC_KEY_SIZE
    
    def test_multiple_generations_produce_different_keys(self):
        """Each key generation should produce unique keys."""
        _, pub1 = generate_dilithium_keypair()
        _, pub2 = generate_dilithium_keypair()
        
        assert pub1 != pub2
        assert pub1.to_bytes() != pub2.to_bytes()


class TestDilithiumSigning:
    """Test Dilithium signature operations."""
    
    def test_sign_and_verify_message(self):
        """Basic sign and verify should work."""
        private_key, public_key = generate_dilithium_keypair()
        message = b"Hello, quantum-resistant world!"
        
        signature = private_key.sign(message)
        assert len(signature) == DILITHIUM_SIGNATURE_SIZE
        
        is_valid = public_key.verify(message, signature)
        assert is_valid is True
    
    def test_signature_verification_fails_for_wrong_message(self):
        """Signature should not verify for different message."""
        private_key, public_key = generate_dilithium_keypair()
        message1 = b"Original message"
        message2 = b"Modified message"
        
        signature = private_key.sign(message1)
        is_valid = public_key.verify(message2, signature)
        
        assert is_valid is False
    
    def test_signature_verification_fails_for_wrong_public_key(self):
        """Signature should not verify with wrong public key."""
        private_key1, _ = generate_dilithium_keypair()
        _, public_key2 = generate_dilithium_keypair()
        message = b"Test message"
        
        signature = private_key1.sign(message)
        is_valid = public_key2.verify(message, signature)
        
        assert is_valid is False
    
    def test_sign_empty_message(self):
        """Should be able to sign empty message."""
        private_key, public_key = generate_dilithium_keypair()
        message = b""
        
        signature = private_key.sign(message)
        is_valid = public_key.verify(message, signature)
        
        assert is_valid is True
    
    def test_sign_large_message(self):
        """Should be able to sign large messages."""
        private_key, public_key = generate_dilithium_keypair()
        message = b"x" * 10000  # 10KB message
        
        signature = private_key.sign(message)
        is_valid = public_key.verify(message, signature)
        
        assert is_valid is True


class TestDilithiumPublicKey:
    """Test DilithiumPublicKey class."""
    
    def test_create_public_key_from_bytes(self):
        """Should create public key from bytes."""
        _, public_key = generate_dilithium_keypair()
        pub_bytes = public_key.to_bytes()
        
        reconstructed = DilithiumPublicKey(pub_bytes)
        assert reconstructed.to_bytes() == pub_bytes
    
    def test_invalid_public_key_size_raises_error(self):
        """Invalid key size should raise ValidationError."""
        with pytest.raises(ValidationError):
            DilithiumPublicKey(b"invalid_key_too_short")
    
    def test_public_key_equality(self):
        """Public keys should be comparable."""
        _, pub1 = generate_dilithium_keypair()
        pub2 = DilithiumPublicKey(pub1.to_bytes())
        
        assert pub1 == pub2
    
    def test_public_key_to_hex(self):
        """Public key should convert to hex string."""
        _, public_key = generate_dilithium_keypair()
        hex_str = public_key.to_hex()
        
        assert isinstance(hex_str, str)
        assert len(hex_str) == DILITHIUM_PUBLIC_KEY_SIZE * 2  # 2 hex chars per byte


class TestDilithiumPrivateKey:
    """Test DilithiumPrivateKey class."""
    
    def test_create_private_key_from_bytes(self):
        """Should create private key from bytes."""
        private_key, public_key = generate_dilithium_keypair()
        priv_bytes = private_key.to_bytes()
        pub_bytes = public_key.to_bytes()
        
        reconstructed = DilithiumPrivateKey(priv_bytes, pub_bytes)
        assert reconstructed.to_bytes() == priv_bytes
    
    def test_invalid_private_key_size_raises_error(self):
        """Invalid key size should raise ValidationError."""
        with pytest.raises(ValidationError):
            DilithiumPrivateKey(b"invalid_key")
    
    def test_get_public_key_from_private_key(self):
        """Should be able to get public key from private key."""
        private_key, expected_public_key = generate_dilithium_keypair()
        
        derived_public_key = private_key.public_key()
        assert derived_public_key == expected_public_key


class TestDilithiumConvenienceFunctions:
    """Test convenience functions."""
    
    def test_verify_dilithium_signature_function(self):
        """Convenience function should work."""
        private_key, public_key = generate_dilithium_keypair()
        message = b"Test message"
        
        signature = private_key.sign(message)
        is_valid = verify_dilithium_signature(message, signature, public_key.to_bytes())
        
        assert is_valid is True
    
    def test_verify_invalid_signature(self):
        """Convenience function should handle invalid signatures."""
        private_key, public_key = generate_dilithium_keypair()
        message = b"Test message"
        
        signature = private_key.sign(message)
        tampered_signature = signature[:-1] + b'\x00'  # Tamper with last byte
        
        is_valid = verify_dilithium_signature(message, tampered_signature, public_key.to_bytes())
        assert is_valid is False
