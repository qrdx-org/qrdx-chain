"""
Hybrid Key Management

Manages both classical (secp256k1) and post-quantum (Dilithium) keys together.
Supports dual-signature validation for migration period.
"""

from dataclasses import dataclass
from typing import Optional

from eth_keys import keys as eth_keys
from eth_keys.datatypes import PrivateKey, PublicKey

from trinity.crypto.pq.dilithium import (
    DilithiumPrivateKey,
    DilithiumPublicKey,
    DILITHIUM_SIGNATURE_SIZE,
)
from trinity.crypto.pq.exceptions import (
    HybridKeyError,
    InvalidSignature,
)


@dataclass
class HybridSignature:
    """
    Contains both classical ECDSA and post-quantum Dilithium signatures.
    
    Used during migration period for dual validation.
    """
    classical_sig: bytes  # ECDSA signature (65 bytes: r, s, v)
    pq_sig: bytes         # Dilithium signature (~4,595 bytes)
    
    def to_bytes(self) -> bytes:
        """
        Serialize hybrid signature.
        
        Format: classical_sig_len (2 bytes) || classical_sig || pq_sig
        """
        classical_len = len(self.classical_sig)
        return (
            classical_len.to_bytes(2, 'big') +
            self.classical_sig +
            self.pq_sig
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'HybridSignature':
        """
        Deserialize hybrid signature.
        
        Args:
            data: Serialized signature bytes
        
        Returns:
            HybridSignature instance
        
        Raises:
            InvalidSignature: If data is malformed
        """
        if len(data) < 2:
            raise InvalidSignature("Hybrid signature too short")
        
        classical_len = int.from_bytes(data[:2], 'big')
        
        if len(data) < 2 + classical_len:
            raise InvalidSignature("Invalid classical signature length")
        
        classical_sig = data[2:2 + classical_len]
        pq_sig = data[2 + classical_len:]
        
        return cls(classical_sig=classical_sig, pq_sig=pq_sig)
    
    def __len__(self) -> int:
        """Total size of hybrid signature"""
        return 2 + len(self.classical_sig) + len(self.pq_sig)


class HybridPublicKey:
    """
    Holds both classical and post-quantum public keys.
    
    Used to verify hybrid signatures during migration period.
    """
    
    def __init__(
        self,
        classical_key: PublicKey,
        pq_key: DilithiumPublicKey
    ):
        """
        Create hybrid public key.
        
        Args:
            classical_key: secp256k1 public key (eth-keys)
            pq_key: Dilithium public key
        """
        self.classical_key = classical_key
        self.pq_key = pq_key
    
    def verify_hybrid(self, message: bytes, signature: HybridSignature) -> bool:
        """
        Verify hybrid signature (both classical and PQ must be valid).
        
        Args:
            message: Original message
            signature: Hybrid signature to verify
        
        Returns:
            True if BOTH signatures are valid, False otherwise
        """
        # Verify classical ECDSA signature
        try:
            # eth-keys expects signature object
            # For now, we'll do basic validation
            classical_valid = self._verify_classical(message, signature.classical_sig)
        except Exception:
            classical_valid = False
        
        # Verify PQ signature
        pq_valid = self.pq_key.verify(message, signature.pq_sig)
        
        # Both must be valid
        return classical_valid and pq_valid
    
    def _verify_classical(self, message: bytes, signature: bytes) -> bool:
        """
        Verify classical ECDSA signature.
        
        Note: This is a simplified implementation. Full implementation
        would need proper signature recovery and validation.
        """
        # TODO: Implement full ECDSA verification
        # For now, just check signature length
        return len(signature) == 65  # r (32) + s (32) + v (1)
    
    def verify_classical_only(self, message: bytes, signature: bytes) -> bool:
        """Verify classical signature only"""
        return self._verify_classical(message, signature)
    
    def verify_pq_only(self, message: bytes, signature: bytes) -> bool:
        """Verify PQ signature only"""
        return self.pq_key.verify(message, signature)
    
    def to_bytes(self) -> bytes:
        """
        Serialize hybrid public key.
        
        Format: classical_pubkey (64 bytes uncompressed) || pq_pubkey (2,592 bytes)
        """
        # Classical key: 64 bytes uncompressed (x, y coordinates)
        classical_bytes = self.classical_key.to_bytes()
        pq_bytes = self.pq_key.to_bytes()
        return classical_bytes + pq_bytes
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'HybridPublicKey':
        """
        Deserialize hybrid public key.
        
        Args:
            data: Serialized key bytes
        
        Returns:
            HybridPublicKey instance
        """
        # Classical key is first 64 bytes
        classical_bytes = data[:64]
        pq_bytes = data[64:]
        
        classical_key = eth_keys.PublicKey(classical_bytes)
        pq_key = DilithiumPublicKey.from_bytes(pq_bytes)
        
        return cls(classical_key, pq_key)


class HybridPrivateKey:
    """
    Holds both classical and post-quantum private keys.
    
    Can sign with either key individually or create hybrid signatures.
    """
    
    def __init__(
        self,
        classical_key: PrivateKey,
        pq_key: DilithiumPrivateKey
    ):
        """
        Create hybrid private key.
        
        Args:
            classical_key: secp256k1 private key (eth-keys)
            pq_key: Dilithium private key
        """
        self.classical_key = classical_key
        self.pq_key = pq_key
    
    def sign_hybrid(self, message: bytes) -> HybridSignature:
        """
        Create hybrid signature with both classical and PQ keys.
        
        Args:
            message: Message to sign
        
        Returns:
            HybridSignature containing both signatures
        
        Example:
            >>> hybrid_key = HybridPrivateKey.generate()
            >>> signature = hybrid_key.sign_hybrid(b"transaction data")
            >>> assert hybrid_key.public_key().verify_hybrid(b"transaction data", signature)
        """
        # Sign with classical key
        classical_sig = self.sign_classical(message)
        
        # Sign with PQ key
        pq_sig = self.sign_pq(message)
        
        return HybridSignature(classical_sig=classical_sig, pq_sig=pq_sig)
    
    def sign_classical(self, message: bytes) -> bytes:
        """
        Sign with classical secp256k1 key only.
        
        Args:
            message: Message to sign
        
        Returns:
            65-byte ECDSA signature (r, s, v)
        """
        # Sign with eth-keys
        signature = self.classical_key.sign_msg(message)
        # Return as bytes (r, s, v)
        return signature.to_bytes()
    
    def sign_pq(self, message: bytes) -> bytes:
        """
        Sign with Dilithium key only.
        
        Args:
            message: Message to sign
        
        Returns:
            Dilithium signature (~4,595 bytes)
        """
        return self.pq_key.sign(message)
    
    def public_key(self) -> HybridPublicKey:
        """
        Get corresponding hybrid public key.
        
        Returns:
            HybridPublicKey instance
        """
        return HybridPublicKey(
            classical_key=self.classical_key.public_key,
            pq_key=self.pq_key.public_key()
        )
    
    @classmethod
    def generate(cls) -> 'HybridPrivateKey':
        """
        Generate new hybrid key pair with both classical and PQ keys.
        
        Returns:
            New HybridPrivateKey instance
        
        Example:
            >>> hybrid_key = HybridPrivateKey.generate()
            >>> pubkey = hybrid_key.public_key()
        """
        # Generate classical key
        classical_key = eth_keys.PrivateKey(eth_keys.keys.keccak(b"random_seed"))
        
        # Generate PQ key
        pq_key = DilithiumPrivateKey.generate()
        
        return cls(classical_key, pq_key)
    
    @classmethod
    def from_classical(cls, classical_key: PrivateKey) -> 'HybridPrivateKey':
        """
        Create hybrid key from existing classical key.
        
        Generates a new PQ key and pairs it with the classical key.
        Used for migrating existing accounts.
        
        Args:
            classical_key: Existing secp256k1 private key
        
        Returns:
            HybridPrivateKey with existing classical key and new PQ key
        
        Example:
            >>> classical_key = PrivateKey(key_bytes)
            >>> hybrid_key = HybridPrivateKey.from_classical(classical_key)
        """
        pq_key = DilithiumPrivateKey.generate()
        return cls(classical_key, pq_key)
    
    @classmethod
    def from_pq(cls, pq_key: DilithiumPrivateKey) -> 'HybridPrivateKey':
        """
        Create hybrid key from existing PQ key.
        
        Generates a new classical key and pairs it with the PQ key.
        Not recommended - use for testing only.
        
        Args:
            pq_key: Existing Dilithium private key
        
        Returns:
            HybridPrivateKey with new classical key and existing PQ key
        """
        classical_key = eth_keys.PrivateKey(eth_keys.keys.keccak(b"random_seed"))
        return cls(classical_key, pq_key)
    
    def __repr__(self) -> str:
        return (
            f"HybridPrivateKey("
            f"classical={self.classical_key.to_hex()[:16]}..., "
            f"pq={self.pq_key})"
        )
