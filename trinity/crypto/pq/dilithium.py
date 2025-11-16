"""
CRYSTALS-Dilithium Digital Signature Algorithm (FIPS 204)

NIST-standardized post-quantum signature scheme based on module lattices.
Provides strong security against quantum computer attacks.

Security Level 5 (Dilithium5):
- Public Key: 2,592 bytes
- Secret Key: 4,864 bytes  
- Signature: 4,595 bytes
- Security: ~256-bit classical and quantum resistance
"""

from typing import Optional
try:
    from oqs import Signature as OQSSignature
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False

from trinity.crypto.pq.constants import (
    DEFAULT_DILITHIUM_VARIANT,
    DILITHIUM2_PUBKEY_SIZE,
    DILITHIUM2_PRIVKEY_SIZE,
    DILITHIUM2_SIGNATURE_SIZE,
    DILITHIUM3_PUBKEY_SIZE,
    DILITHIUM3_PRIVKEY_SIZE,
    DILITHIUM3_SIGNATURE_SIZE,
    DILITHIUM5_PUBKEY_SIZE,
    DILITHIUM5_PRIVKEY_SIZE,
    DILITHIUM5_SIGNATURE_SIZE,
    DILITHIUM2_VARIANT,
    DILITHIUM3_VARIANT,
    DILITHIUM5_VARIANT,
)
from trinity.crypto.pq.exceptions import (
    DilithiumError,
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidSignature,
    SignatureVerificationFailed,
    LibraryNotAvailable,
)


# Export constants for easy access
DILITHIUM_VARIANT = DEFAULT_DILITHIUM_VARIANT
DILITHIUM_PUBKEY_SIZE = DILITHIUM5_PUBKEY_SIZE
DILITHIUM_PRIVKEY_SIZE = DILITHIUM5_PRIVKEY_SIZE
DILITHIUM_SIGNATURE_SIZE = DILITHIUM5_SIGNATURE_SIZE


def _get_key_sizes(variant: str) -> tuple:
    """Get (pubkey_size, privkey_size, signature_size) for variant"""
    if variant == DILITHIUM2_VARIANT:
        return (DILITHIUM2_PUBKEY_SIZE, DILITHIUM2_PRIVKEY_SIZE, DILITHIUM2_SIGNATURE_SIZE)
    elif variant == DILITHIUM3_VARIANT:
        return (DILITHIUM3_PUBKEY_SIZE, DILITHIUM3_PRIVKEY_SIZE, DILITHIUM3_SIGNATURE_SIZE)
    elif variant == DILITHIUM5_VARIANT:
        return (DILITHIUM5_PUBKEY_SIZE, DILITHIUM5_PRIVKEY_SIZE, DILITHIUM5_SIGNATURE_SIZE)
    else:
        raise ValueError(f"Unknown Dilithium variant: {variant}")


class DilithiumPublicKey:
    """
    Dilithium public key for signature verification.
    
    Example:
        >>> pubkey = DilithiumPublicKey.from_bytes(pubkey_bytes)
        >>> is_valid = pubkey.verify(message, signature)
    """
    
    def __init__(
        self,
        key_bytes: bytes,
        variant: str = DEFAULT_DILITHIUM_VARIANT
    ):
        """
        Create Dilithium public key from bytes.
        
        Args:
            key_bytes: Raw public key bytes
            variant: Dilithium variant (Dilithium2/3/5)
        
        Raises:
            InvalidPublicKey: If key_bytes has wrong size
            LibraryNotAvailable: If liboqs not installed
        """
        if not OQS_AVAILABLE:
            raise LibraryNotAvailable(
                "liboqs-python not available. Install with: pip install liboqs-python"
            )
        
        expected_size = _get_key_sizes(variant)[0]
        if len(key_bytes) != expected_size:
            raise InvalidPublicKey(
                f"Invalid public key size for {variant}: "
                f"expected {expected_size}, got {len(key_bytes)}"
            )
        
        self._key_bytes = key_bytes
        self._variant = variant
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a Dilithium signature.
        
        Args:
            message: Original message that was signed
            signature: Dilithium signature to verify
        
        Returns:
            True if signature is valid, False otherwise
        
        Example:
            >>> valid = pubkey.verify(b"hello", signature)
        """
        try:
            with OQSSignature(self._variant) as sig:
                # liboqs verify returns True/False
                return sig.verify(message, signature, self._key_bytes)
        except Exception as e:
            # If verification raises exception, treat as invalid
            return False
    
    def to_bytes(self) -> bytes:
        """Return raw public key bytes"""
        return self._key_bytes
    
    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        variant: str = DEFAULT_DILITHIUM_VARIANT
    ) -> 'DilithiumPublicKey':
        """
        Create public key from bytes.
        
        Args:
            data: Raw public key bytes
            variant: Dilithium variant
        
        Returns:
            DilithiumPublicKey instance
        """
        return cls(data, variant=variant)
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DilithiumPublicKey):
            return False
        return self._key_bytes == other._key_bytes and self._variant == other._variant
    
    def __repr__(self) -> str:
        return f"DilithiumPublicKey(variant={self._variant}, size={len(self._key_bytes)})"


class DilithiumPrivateKey:
    """
    Dilithium private key for signing.
    
    Example:
        >>> privkey = DilithiumPrivateKey.generate()
        >>> signature = privkey.sign(b"message")
        >>> pubkey = privkey.public_key()
        >>> assert pubkey.verify(b"message", signature)
    """
    
    def __init__(
        self,
        key_bytes: bytes,
        public_key_bytes: bytes = None,
        variant: str = DEFAULT_DILITHIUM_VARIANT
    ):
        """
        Create Dilithium private key from bytes.
        
        Args:
            key_bytes: Raw private key bytes
            public_key_bytes: Raw public key bytes (optional, will be derived if not provided)
            variant: Dilithium variant
        
        Raises:
            InvalidPrivateKey: If key_bytes has wrong size
            LibraryNotAvailable: If liboqs not installed
        """
        if not OQS_AVAILABLE:
            raise LibraryNotAvailable(
                "liboqs-python not available. Install with: pip install liboqs-python"
            )
        
        expected_size = _get_key_sizes(variant)[1]
        if len(key_bytes) != expected_size:
            raise InvalidPrivateKey(
                f"Invalid private key size for {variant}: "
                f"expected {expected_size}, got {len(key_bytes)}"
            )
        
        self._key_bytes = key_bytes
        self._variant = variant
        
        # Store or derive public key
        if public_key_bytes is not None:
            self._public_key_bytes = public_key_bytes
        else:
            # Derive public key from private key using liboqs
            # We need to sign a dummy message to get access to the public key
            # Actually, we can't derive it - liboqs requires both keys to be generated together
            # For now, require public key to be provided
            raise InvalidPrivateKey("Public key must be provided when creating from bytes")
    
    @property
    def public_key_bytes(self) -> bytes:
        """Get the raw public key bytes (property for consensus modules)."""
        return self._public_key_bytes
    
    @property
    def pq_address(self) -> bytes:
        """
        Get the PQ address derived from this key.
        Returns 32-byte address.
        """
        from trinity.crypto.pq.addresses import generate_pq_address
        return generate_pq_address(self.public_key())
    
    def sign(self, message: bytes) -> bytes:
        """
        Sign a message with Dilithium.
        
        Args:
            message: Message to sign
        
        Returns:
            Dilithium signature bytes
        
        Raises:
            DilithiumError: If signing fails
        
        Example:
            >>> signature = privkey.sign(b"hello world")
        """
        try:
            with OQSSignature(self._variant, secret_key=self._key_bytes) as sig:
                # liboqs sign method takes only the message
                signature = sig.sign(message)
                return signature
        except Exception as e:
            raise DilithiumError(f"Signing failed: {e}")
    
    def public_key(self) -> DilithiumPublicKey:
        """
        Get the corresponding public key.
        
        Returns:
            DilithiumPublicKey instance
        """
        return DilithiumPublicKey(self._public_key_bytes, variant=self._variant)
    
    def to_bytes(self) -> bytes:
        """
        Export private key as bytes.
        
        Warning: Keep private keys secure! Never expose them.
        """
        return self._key_bytes
    
    @classmethod
    def generate(cls, variant: str = DEFAULT_DILITHIUM_VARIANT) -> 'DilithiumPrivateKey':
        """
        Generate a new Dilithium key pair.
        
        Args:
            variant: Dilithium variant to use (default: Dilithium5)
        
        Returns:
            New DilithiumPrivateKey instance
        
        Raises:
            LibraryNotAvailable: If liboqs not installed
        
        Example:
            >>> privkey = DilithiumPrivateKey.generate()
            >>> pubkey = privkey.public_key()
        """
        if not OQS_AVAILABLE:
            raise LibraryNotAvailable(
                "liboqs-python not available. Install with: pip install liboqs-python"
            )
        
        try:
            with OQSSignature(variant) as sig:
                # Generate key pair - returns public key, stores private key internally
                public_key = sig.generate_keypair()
                # Export the private key
                private_key = sig.export_secret_key()
                
                # Create instance with both keys
                return cls(private_key, public_key_bytes=public_key, variant=variant)
        except Exception as e:
            raise DilithiumError(f"Key generation failed: {e}")
    
    @classmethod
    def from_bytes(
        cls,
        private_key_bytes: bytes,
        public_key_bytes: bytes,
        variant: str = DEFAULT_DILITHIUM_VARIANT
    ) -> 'DilithiumPrivateKey':
        """
        Create private key from bytes.
        
        Args:
            private_key_bytes: Raw private key bytes
            public_key_bytes: Raw public key bytes
            variant: Dilithium variant
        
        Returns:
            DilithiumPrivateKey instance
        """
        return cls(private_key_bytes, public_key_bytes=public_key_bytes, variant=variant)
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DilithiumPrivateKey):
            return False
        return self._key_bytes == other._key_bytes and self._variant == other._variant
    
    def __repr__(self) -> str:
        return f"DilithiumPrivateKey(variant={self._variant}, size={len(self._key_bytes)})"


def verify_dilithium(public_key_bytes: bytes, message: bytes, signature: bytes, variant: str = DEFAULT_DILITHIUM_VARIANT) -> bool:
    """
    Standalone function to verify a Dilithium signature.
    
    Args:
        public_key_bytes: Raw public key bytes
        message: Message that was signed
        signature: Dilithium signature
        variant: Dilithium variant to use
    
    Returns:
        True if signature is valid, False otherwise
    
    Example:
        >>> privkey = DilithiumPrivateKey.generate()
        >>> pubkey_bytes = privkey.public_key
        >>> sig = privkey.sign(b"message")
        >>> assert verify_dilithium(pubkey_bytes, b"message", sig)
    """
    try:
        pubkey = DilithiumPublicKey(public_key_bytes, variant=variant)
        return pubkey.verify(message, signature)
    except Exception:
        return False
