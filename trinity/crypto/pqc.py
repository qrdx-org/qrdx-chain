"""
Post-Quantum Cryptography Implementation for QRDX Chain
Implements CRYSTALS-Dilithium (signatures) and CRYSTALS-Kyber (key encapsulation)
Based on NIST FIPS 204 and FIPS 203 standards
"""

import oqs
from typing import Tuple
from eth_utils import ValidationError


# NIST Security Level 3 (comparable to AES-192)
DILITHIUM_ALGORITHM = "Dilithium3"
KYBER_ALGORITHM = "Kyber768"

# Key and signature sizes for Dilithium3
DILITHIUM_PUBLIC_KEY_SIZE = 1952
DILITHIUM_PRIVATE_KEY_SIZE = 4000
DILITHIUM_SIGNATURE_SIZE = 3293

# Key sizes for Kyber768
KYBER_PUBLIC_KEY_SIZE = 1184
KYBER_PRIVATE_KEY_SIZE = 2400
KYBER_CIPHERTEXT_SIZE = 1088
KYBER_SHARED_SECRET_SIZE = 32


class DilithiumPrivateKey:
    """
    CRYSTALS-Dilithium private key for quantum-resistant digital signatures.
    NIST FIPS 204 (Dilithium3 - Security Level 3)
    """
    
    def __init__(self, key_bytes: bytes):
        """
        Initialize a Dilithium private key.
        
        Args:
            key_bytes: Raw private key bytes (4000 bytes for Dilithium3)
        """
        if len(key_bytes) != DILITHIUM_PRIVATE_KEY_SIZE:
            raise ValidationError(
                f"Invalid Dilithium private key size. Expected {DILITHIUM_PRIVATE_KEY_SIZE}, "
                f"got {len(key_bytes)}"
            )
        self._key_bytes = key_bytes
        self._signer = None
    
    def sign(self, message: bytes) -> bytes:
        """
        Sign a message using Dilithium.
        
        Args:
            message: The message to sign
            
        Returns:
            Signature bytes (3293 bytes for Dilithium3)
        """
        if self._signer is None:
            self._signer = oqs.Signature(DILITHIUM_ALGORITHM, self._key_bytes)
        
        signature = self._signer.sign(message)
        
        if len(signature) != DILITHIUM_SIGNATURE_SIZE:
            raise ValidationError(
                f"Generated signature has invalid size. Expected {DILITHIUM_SIGNATURE_SIZE}, "
                f"got {len(signature)}"
            )
        
        return signature
    
    def public_key(self) -> 'DilithiumPublicKey':
        """
        Derive the public key from this private key.
        
        Returns:
            DilithiumPublicKey instance
        """
        # Extract public key from private key using liboqs
        with oqs.Signature(DILITHIUM_ALGORITHM) as temp_signer:
            # Generate a new keypair to get the structure
            temp_public = temp_signer.generate_keypair()
            
        # The first DILITHIUM_PUBLIC_KEY_SIZE bytes of the secret key contain the public key
        # This is specific to Dilithium's key format
        # For proper implementation, we should use the signing operation to extract it
        # But for now, we'll use the standard approach
        with oqs.Signature(DILITHIUM_ALGORITHM, self._key_bytes) as signer:
            # Export public key - liboqs stores it internally
            # We need to sign a dummy message and export the verification key
            public_key_bytes = signer.export_public_key()
            
        return DilithiumPublicKey(public_key_bytes)
    
    def to_bytes(self) -> bytes:
        """Return the raw private key bytes."""
        return self._key_bytes
    
    def __repr__(self) -> str:
        return f"<DilithiumPrivateKey: {self._key_bytes[:8].hex()}...>"


class DilithiumPublicKey:
    """
    CRYSTALS-Dilithium public key for quantum-resistant signature verification.
    """
    
    def __init__(self, key_bytes: bytes):
        """
        Initialize a Dilithium public key.
        
        Args:
            key_bytes: Raw public key bytes (1952 bytes for Dilithium3)
        """
        if len(key_bytes) != DILITHIUM_PUBLIC_KEY_SIZE:
            raise ValidationError(
                f"Invalid Dilithium public key size. Expected {DILITHIUM_PUBLIC_KEY_SIZE}, "
                f"got {len(key_bytes)}"
            )
        self._key_bytes = key_bytes
        self._verifier = None
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a Dilithium signature.
        
        Args:
            message: The original message
            signature: The signature to verify (3293 bytes)
            
        Returns:
            True if signature is valid, False otherwise
        """
        if len(signature) != DILITHIUM_SIGNATURE_SIZE:
            return False
        
        try:
            if self._verifier is None:
                self._verifier = oqs.Signature(DILITHIUM_ALGORITHM)
            
            return self._verifier.verify(message, signature, self._key_bytes)
        except Exception:
            return False
    
    def to_bytes(self) -> bytes:
        """Return the raw public key bytes."""
        return self._key_bytes
    
    def __repr__(self) -> str:
        return f"<DilithiumPublicKey: {self._key_bytes[:8].hex()}...>"
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DilithiumPublicKey):
            return False
        return self._key_bytes == other._key_bytes
    
    def __hash__(self) -> int:
        return hash(self._key_bytes)


class KyberPrivateKey:
    """
    CRYSTALS-Kyber private key for quantum-resistant key encapsulation.
    NIST FIPS 203 (Kyber768 - Security Level 3)
    """
    
    def __init__(self, key_bytes: bytes):
        """
        Initialize a Kyber private key.
        
        Args:
            key_bytes: Raw private key bytes (2400 bytes for Kyber768)
        """
        if len(key_bytes) != KYBER_PRIVATE_KEY_SIZE:
            raise ValidationError(
                f"Invalid Kyber private key size. Expected {KYBER_PRIVATE_KEY_SIZE}, "
                f"got {len(key_bytes)}"
            )
        self._key_bytes = key_bytes
        self._kem = None
    
    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate a ciphertext to recover the shared secret.
        
        Args:
            ciphertext: The encapsulated ciphertext (1088 bytes)
            
        Returns:
            Shared secret bytes (32 bytes)
        """
        if len(ciphertext) != KYBER_CIPHERTEXT_SIZE:
            raise ValidationError(
                f"Invalid ciphertext size. Expected {KYBER_CIPHERTEXT_SIZE}, "
                f"got {len(ciphertext)}"
            )
        
        if self._kem is None:
            self._kem = oqs.KeyEncapsulation(KYBER_ALGORITHM, self._key_bytes)
        
        shared_secret = self._kem.decap_secret(ciphertext)
        
        if len(shared_secret) != KYBER_SHARED_SECRET_SIZE:
            raise ValidationError(
                f"Invalid shared secret size. Expected {KYBER_SHARED_SECRET_SIZE}, "
                f"got {len(shared_secret)}"
            )
        
        return shared_secret
    
    def public_key(self) -> 'KyberPublicKey':
        """
        Derive the public key from this private key.
        
        Returns:
            KyberPublicKey instance
        """
        # Extract public key from the KEM
        with oqs.KeyEncapsulation(KYBER_ALGORITHM, self._key_bytes) as kem:
            public_key_bytes = kem.export_public_key()
            
        return KyberPublicKey(public_key_bytes)
    
    def to_bytes(self) -> bytes:
        """Return the raw private key bytes."""
        return self._key_bytes
    
    def __repr__(self) -> str:
        return f"<KyberPrivateKey: {self._key_bytes[:8].hex()}...>"


class KyberPublicKey:
    """
    CRYSTALS-Kyber public key for quantum-resistant key encapsulation.
    """
    
    def __init__(self, key_bytes: bytes):
        """
        Initialize a Kyber public key.
        
        Args:
            key_bytes: Raw public key bytes (1184 bytes for Kyber768)
        """
        if len(key_bytes) != KYBER_PUBLIC_KEY_SIZE:
            raise ValidationError(
                f"Invalid Kyber public key size. Expected {KYBER_PUBLIC_KEY_SIZE}, "
                f"got {len(key_bytes)}"
            )
        self._key_bytes = key_bytes
        self._kem = None
    
    def encapsulate(self) -> Tuple[bytes, bytes]:
        """
        Generate a shared secret and encapsulate it.
        
        Returns:
            Tuple of (ciphertext, shared_secret)
            - ciphertext: Encapsulated ciphertext (1088 bytes)
            - shared_secret: Shared secret (32 bytes)
        """
        if self._kem is None:
            self._kem = oqs.KeyEncapsulation(KYBER_ALGORITHM)
        
        ciphertext, shared_secret = self._kem.encap_secret(self._key_bytes)
        
        if len(ciphertext) != KYBER_CIPHERTEXT_SIZE:
            raise ValidationError(
                f"Invalid ciphertext size. Expected {KYBER_CIPHERTEXT_SIZE}, "
                f"got {len(ciphertext)}"
            )
        
        if len(shared_secret) != KYBER_SHARED_SECRET_SIZE:
            raise ValidationError(
                f"Invalid shared secret size. Expected {KYBER_SHARED_SECRET_SIZE}, "
                f"got {len(shared_secret)}"
            )
        
        return ciphertext, shared_secret
    
    def to_bytes(self) -> bytes:
        """Return the raw public key bytes."""
        return self._key_bytes
    
    def __repr__(self) -> str:
        return f"<KyberPublicKey: {self._key_bytes[:8].hex()}...>"
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KyberPublicKey):
            return False
        return self._key_bytes == other._key_bytes
    
    def __hash__(self) -> int:
        return hash(self._key_bytes)


def generate_dilithium_keypair() -> Tuple[DilithiumPrivateKey, DilithiumPublicKey]:
    """
    Generate a new Dilithium keypair.
    
    Returns:
        Tuple of (private_key, public_key)
    """
    with oqs.Signature(DILITHIUM_ALGORITHM) as signer:
        public_key_bytes = signer.generate_keypair()
        private_key_bytes = signer.export_secret_key()
    
    private_key = DilithiumPrivateKey(private_key_bytes)
    public_key = DilithiumPublicKey(public_key_bytes)
    
    return private_key, public_key


def generate_kyber_keypair() -> Tuple[KyberPrivateKey, KyberPublicKey]:
    """
    Generate a new Kyber keypair.
    
    Returns:
        Tuple of (private_key, public_key)
    """
    with oqs.KeyEncapsulation(KYBER_ALGORITHM) as kem:
        public_key_bytes = kem.generate_keypair()
        private_key_bytes = kem.export_secret_key()
    
    private_key = KyberPrivateKey(private_key_bytes)
    public_key = KyberPublicKey(public_key_bytes)
    
    return private_key, public_key
