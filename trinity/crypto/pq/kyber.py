"""
CRYSTALS-Kyber Key Encapsulation Mechanism (FIPS 203)

NIST-standardized post-quantum KEM based on module lattices.
Used for secure key exchange resistant to quantum attacks.

Security Level 5 (Kyber1024):
- Public Key: 1,568 bytes
- Secret Key: 3,168 bytes
- Ciphertext: 1,568 bytes
- Shared Secret: 32 bytes
- Security: ~256-bit classical and quantum resistance
"""

from typing import Tuple
try:
    from oqs import KeyEncapsulation as OQSKEM
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False

from trinity.crypto.pq.constants import (
    DEFAULT_KYBER_VARIANT,
    KYBER512_PUBKEY_SIZE,
    KYBER512_PRIVKEY_SIZE,
    KYBER512_CIPHERTEXT_SIZE,
    KYBER512_SHARED_SECRET_SIZE,
    KYBER768_PUBKEY_SIZE,
    KYBER768_PRIVKEY_SIZE,
    KYBER768_CIPHERTEXT_SIZE,
    KYBER768_SHARED_SECRET_SIZE,
    KYBER1024_PUBKEY_SIZE,
    KYBER1024_PRIVKEY_SIZE,
    KYBER1024_CIPHERTEXT_SIZE,
    KYBER1024_SHARED_SECRET_SIZE,
    KYBER512_VARIANT,
    KYBER768_VARIANT,
    KYBER1024_VARIANT,
)
from trinity.crypto.pq.exceptions import (
    KyberError,
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidCiphertext,
    LibraryNotAvailable,
)


# Export constants for easy access
KYBER_VARIANT = DEFAULT_KYBER_VARIANT
KYBER_PUBKEY_SIZE = KYBER1024_PUBKEY_SIZE
KYBER_PRIVKEY_SIZE = KYBER1024_PRIVKEY_SIZE
KYBER_CIPHERTEXT_SIZE = KYBER1024_CIPHERTEXT_SIZE
KYBER_SHARED_SECRET_SIZE = KYBER1024_SHARED_SECRET_SIZE


def _get_key_sizes(variant: str) -> tuple:
    """Get (pubkey_size, privkey_size, ciphertext_size, shared_secret_size) for variant"""
    if variant == KYBER512_VARIANT:
        return (
            KYBER512_PUBKEY_SIZE,
            KYBER512_PRIVKEY_SIZE,
            KYBER512_CIPHERTEXT_SIZE,
            KYBER512_SHARED_SECRET_SIZE,
        )
    elif variant == KYBER768_VARIANT:
        return (
            KYBER768_PUBKEY_SIZE,
            KYBER768_PRIVKEY_SIZE,
            KYBER768_CIPHERTEXT_SIZE,
            KYBER768_SHARED_SECRET_SIZE,
        )
    elif variant == KYBER1024_VARIANT:
        return (
            KYBER1024_PUBKEY_SIZE,
            KYBER1024_PRIVKEY_SIZE,
            KYBER1024_CIPHERTEXT_SIZE,
            KYBER1024_SHARED_SECRET_SIZE,
        )
    else:
        raise ValueError(f"Unknown Kyber variant: {variant}")


class KyberPublicKey:
    """
    Kyber public key for key encapsulation.
    
    The holder of this public key can encapsulate a shared secret,
    which only the private key holder can decapsulate.
    
    Example:
        >>> pubkey = KyberPublicKey.from_bytes(pubkey_bytes)
        >>> ciphertext, shared_secret = pubkey.encapsulate()
        >>> # Send ciphertext to private key holder
    """
    
    def __init__(
        self,
        key_bytes: bytes,
        variant: str = DEFAULT_KYBER_VARIANT
    ):
        """
        Create Kyber public key from bytes.
        
        Args:
            key_bytes: Raw public key bytes
            variant: Kyber variant (Kyber512/768/1024)
        
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
    
    def encapsulate(self) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using this public key.
        
        Generates a random shared secret and encapsulates it for the
        private key holder. Only the holder of the corresponding private
        key can decapsulate to recover the shared secret.
        
        Returns:
            Tuple of (ciphertext, shared_secret)
            - ciphertext: To send to private key holder
            - shared_secret: 32-byte secret for symmetric encryption
        
        Raises:
            KyberError: If encapsulation fails
        
        Example:
            >>> ciphertext, secret = pubkey.encapsulate()
            >>> # Send ciphertext to recipient
            >>> # Use secret for AES encryption
        """
        try:
            with OQSKEM(self._variant) as kem:
                # Encapsulate with public key
                ciphertext, shared_secret = kem.encap_secret(self._key_bytes)
                return (ciphertext, shared_secret)
        except Exception as e:
            raise KyberError(f"Encapsulation failed: {e}")
    
    def to_bytes(self) -> bytes:
        """Return raw public key bytes"""
        return self._key_bytes
    
    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        variant: str = DEFAULT_KYBER_VARIANT
    ) -> 'KyberPublicKey':
        """
        Create public key from bytes.
        
        Args:
            data: Raw public key bytes
            variant: Kyber variant
        
        Returns:
            KyberPublicKey instance
        """
        return cls(data, variant=variant)
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KyberPublicKey):
            return False
        return self._key_bytes == other._key_bytes and self._variant == other._variant
    
    def __repr__(self) -> str:
        return f"KyberPublicKey(variant={self._variant}, size={len(self._key_bytes)})"


class KyberPrivateKey:
    """
    Kyber private key for key decapsulation.
    
    The holder of this private key can decapsulate ciphertexts created
    with the corresponding public key to recover shared secrets.
    
    Example:
        >>> privkey = KyberPrivateKey.generate()
        >>> pubkey = privkey.public_key()
        >>> # Public key is sent to sender
        >>> # Sender creates: ciphertext, secret = pubkey.encapsulate()
        >>> recovered_secret = privkey.decapsulate(ciphertext)
        >>> assert recovered_secret == secret
    """
    
    def __init__(
        self,
        key_bytes: bytes,
        variant: str = DEFAULT_KYBER_VARIANT
    ):
        """
        Create Kyber private key from bytes.
        
        Args:
            key_bytes: Raw private key bytes
            variant: Kyber variant
        
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
        
        # Extract public key (stored in private key by liboqs)
        # Public key is at the beginning of the private key
        pubkey_size = _get_key_sizes(variant)[0]
        self._public_key_bytes = key_bytes[:pubkey_size]
    
    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate ciphertext to recover shared secret.
        
        Args:
            ciphertext: Ciphertext from encapsulate()
        
        Returns:
            32-byte shared secret
        
        Raises:
            InvalidCiphertext: If ciphertext has wrong size
            KyberError: If decapsulation fails
        
        Example:
            >>> shared_secret = privkey.decapsulate(ciphertext)
            >>> # Use shared_secret for AES decryption
        """
        expected_ct_size = _get_key_sizes(self._variant)[2]
        if len(ciphertext) != expected_ct_size:
            raise InvalidCiphertext(
                f"Invalid ciphertext size for {self._variant}: "
                f"expected {expected_ct_size}, got {len(ciphertext)}"
            )
        
        try:
            with OQSKEM(self._variant) as kem:
                # Decapsulate with private key
                shared_secret = kem.decap_secret(ciphertext, self._key_bytes)
                return shared_secret
        except Exception as e:
            raise KyberError(f"Decapsulation failed: {e}")
    
    def public_key(self) -> KyberPublicKey:
        """
        Get the corresponding public key.
        
        Returns:
            KyberPublicKey instance
        """
        return KyberPublicKey(self._public_key_bytes, variant=self._variant)
    
    def to_bytes(self) -> bytes:
        """
        Export private key as bytes.
        
        Warning: Keep private keys secure! Never expose them.
        """
        return self._key_bytes
    
    @classmethod
    def generate(cls, variant: str = DEFAULT_KYBER_VARIANT) -> 'KyberPrivateKey':
        """
        Generate a new Kyber key pair.
        
        Args:
            variant: Kyber variant to use (default: Kyber1024)
        
        Returns:
            New KyberPrivateKey instance
        
        Raises:
            LibraryNotAvailable: If liboqs not installed
        
        Example:
            >>> privkey = KyberPrivateKey.generate()
            >>> pubkey = privkey.public_key()
            >>> ciphertext, secret1 = pubkey.encapsulate()
            >>> secret2 = privkey.decapsulate(ciphertext)
            >>> assert secret1 == secret2
        """
        if not OQS_AVAILABLE:
            raise LibraryNotAvailable(
                "liboqs-python not available. Install with: pip install liboqs-python"
            )
        
        try:
            with OQSKEM(variant) as kem:
                # Generate key pair
                public_key = kem.generate_keypair()
                # Export secret key
                private_key = kem.export_secret_key()
                
                return cls(private_key, variant=variant)
        except Exception as e:
            raise KyberError(f"Key generation failed: {e}")
    
    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        variant: str = DEFAULT_KYBER_VARIANT
    ) -> 'KyberPrivateKey':
        """
        Create private key from bytes.
        
        Args:
            data: Raw private key bytes
            variant: Kyber variant
        
        Returns:
            KyberPrivateKey instance
        """
        return cls(data, variant=variant)
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KyberPrivateKey):
            return False
        return self._key_bytes == other._key_bytes and self._variant == other._variant
    
    def __repr__(self) -> str:
        return f"KyberPrivateKey(variant={self._variant}, size={len(self._key_bytes)})"
