"""
QRDX Kyber Post-Quantum Key Encapsulation Mechanism (KEM)

Implements ML-KEM-768 (formerly Kyber768) for post-quantum secure key exchange.
ML-KEM is the NIST PQC standard (FIPS 203).

Used for:
- Secure node-to-node communication
- Key agreement in cross-chain bridge
- Future encrypted messaging between wallets

SECURITY: This module REQUIRES liboqs-python. There is NO fallback mode.

    pip install liboqs-python
"""

from dataclasses import dataclass
from typing import Optional, Tuple

try:
    import oqs
except ImportError as e:
    raise ImportError(
        "FATAL: liboqs-python is required for QRDX post-quantum cryptography. "
        "Install it with: pip install liboqs-python\n"
        f"Original error: {e}"
    ) from e


# ML-KEM-768 parameters (formerly Kyber768) — FIPS 203
ALGORITHM = "ML-KEM-768"
ALGORITHM_LEGACY = "Kyber768"
PUBLIC_KEY_SIZE = 1184    # ML-KEM-768 public key size
PRIVATE_KEY_SIZE = 2400   # ML-KEM-768 private key size
CIPHERTEXT_SIZE = 1088    # ML-KEM-768 ciphertext size
SHARED_SECRET_SIZE = 32   # ML-KEM-768 shared secret size


class KEMError(Exception):
    """Key Encapsulation Mechanism error."""
    pass


def _get_working_algorithm() -> str:
    """Determine which KEM algorithm name the installed liboqs supports."""
    try:
        oqs.KeyEncapsulation(ALGORITHM)
        return ALGORITHM
    except Exception:
        try:
            oqs.KeyEncapsulation(ALGORITHM_LEGACY)
            return ALGORITHM_LEGACY
        except Exception:
            raise KEMError(
                f"Neither {ALGORITHM} nor {ALGORITHM_LEGACY} is supported by "
                f"the installed liboqs. Upgrade liboqs to a version that "
                f"supports FIPS 203 (ML-KEM-768)."
            )


# Validate at import time
_WORKING_ALGORITHM = _get_working_algorithm()


@dataclass
class KEMPublicKey:
    """
    ML-KEM-768 public key for key encapsulation.

    Attributes:
        key_bytes: Raw public key bytes (1184 bytes for ML-KEM-768)
    """
    key_bytes: bytes

    def __post_init__(self):
        if not isinstance(self.key_bytes, bytes):
            raise TypeError("key_bytes must be bytes")
        if len(self.key_bytes) != PUBLIC_KEY_SIZE:
            raise ValueError(
                f"KEM public key must be {PUBLIC_KEY_SIZE} bytes, "
                f"got {len(self.key_bytes)}"
            )

    @classmethod
    def from_bytes(cls, data: bytes) -> 'KEMPublicKey':
        return cls(key_bytes=data)

    @classmethod
    def from_hex(cls, hex_str: str) -> 'KEMPublicKey':
        if hex_str.startswith('0x'):
            hex_str = hex_str[2:]
        return cls(key_bytes=bytes.fromhex(hex_str))

    def to_bytes(self) -> bytes:
        return self.key_bytes

    def to_hex(self) -> str:
        return self.key_bytes.hex()

    def __repr__(self) -> str:
        return f"KEMPublicKey(length={len(self.key_bytes)})"

    def __eq__(self, other) -> bool:
        if isinstance(other, KEMPublicKey):
            return self.key_bytes == other.key_bytes
        return False

    def __hash__(self) -> int:
        return hash(self.key_bytes)


class KEMPrivateKey:
    """
    ML-KEM-768 private key for key decapsulation.

    Supports keypair generation, encapsulation (encrypt), and
    decapsulation (decrypt) of shared secrets.

    REQUIRES liboqs — no fallback mode.
    """

    def __init__(
        self,
        key_bytes: Optional[bytes] = None,
        public_key: Optional[KEMPublicKey] = None,
    ):
        self._kem = None
        self._key_bytes = key_bytes
        self._public_key = public_key

        if key_bytes is None:
            self._generate()
        else:
            self._restore_from_bytes(key_bytes)

    def _generate(self):
        """Generate new KEM keypair."""
        try:
            self._kem = oqs.KeyEncapsulation(_WORKING_ALGORITHM)
            pub_bytes = self._kem.generate_keypair()
            self._public_key = KEMPublicKey(pub_bytes)
            self._key_bytes = self._kem.export_secret_key()
        except Exception as e:
            raise KEMError(f"KEM key generation failed: {e}")

    def _restore_from_bytes(self, key_bytes: bytes):
        """Restore KEM keypair from private key bytes."""
        try:
            self._kem = oqs.KeyEncapsulation(_WORKING_ALGORITHM, key_bytes)
            if self._public_key is None:
                pub_bytes = self._kem.generate_keypair()
                self._public_key = KEMPublicKey(pub_bytes)
        except Exception as e:
            raise KEMError(f"KEM key restoration failed: {e}")

    @classmethod
    def generate(cls) -> 'KEMPrivateKey':
        """Generate a new random KEM keypair."""
        return cls()

    @classmethod
    def from_bytes(cls, data: bytes, public_key: Optional[KEMPublicKey] = None) -> 'KEMPrivateKey':
        return cls(key_bytes=data, public_key=public_key)

    def to_bytes(self) -> bytes:
        if self._key_bytes:
            return self._key_bytes
        if self._kem:
            return self._kem.export_secret_key()
        raise KEMError("No key material available")

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @property
    def public_key(self) -> KEMPublicKey:
        if self._public_key is None:
            raise KEMError("Public key not initialized")
        return self._public_key

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate a shared secret from ciphertext.

        Args:
            ciphertext: Ciphertext from encapsulate()

        Returns:
            Shared secret bytes (32 bytes)

        Raises:
            KEMError: If decapsulation fails
        """
        if not isinstance(ciphertext, bytes):
            raise TypeError("Ciphertext must be bytes")

        if self._kem is None:
            raise KEMError("KEM not initialized")

        try:
            shared_secret = self._kem.decap_secret(ciphertext)
            return shared_secret
        except Exception as e:
            raise KEMError(f"Decapsulation failed: {e}")

    def __repr__(self) -> str:
        return f"KEMPrivateKey(algorithm={_WORKING_ALGORITHM})"


# ============================================================================
# Module-level convenience functions
# ============================================================================


def kyber_generate_keypair() -> Tuple[KEMPrivateKey, KEMPublicKey]:
    """
    Generate a new ML-KEM-768 keypair.

    Returns:
        Tuple of (private_key, public_key)
    """
    private_key = KEMPrivateKey.generate()
    return private_key, private_key.public_key


def kyber_encapsulate(public_key: KEMPublicKey) -> Tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using a public key.

    This is the "encrypt" side — only requires the public key.
    Produces a ciphertext and a shared secret.

    Args:
        public_key: KEMPublicKey to encapsulate with

    Returns:
        Tuple of (ciphertext, shared_secret)

    Raises:
        KEMError: If encapsulation fails
    """
    if not isinstance(public_key, KEMPublicKey):
        raise TypeError("public_key must be a KEMPublicKey")

    try:
        kem = oqs.KeyEncapsulation(_WORKING_ALGORITHM)
        ciphertext, shared_secret = kem.encap_secret(public_key.to_bytes())
        return ciphertext, shared_secret
    except Exception as e:
        raise KEMError(f"Encapsulation failed: {e}")


def kyber_decapsulate(private_key: KEMPrivateKey, ciphertext: bytes) -> bytes:
    """
    Decapsulate a shared secret using a private key.

    This is the "decrypt" side — requires the private key and the ciphertext.

    Args:
        private_key: KEMPrivateKey to decapsulate with
        ciphertext: Ciphertext from encapsulate()

    Returns:
        Shared secret bytes (32 bytes)
    """
    return private_key.decapsulate(ciphertext)


def is_available() -> bool:
    """Check if KEM is available. Always True if module imported successfully."""
    return True


def get_algorithm_info() -> dict:
    """Get information about the KEM algorithm."""
    algo = _WORKING_ALGORITHM
    try:
        kem = oqs.KeyEncapsulation(algo)
        details = kem.details
    except Exception:
        details = {}

    return {
        'algorithm': algo,
        'algorithm_family': 'ML-KEM (Kyber)',
        'nist_standard': 'FIPS 203',
        'private_key_size': PRIVATE_KEY_SIZE,
        'public_key_size': PUBLIC_KEY_SIZE,
        'ciphertext_size': CIPHERTEXT_SIZE,
        'shared_secret_size': SHARED_SECRET_SIZE,
        'liboqs_available': True,
        'claimed_nist_level': details.get('claimed_nist_level', 3),
    }
