"""
QRDX Dilithium Post-Quantum Signatures

Implements ML-DSA-65 (formerly Dilithium3) for post-quantum secure digital signatures.
ML-DSA is the NIST PQC standard (FIPS 204).

SECURITY: This module REQUIRES liboqs-python. There is NO fallback mode.
A node without liboqs cannot generate keys, sign, or verify — it will fail hard.

    pip install liboqs-python
"""

import hashlib
from dataclasses import dataclass
from typing import Optional, Tuple, Union

try:
    import oqs
except ImportError as e:
    raise ImportError(
        "FATAL: liboqs-python is required for QRDX post-quantum cryptography. "
        "Install it with: pip install liboqs-python\n"
        "liboqs system library must also be installed. "
        "See https://github.com/open-quantum-safe/liboqs\n"
        f"Original error: {e}"
    ) from e


# ML-DSA-65 parameters (formerly Dilithium3) — FIPS 204
# Try ML-DSA-65 first (newer liboqs ≥0.9), fallback to Dilithium3 (older)
ALGORITHM = "ML-DSA-65"
ALGORITHM_LEGACY = "Dilithium3"
PRIVATE_KEY_SIZE = 4032   # ML-DSA-65 private key size
PUBLIC_KEY_SIZE = 1952    # ML-DSA-65 public key size
SIGNATURE_SIZE = 3309     # ML-DSA-65 signature size


class PQCryptoError(Exception):
    """Post-quantum cryptography error."""
    pass


class PQSignatureError(PQCryptoError):
    """Signature operation failed."""
    pass


def _get_working_algorithm() -> str:
    """Determine which algorithm name the installed liboqs supports."""
    try:
        oqs.Signature(ALGORITHM)
        return ALGORITHM
    except Exception:
        try:
            oqs.Signature(ALGORITHM_LEGACY)
            return ALGORITHM_LEGACY
        except Exception:
            raise PQCryptoError(
                f"Neither {ALGORITHM} nor {ALGORITHM_LEGACY} is supported by "
                f"the installed liboqs. Upgrade liboqs to a version that "
                f"supports FIPS 204 (ML-DSA-65)."
            )


# Validate at import time that at least one algorithm works
_WORKING_ALGORITHM = _get_working_algorithm()


@dataclass
class PQPublicKey:
    """
    Dilithium3 / ML-DSA-65 public key.

    Attributes:
        key_bytes: Raw public key bytes (1952 bytes for ML-DSA-65)
    """
    key_bytes: bytes

    def __post_init__(self):
        if not isinstance(self.key_bytes, bytes):
            raise TypeError("key_bytes must be bytes")
        if len(self.key_bytes) != PUBLIC_KEY_SIZE:
            raise ValueError(
                f"Public key must be {PUBLIC_KEY_SIZE} bytes, "
                f"got {len(self.key_bytes)}"
            )

    @classmethod
    def from_bytes(cls, data: bytes) -> 'PQPublicKey':
        """Create public key from bytes."""
        return cls(key_bytes=data)

    @classmethod
    def from_hex(cls, hex_str: str) -> 'PQPublicKey':
        """Create public key from hex string."""
        if hex_str.startswith('0x'):
            hex_str = hex_str[2:]
        return cls(key_bytes=bytes.fromhex(hex_str))

    def to_bytes(self) -> bytes:
        """Get raw public key bytes."""
        return self.key_bytes

    def to_hex(self) -> str:
        """Get hex-encoded public key."""
        return self.key_bytes.hex()

    def to_address(self) -> str:
        """
        Derive PQ address from public key.

        Address is first 32 bytes of keccak256(pubkey) with 0xPQ prefix.
        """
        from ..address import public_key_to_address, AddressType
        return public_key_to_address(self.key_bytes, AddressType.POST_QUANTUM)

    def fingerprint(self) -> str:
        """
        Get short fingerprint for display.

        Returns first 8 bytes of SHA256 hash as hex.
        """
        h = hashlib.sha256(self.key_bytes).digest()[:8]
        return h.hex()

    def __repr__(self) -> str:
        return f"PQPublicKey(fingerprint={self.fingerprint()})"

    def __eq__(self, other) -> bool:
        if isinstance(other, PQPublicKey):
            return self.key_bytes == other.key_bytes
        return False

    def __hash__(self) -> int:
        return hash(self.key_bytes)


@dataclass
class PQSignature:
    """
    Dilithium3 / ML-DSA-65 signature.

    Attributes:
        sig_bytes: Raw signature bytes (3309 bytes for ML-DSA-65)
    """
    sig_bytes: bytes

    def __post_init__(self):
        if not isinstance(self.sig_bytes, bytes):
            raise TypeError("sig_bytes must be bytes")
        if len(self.sig_bytes) == 0:
            raise ValueError("Signature cannot be empty")

    @classmethod
    def from_bytes(cls, data: bytes) -> 'PQSignature':
        """Create signature from bytes."""
        return cls(sig_bytes=data)

    @classmethod
    def from_hex(cls, hex_str: str) -> 'PQSignature':
        """Create signature from hex string."""
        if hex_str.startswith('0x'):
            hex_str = hex_str[2:]
        return cls(sig_bytes=bytes.fromhex(hex_str))

    def to_bytes(self) -> bytes:
        """Get raw signature bytes."""
        return self.sig_bytes

    def to_hex(self) -> str:
        """Get hex-encoded signature."""
        return self.sig_bytes.hex()

    def __repr__(self) -> str:
        return f"PQSignature(length={len(self.sig_bytes)})"

    def __eq__(self, other) -> bool:
        if isinstance(other, PQSignature):
            return self.sig_bytes == other.sig_bytes
        return False


class PQPrivateKey:
    """
    Dilithium3 / ML-DSA-65 private key.

    Supports key generation, signing, and serialization.
    REQUIRES liboqs — no fallback mode.
    """

    def __init__(
        self,
        key_bytes: Optional[bytes] = None,
        _signer=None,
        public_key: Optional[PQPublicKey] = None,
    ):
        """
        Initialize private key.

        Args:
            key_bytes: Raw private key bytes (optional, generates new if None)
            _signer: Internal OQS signer object
            public_key: Pre-computed public key (for restoration)
        """
        self._signer = _signer
        self._key_bytes = key_bytes
        self._public_key: Optional[PQPublicKey] = public_key

        if _signer is None and key_bytes is None:
            # Generate new keypair
            self._generate()
        elif _signer is None and key_bytes is not None:
            # Restore from bytes
            self._restore_from_bytes(key_bytes)

    def _generate(self):
        """Generate new keypair using liboqs."""
        try:
            self._signer = oqs.Signature(_WORKING_ALGORITHM)
            pub_bytes = self._signer.generate_keypair()
            self._public_key = PQPublicKey(pub_bytes)
            self._key_bytes = self._signer.export_secret_key()
        except Exception as e:
            raise PQCryptoError(f"Key generation failed: {e}")

    def _restore_from_bytes(self, key_bytes: bytes):
        """Restore keypair from private key bytes."""
        try:
            self._signer = oqs.Signature(_WORKING_ALGORITHM, key_bytes)
            if self._public_key is None:
                # OQS API: when restoring from secret key, we must call
                # generate_keypair() to initialize internal state.
                # Callers SHOULD provide public_key for proper restoration.
                pub_bytes = self._signer.generate_keypair()
                self._public_key = PQPublicKey(pub_bytes)
        except Exception as e:
            raise PQCryptoError(f"Key restoration failed: {e}")

    @classmethod
    def generate(cls) -> 'PQPrivateKey':
        """Generate a new random keypair."""
        return cls()

    @classmethod
    def from_bytes(cls, data: bytes, public_key: Optional[PQPublicKey] = None) -> 'PQPrivateKey':
        """
        Create private key from bytes.

        Args:
            data: Private key bytes
            public_key: Optional public key for proper restoration
        """
        return cls(key_bytes=data, public_key=public_key)

    @classmethod
    def from_hex(cls, hex_str: str, public_key_hex: Optional[str] = None) -> 'PQPrivateKey':
        """
        Create private key from hex string.

        Args:
            hex_str: Private key hex (with or without 0x)
            public_key_hex: Optional public key hex for proper restoration
        """
        if hex_str.startswith('0x'):
            hex_str = hex_str[2:]

        public_key = None
        if public_key_hex:
            public_key = PQPublicKey.from_hex(public_key_hex)

        return cls(key_bytes=bytes.fromhex(hex_str), public_key=public_key)

    def to_bytes(self) -> bytes:
        """Export private key as bytes."""
        if self._key_bytes:
            return self._key_bytes
        if self._signer:
            return self._signer.export_secret_key()
        raise PQCryptoError("No key material available")

    def to_hex(self) -> str:
        """Export private key as hex string."""
        return self.to_bytes().hex()

    @property
    def public_key(self) -> PQPublicKey:
        """Get corresponding public key."""
        if self._public_key is None:
            raise PQCryptoError("Public key not initialized")
        return self._public_key

    @property
    def address(self) -> str:
        """Get PQ address for this key."""
        return self.public_key.to_address()

    def sign(self, message: bytes) -> PQSignature:
        """
        Sign a message.

        Args:
            message: Message bytes to sign

        Returns:
            PQSignature object

        Raises:
            PQSignatureError: If signing fails
            TypeError: If message is not bytes
        """
        if not isinstance(message, bytes):
            raise TypeError("Message must be bytes")

        if self._signer is None:
            raise PQCryptoError("Signer not initialized")

        try:
            sig_bytes = self._signer.sign(message)
            return PQSignature(sig_bytes)
        except Exception as e:
            raise PQSignatureError(f"Signing failed: {e}")

    def sign_hash(self, message_hash: bytes) -> PQSignature:
        """
        Sign a pre-hashed message.

        Note: Dilithium internally hashes, so this signs the hash as the message.

        Args:
            message_hash: Pre-hashed message (32 bytes recommended)

        Returns:
            PQSignature object
        """
        return self.sign(message_hash)

    def __repr__(self) -> str:
        if self._public_key:
            return f"PQPrivateKey(address={self.address})"
        return "PQPrivateKey(uninitialized)"


# ============================================================================
# Module-level convenience functions
# ============================================================================


def generate_keypair() -> Tuple[PQPrivateKey, PQPublicKey]:
    """
    Generate a new Dilithium3 / ML-DSA-65 keypair.

    Returns:
        Tuple of (private_key, public_key)
    """
    private_key = PQPrivateKey.generate()
    return private_key, private_key.public_key


def sign(private_key: PQPrivateKey, message: bytes) -> PQSignature:
    """
    Sign a message with a private key.

    Args:
        private_key: PQPrivateKey to sign with
        message: Message bytes to sign

    Returns:
        PQSignature object
    """
    return private_key.sign(message)


def verify(public_key: PQPublicKey, message: bytes, signature: PQSignature) -> bool:
    """
    Verify a signature against a public key.

    SECURITY: This function uses real liboqs verification. There is NO
    fallback that returns True. If verification fails for any reason,
    this returns False.

    Args:
        public_key: PQPublicKey to verify with
        message: Original message bytes
        signature: PQSignature to verify

    Returns:
        True if signature is valid, False otherwise
    """
    if not isinstance(public_key, PQPublicKey):
        return False
    if not isinstance(signature, PQSignature):
        return False
    if not isinstance(message, bytes):
        return False

    try:
        verifier = oqs.Signature(_WORKING_ALGORITHM)
        return verifier.verify(message, signature.to_bytes(), public_key.to_bytes())
    except Exception:
        return False


def is_available() -> bool:
    """
    Check if liboqs is available and working.

    Since this module fails hard at import if liboqs is absent,
    this will always return True if you can call it.
    """
    return True


def get_liboqs_error() -> Optional[str]:
    """
    Get liboqs import error if any.

    Since this module fails hard at import, this always returns None.
    """
    return None


def get_algorithm_info() -> dict:
    """Get information about the signature algorithm."""
    algo = _WORKING_ALGORITHM
    try:
        sig = oqs.Signature(algo)
        details = sig.details
    except Exception:
        details = {}

    return {
        'algorithm': algo,
        'algorithm_family': 'ML-DSA (Dilithium)',
        'nist_standard': 'FIPS 204',
        'private_key_size': PRIVATE_KEY_SIZE,
        'public_key_size': PUBLIC_KEY_SIZE,
        'signature_size': SIGNATURE_SIZE,
        'liboqs_available': True,
        'claimed_nist_level': details.get('claimed_nist_level', 3),
        'is_euf_cma': details.get('is_euf_cma', True),
    }
