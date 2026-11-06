"""
QRDX Base Wallet Classes

Defines the abstract interface and common functionality for all wallet types.
"""

import hashlib
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class WalletType(Enum):
    """Wallet type enumeration."""

    TRADITIONAL = "traditional"  # secp256k1 ECDSA
    POST_QUANTUM = "pq"  # ML-DSA-65
    UNIFIED = "unified"  # Contains both types


class WalletError(Exception):
    """Base wallet error."""

    pass


class WalletNotFoundError(WalletError):
    """Wallet file not found."""

    pass


class WalletDecryptionError(WalletError):
    """Failed to decrypt wallet."""

    pass


class WalletInvalidError(WalletError):
    """Wallet file is invalid or corrupted."""

    pass


class InsufficientFundsError(WalletError):
    """Insufficient balance for transaction."""

    pass


@dataclass
class WalletMetadata:
    """
    Wallet metadata.

    Stored alongside wallet data for identification and management.
    """

    name: str
    wallet_type: WalletType
    created_at: str
    version: str = "2.0"
    description: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "wallet_type": self.wallet_type.value,
            "created_at": self.created_at,
            "version": self.version,
            "description": self.description,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WalletMetadata":
        return cls(
            name=data["name"],
            wallet_type=WalletType(data["wallet_type"]),
            created_at=data["created_at"],
            version=data.get("version", "2.0"),
            description=data.get("description", ""),
            tags=data.get("tags", []),
        )


class BaseWallet(ABC):
    """
    Abstract base class for all wallet types.

    Provides common interface for key management, signing, and serialization.
    """

    def __init__(self, metadata: Optional[WalletMetadata] = None):
        """
        Initialize wallet.

        Args:
            metadata: Optional wallet metadata
        """
        self._metadata = metadata

    @property
    def metadata(self) -> Optional[WalletMetadata]:
        """Get wallet metadata."""
        return self._metadata

    @metadata.setter
    def metadata(self, value: WalletMetadata):
        """Set wallet metadata."""
        self._metadata = value

    @property
    @abstractmethod
    def wallet_type(self) -> WalletType:
        """Get wallet type."""
        pass

    @property
    @abstractmethod
    def address(self) -> str:
        """Get wallet address."""
        pass

    @property
    @abstractmethod
    def public_key(self) -> bytes:
        """Get public key bytes."""
        pass

    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        """
        Sign a message.

        Args:
            message: Message bytes to sign

        Returns:
            Signature bytes
        """
        pass

    @abstractmethod
    def sign_transaction(self, tx_hash: bytes) -> bytes:
        """
        Sign a transaction hash.

        Args:
            tx_hash: Transaction hash (32 bytes)

        Returns:
            Signature bytes
        """
        pass

    @abstractmethod
    def export_private_key(self) -> bytes:
        """
        Export private key bytes.

        WARNING: Handle with extreme care!

        Returns:
            Private key bytes
        """
        pass

    @abstractmethod
    def to_keystore(self, password: str) -> Dict[str, Any]:
        """
        Export wallet to encrypted keystore format.

        Args:
            password: Encryption password

        Returns:
            Keystore dictionary (JSON-serializable)
        """
        pass

    @classmethod
    @abstractmethod
    def from_keystore(cls, keystore: Dict[str, Any], password: str) -> "BaseWallet":
        """
        Load wallet from encrypted keystore.

        Args:
            keystore: Keystore dictionary
            password: Decryption password

        Returns:
            Wallet instance
        """
        pass

    @classmethod
    @abstractmethod
    def generate(cls) -> "BaseWallet":
        """
        Generate a new random wallet.

        Returns:
            New wallet instance
        """
        pass

    @classmethod
    @abstractmethod
    def from_private_key(cls, private_key: bytes) -> "BaseWallet":
        """
        Create wallet from private key.

        Args:
            private_key: Private key bytes

        Returns:
            Wallet instance
        """
        pass

    def save(self, path: Path, password: str) -> None:
        """
        Save wallet to encrypted file.

        Args:
            path: File path to save to
            password: Encryption password
        """
        keystore = self.to_keystore(password)

        # Add metadata if present
        if self._metadata:
            keystore["metadata"] = self._metadata.to_dict()

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(keystore, f, indent=2)

    @classmethod
    def load(cls, path: Path, password: str) -> "BaseWallet":
        """
        Load wallet from encrypted file.

        Args:
            path: File path to load from
            password: Decryption password

        Returns:
            Wallet instance
        """
        if not path.exists():
            raise WalletNotFoundError(f"Wallet not found: {path}")

        with open(path, "r") as f:
            keystore = json.load(f)

        wallet = cls.from_keystore(keystore, password)

        # Load metadata if present
        if "metadata" in keystore:
            wallet.metadata = WalletMetadata.from_dict(keystore["metadata"])

        return wallet

    def fingerprint(self) -> str:
        """
        Get short wallet fingerprint for display.

        Returns:
            8-character hex fingerprint
        """
        return hashlib.sha256(self.public_key).hexdigest()[:8]

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(address={self.address})"


def derive_key_from_password(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    """
    Derive encryption key from password using PBKDF2.

    Args:
        password: User password
        salt: Random salt (16+ bytes)
        iterations: PBKDF2 iterations

    Returns:
        32-byte derived key
    """
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)


# The keystore cipher. A key is encrypted with AES-256-GCM under a key derived from the password
# by scrypt, and the ciphertext is bound to what the keystore says it holds (``aad``: for a PQ
# wallet its address and public key), so a file whose public key was swapped does not decrypt.
# AES-256 keeps 128-bit security against Grover's algorithm; the older "fernet" cipher (AES-128
# under PBKDF2) is still read, never written. The scrypt cost is the EIP-2335 keystore's: about
# 256 MiB and a second per attempt.
KEYSTORE_CIPHER = "aes-256-gcm"
KEYSTORE_KDF = "scrypt"
SCRYPT_N = 2**18
SCRYPT_R = 8
SCRYPT_P = 1
# What a keystore may ask of the machine that opens it: bounded so a crafted file cannot make
# loading it take unbounded memory or time, and floored so it cannot ask for a trivial KDF.
_SCRYPT_N_RANGE = (2**14, 2**20)
_SCRYPT_RP_MAX = 64


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8"))


def encrypt_key(key_bytes: bytes, password: str, aad: bytes = b"") -> Dict[str, Any]:
    """
    Encrypt key bytes with a password: AES-256-GCM under a scrypt-derived key.

    Args:
        key_bytes: Key to encrypt
        password: Encryption password
        aad: What the ciphertext is bound to; decrypting needs the same bytes

    Returns:
        Dictionary with encrypted data and parameters
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if not password:
        raise WalletError("a keystore needs a password")
    salt, nonce = os.urandom(32), os.urandom(12)
    key = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    return {
        "cipher": KEYSTORE_CIPHER,
        "ciphertext": AESGCM(key).encrypt(nonce, key_bytes, aad).hex(),
        "nonce": nonce.hex(),
        "kdf": KEYSTORE_KDF,
        "kdfparams": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": salt.hex()},
    }


def decrypt_key(encrypted: Dict[str, Any], password: str, aad: bytes = b"") -> bytes:
    """
    Decrypt key bytes with a password.

    Args:
        encrypted: Dictionary from encrypt_key()
        password: Decryption password
        aad: The bytes the ciphertext was bound to (``aes-256-gcm`` only)

    Returns:
        Decrypted key bytes

    Raises:
        WalletDecryptionError: If decryption fails
    """
    try:
        cipher = encrypted.get("cipher")
        if cipher == KEYSTORE_CIPHER:
            from cryptography.exceptions import InvalidTag
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            if encrypted.get("kdf") != KEYSTORE_KDF:
                raise WalletDecryptionError(f"Unknown key derivation: {encrypted.get('kdf')}")
            params = encrypted["kdfparams"]
            n, r, p = int(params["n"]), int(params["r"]), int(params["p"])
            if not (_SCRYPT_N_RANGE[0] <= n <= _SCRYPT_N_RANGE[1]) or n & (n - 1):
                raise WalletDecryptionError(f"scrypt n={n} is outside what a keystore may use")
            if not (1 <= r <= _SCRYPT_RP_MAX and 1 <= p <= _SCRYPT_RP_MAX):
                raise WalletDecryptionError(
                    f"scrypt r={r} p={p} is outside what a keystore may use"
                )
            key = _scrypt(password, bytes.fromhex(params["salt"]), n, r, p)
            try:
                return AESGCM(key).decrypt(
                    bytes.fromhex(encrypted["nonce"]), bytes.fromhex(encrypted["ciphertext"]), aad
                )
            except InvalidTag as exc:
                raise WalletDecryptionError(
                    "Invalid password, or the keystore was altered"
                ) from exc

        if cipher == "fernet":
            # Legacy keystores (AES-128 under PBKDF2-SHA256): read so they can be re-encrypted.
            import base64

            from cryptography.fernet import Fernet, InvalidToken
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=bytes.fromhex(encrypted["salt"]),
                iterations=encrypted["iterations"],
            )
            fernet_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            try:
                return Fernet(fernet_key).decrypt(base64.b64decode(encrypted["ciphertext"]))
            except InvalidToken as exc:
                raise WalletDecryptionError("Invalid password") from exc

        if cipher == "xor-fallback":
            raise WalletDecryptionError(
                "This wallet was encrypted with the insecure XOR-fallback cipher "
                "which is no longer supported.  Re-create the wallet with the "
                "'cryptography' package installed: pip install cryptography"
            )

        raise WalletDecryptionError(f"Unknown cipher: {cipher}")

    except WalletDecryptionError:
        raise
    except Exception as e:
        raise WalletDecryptionError(f"Decryption failed: {e}") from e
