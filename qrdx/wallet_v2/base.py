"""
QRDX Base Wallet Classes

Defines the abstract interface and common functionality for all wallet types.
"""

import os
import json
import hashlib
from abc import ABC, abstractmethod
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from pathlib import Path


class WalletType(Enum):
    """Wallet type enumeration."""
    TRADITIONAL = "traditional"  # secp256k1 ECDSA
    POST_QUANTUM = "pq"          # Dilithium3
    UNIFIED = "unified"          # Contains both types


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
            'name': self.name,
            'wallet_type': self.wallet_type.value,
            'created_at': self.created_at,
            'version': self.version,
            'description': self.description,
            'tags': self.tags,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WalletMetadata':
        return cls(
            name=data['name'],
            wallet_type=WalletType(data['wallet_type']),
            created_at=data['created_at'],
            version=data.get('version', '2.0'),
            description=data.get('description', ''),
            tags=data.get('tags', []),
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
    def from_keystore(cls, keystore: Dict[str, Any], password: str) -> 'BaseWallet':
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
    def generate(cls) -> 'BaseWallet':
        """
        Generate a new random wallet.
        
        Returns:
            New wallet instance
        """
        pass
    
    @classmethod
    @abstractmethod
    def from_private_key(cls, private_key: bytes) -> 'BaseWallet':
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
            keystore['metadata'] = self._metadata.to_dict()
        
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(keystore, f, indent=2)
    
    @classmethod
    def load(cls, path: Path, password: str) -> 'BaseWallet':
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
        
        with open(path, 'r') as f:
            keystore = json.load(f)
        
        wallet = cls.from_keystore(keystore, password)
        
        # Load metadata if present
        if 'metadata' in keystore:
            wallet.metadata = WalletMetadata.from_dict(keystore['metadata'])
        
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
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations,
        dklen=32
    )


def encrypt_key(key_bytes: bytes, password: str) -> Dict[str, Any]:
    """
    Encrypt key bytes with password.
    
    Uses AES-256-GCM via Fernet-style encryption.
    
    Args:
        key_bytes: Key to encrypt
        password: Encryption password
        
    Returns:
        Dictionary with encrypted data and parameters
    """
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        import base64
        
        salt = os.urandom(16)
        iterations = 100000
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        derived_key = kdf.derive(password.encode())
        fernet_key = base64.urlsafe_b64encode(derived_key)
        
        f = Fernet(fernet_key)
        encrypted = f.encrypt(key_bytes)
        
        return {
            'ciphertext': base64.b64encode(encrypted).decode('ascii'),
            'salt': salt.hex(),
            'iterations': iterations,
            'kdf': 'pbkdf2-sha256',
            'cipher': 'fernet',
        }
    except ImportError:
        raise ImportError(
            "The 'cryptography' package is required for wallet encryption. "
            "Install with: pip install cryptography"
        )


def decrypt_key(encrypted: Dict[str, Any], password: str) -> bytes:
    """
    Decrypt key bytes with password.
    
    Args:
        encrypted: Dictionary from encrypt_key()
        password: Decryption password
        
    Returns:
        Decrypted key bytes
        
    Raises:
        WalletDecryptionError: If decryption fails
    """
    try:
        salt = bytes.fromhex(encrypted['salt'])
        
        if encrypted['cipher'] == 'fernet':
            from cryptography.fernet import Fernet, InvalidToken
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            import base64
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=encrypted['iterations'],
            )
            derived_key = kdf.derive(password.encode())
            fernet_key = base64.urlsafe_b64encode(derived_key)
            
            f = Fernet(fernet_key)
            ciphertext = base64.b64decode(encrypted['ciphertext'])
            
            try:
                return f.decrypt(ciphertext)
            except InvalidToken:
                raise WalletDecryptionError("Invalid password")
        
        elif encrypted['cipher'] == 'xor-fallback':
            raise WalletDecryptionError(
                "This wallet was encrypted with the insecure XOR-fallback cipher "
                "which is no longer supported.  Re-create the wallet with the "
                "'cryptography' package installed: pip install cryptography"
            )
        
        else:
            raise WalletDecryptionError(f"Unknown cipher: {encrypted['cipher']}")
            
    except WalletDecryptionError:
        raise
    except Exception as e:
        raise WalletDecryptionError(f"Decryption failed: {e}")
