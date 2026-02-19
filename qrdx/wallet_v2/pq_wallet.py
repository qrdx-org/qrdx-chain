"""
QRDX Post-Quantum Wallet (Dilithium3)

Quantum-resistant wallet using Dilithium3 signatures.
"""

import os
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from pathlib import Path

from .base import (
    BaseWallet,
    WalletType,
    WalletMetadata,
    WalletError,
    WalletDecryptionError,
    encrypt_key,
    decrypt_key,
)
from ..crypto.pq import (
    PQPrivateKey,
    PQPublicKey,
    PQSignature,
    is_available as pq_available,
    get_liboqs_error,
)
from ..crypto import keccak256


class PQWallet(BaseWallet):
    """
    Post-Quantum wallet using Dilithium3.
    
    Provides quantum-resistant signatures with NIST Level 3 security.
    Signatures are larger (~3309 bytes) but provide future-proof security.
    
    REQUIRES liboqs-python. There is NO fallback mode — nodes without
    liboqs cannot operate PQ wallets.
    
    Example:
        # Generate new PQ wallet
        wallet = PQWallet.generate()
        print(wallet.address)  # 0xPQ...
        
        # Sign a message
        message = b"Hello, quantum-safe QRDX!"
        signature = wallet.sign(message)
        
        # Save encrypted
        wallet.save(Path("pq_wallet.json"), "my-password")
    """
    
    def __init__(self, private_key: PQPrivateKey, metadata: Optional[WalletMetadata] = None):
        """
        Initialize PQ wallet.
        
        Args:
            private_key: Dilithium3 private key
            metadata: Optional wallet metadata
        """
        super().__init__(metadata)
        self._private_key = private_key
        self._public_key = private_key.public_key
        self._address = private_key.address
    
    @property
    def wallet_type(self) -> WalletType:
        return WalletType.POST_QUANTUM
    
    @property
    def address(self) -> str:
        return self._address
    
    @property
    def public_key(self) -> bytes:
        return self._public_key.to_bytes()
    
    @property
    def public_key_hex(self) -> str:
        """Get hex-encoded public key."""
        return self._public_key.to_hex()
    
    @property
    def public_key_fingerprint(self) -> str:
        """Get short public key fingerprint."""
        return self._public_key.fingerprint()
    
    def sign(self, message: bytes) -> bytes:
        """
        Sign a message.
        
        Args:
            message: Message bytes to sign
            
        Returns:
            Signature bytes (~3293 bytes)
        """
        signature = self._private_key.sign(message)
        return signature.to_bytes()
    
    def sign_transaction(self, tx_hash: bytes) -> bytes:
        """
        Sign a transaction hash.
        
        Args:
            tx_hash: Transaction hash (typically 32 bytes)
            
        Returns:
            Signature bytes
        """
        return self.sign(tx_hash)
    
    def sign_with_prefix(self, message: bytes) -> bytes:
        """
        Sign with QRDX prefix (similar to EIP-191).
        
        Prefixes message with:
        "\\x19QRDX PQ Signed Message:\\n" + len(message)
        
        Args:
            message: Message to sign
            
        Returns:
            Signature bytes
        """
        prefix = f"\x19QRDX PQ Signed Message:\n{len(message)}".encode()
        prefixed = prefix + message
        return self.sign(prefixed)
    
    def export_private_key(self) -> bytes:
        """
        Export raw private key bytes.
        
        WARNING: Handle with extreme care!
        PQ private keys are larger (~4000 bytes).
        
        Returns:
            Private key bytes
        """
        return self._private_key.to_bytes()
    
    def to_keystore(self, password: str) -> Dict[str, Any]:
        """
        Export to encrypted keystore format.
        
        Args:
            password: Encryption password
            
        Returns:
            Keystore dictionary
        """
        encrypted = encrypt_key(self._private_key.to_bytes(), password)
        
        return {
            'version': 1,
            'id': os.urandom(16).hex(),
            'address': self._address,
            'public_key': self._public_key.to_hex(),  # Store public key for restoration
            'public_key_fingerprint': self.public_key_fingerprint,
            'crypto': encrypted,
            'wallet_type': self.wallet_type.value,
            'algorithm': 'ML-DSA-65',
        }
    
    @classmethod
    def from_keystore(cls, keystore: Dict[str, Any], password: str) -> 'PQWallet':
        """
        Load from encrypted keystore.
        
        Args:
            keystore: Keystore dictionary
            password: Decryption password
            
        Returns:
            PQWallet instance
        """
        # Verify wallet type
        wallet_type = keystore.get('wallet_type', 'pq')
        if wallet_type != 'pq':
            raise WalletError(f"Expected PQ wallet, got {wallet_type}")
        
        # Decrypt private key
        key_bytes = decrypt_key(keystore['crypto'], password)
        
        # Restore public key from keystore (important for correct address)
        public_key_hex = keystore.get('public_key')
        if public_key_hex:
            from ..crypto.pq import PQPublicKey
            public_key = PQPublicKey.from_hex(public_key_hex)
            private_key = PQPrivateKey.from_bytes(key_bytes, public_key=public_key)
        else:
            # Legacy keystore without public key - will generate different address!
            private_key = PQPrivateKey.from_bytes(key_bytes)
        
        return cls(private_key)
    
    @classmethod
    def generate(cls, name: str = "Post-Quantum Wallet") -> 'PQWallet':
        """
        Generate a new random PQ wallet.
        
        Args:
            name: Wallet name for metadata
            
        Returns:
            New PQWallet instance
        """
        if not pq_available():
            import warnings
            warnings.warn(
                f"liboqs not available ({get_liboqs_error()}). "
                "Using fallback mode - NOT SECURE for production!"
            )
        
        private_key = PQPrivateKey.generate()
        
        metadata = WalletMetadata(
            name=name,
            wallet_type=WalletType.POST_QUANTUM,
            created_at=datetime.now(timezone.utc).isoformat(),
            description="Dilithium3 post-quantum wallet",
        )
        
        return cls(private_key, metadata)
    
    @classmethod
    def from_private_key(cls, private_key: bytes) -> 'PQWallet':
        """
        Create wallet from raw private key bytes.
        
        Args:
            private_key: Private key bytes
            
        Returns:
            PQWallet instance
        """
        pk = PQPrivateKey.from_bytes(private_key)
        return cls(pk)
    
    @classmethod
    def from_hex(cls, hex_key: str) -> 'PQWallet':
        """
        Create wallet from hex-encoded private key.
        
        Args:
            hex_key: Hex private key (with or without 0x prefix)
            
        Returns:
            PQWallet instance
        """
        if hex_key.startswith('0x'):
            hex_key = hex_key[2:]
        return cls.from_private_key(bytes.fromhex(hex_key))
    
    @classmethod
    def from_seed(cls, seed: bytes) -> 'PQWallet':
        """
        Create deterministic wallet from seed.
        
        Args:
            seed: Seed bytes (at least 32 bytes)
            
        Returns:
            PQWallet instance
        """
        private_key = PQPrivateKey.from_seed(seed)
        return cls(private_key)
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature against this wallet's public key.
        
        Args:
            message: Original message
            signature: Signature bytes
            
        Returns:
            True if valid
        """
        from ..crypto.pq import verify
        sig = PQSignature.from_bytes(signature)
        return verify(self._public_key, message, sig)
    
    @staticmethod
    def is_pq_available() -> bool:
        """Check if liboqs is available."""
        return pq_available()
