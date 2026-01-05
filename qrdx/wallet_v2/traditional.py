"""
QRDX Traditional Wallet (secp256k1)

Ethereum-compatible wallet using secp256k1 ECDSA signatures.
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
from ..crypto import (
    PrivateKey,
    PublicKey,
    public_key_to_address,
    sign_message_hash,
    keccak256,
)


class TraditionalWallet(BaseWallet):
    """
    Traditional secp256k1 wallet.
    
    Compatible with Ethereum and other EVM chains.
    Provides 128-bit security level.
    
    Example:
        # Generate new wallet
        wallet = TraditionalWallet.generate()
        print(wallet.address)  # 0x...
        
        # Sign a message
        message = b"Hello, QRDX!"
        signature = wallet.sign(message)
        
        # Save encrypted
        wallet.save(Path("wallet.json"), "my-password")
        
        # Load wallet
        wallet = TraditionalWallet.load(Path("wallet.json"), "my-password")
    """
    
    def __init__(self, private_key: PrivateKey, metadata: Optional[WalletMetadata] = None):
        """
        Initialize traditional wallet.
        
        Args:
            private_key: secp256k1 private key
            metadata: Optional wallet metadata
        """
        super().__init__(metadata)
        self._private_key = private_key
        self._public_key = private_key.public_key
        self._address = public_key_to_address(self._public_key.to_bytes())
    
    @property
    def wallet_type(self) -> WalletType:
        return WalletType.TRADITIONAL
    
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
    def private_key_hex(self) -> str:
        """
        Get hex-encoded private key.
        
        WARNING: Handle with extreme care!
        """
        return self._private_key.to_hex()
    
    def sign(self, message: bytes) -> bytes:
        """
        Sign a message (hashes first with keccak256).
        
        Args:
            message: Message bytes to sign
            
        Returns:
            65-byte signature (r[32] + s[32] + v[1])
        """
        message_hash = keccak256(message)
        return self.sign_transaction(message_hash)
    
    def sign_transaction(self, tx_hash: bytes) -> bytes:
        """
        Sign a transaction hash.
        
        Args:
            tx_hash: 32-byte transaction hash
            
        Returns:
            65-byte signature (r[32] + s[32] + v[1])
        """
        if len(tx_hash) != 32:
            raise ValueError(f"Transaction hash must be 32 bytes, got {len(tx_hash)}")
        
        signature = sign_message_hash(self._private_key, tx_hash)
        return signature.to_bytes()
    
    def sign_typed_data(self, domain_hash: bytes, struct_hash: bytes) -> bytes:
        """
        Sign EIP-712 typed data.
        
        Args:
            domain_hash: Domain separator hash
            struct_hash: Struct hash
            
        Returns:
            65-byte signature
        """
        # EIP-712: hash = keccak256("\x19\x01" + domainSeparator + structHash)
        message = b'\x19\x01' + domain_hash + struct_hash
        message_hash = keccak256(message)
        return self.sign_transaction(message_hash)
    
    def personal_sign(self, message: bytes) -> bytes:
        """
        Sign with Ethereum personal_sign (EIP-191).
        
        Prefixes message with:
        "\\x19Ethereum Signed Message:\\n" + len(message)
        
        Args:
            message: Message to sign
            
        Returns:
            65-byte signature
        """
        prefix = f"\x19Ethereum Signed Message:\n{len(message)}".encode()
        prefixed = prefix + message
        return self.sign(prefixed)
    
    def export_private_key(self) -> bytes:
        """
        Export raw private key bytes.
        
        WARNING: Handle with extreme care!
        
        Returns:
            32-byte private key
        """
        return self._private_key.to_bytes()
    
    def to_keystore(self, password: str) -> Dict[str, Any]:
        """
        Export to encrypted Web3 keystore format.
        
        Args:
            password: Encryption password
            
        Returns:
            Keystore dictionary
        """
        encrypted = encrypt_key(self._private_key.to_bytes(), password)
        
        return {
            'version': 3,
            'id': os.urandom(16).hex(),
            'address': self._address[2:].lower(),  # Without 0x prefix
            'crypto': encrypted,
            'wallet_type': self.wallet_type.value,
        }
    
    @classmethod
    def from_keystore(cls, keystore: Dict[str, Any], password: str) -> 'TraditionalWallet':
        """
        Load from encrypted keystore.
        
        Args:
            keystore: Keystore dictionary
            password: Decryption password
            
        Returns:
            TraditionalWallet instance
        """
        # Verify wallet type
        wallet_type = keystore.get('wallet_type', 'traditional')
        if wallet_type != 'traditional':
            raise WalletError(f"Expected traditional wallet, got {wallet_type}")
        
        # Decrypt private key
        key_bytes = decrypt_key(keystore['crypto'], password)
        private_key = PrivateKey.from_bytes(key_bytes)
        
        return cls(private_key)
    
    @classmethod
    def generate(cls, name: str = "Traditional Wallet") -> 'TraditionalWallet':
        """
        Generate a new random wallet.
        
        Args:
            name: Wallet name for metadata
            
        Returns:
            New TraditionalWallet instance
        """
        private_key = PrivateKey.generate()
        
        metadata = WalletMetadata(
            name=name,
            wallet_type=WalletType.TRADITIONAL,
            created_at=datetime.now(timezone.utc).isoformat(),
            description="secp256k1 ECDSA wallet",
        )
        
        return cls(private_key, metadata)
    
    @classmethod
    def from_private_key(cls, private_key: bytes) -> 'TraditionalWallet':
        """
        Create wallet from raw private key bytes.
        
        Args:
            private_key: 32-byte private key
            
        Returns:
            TraditionalWallet instance
        """
        pk = PrivateKey.from_bytes(private_key)
        return cls(pk)
    
    @classmethod
    def from_hex(cls, hex_key: str) -> 'TraditionalWallet':
        """
        Create wallet from hex-encoded private key.
        
        Args:
            hex_key: Hex private key (with or without 0x prefix)
            
        Returns:
            TraditionalWallet instance
        """
        if hex_key.startswith('0x'):
            hex_key = hex_key[2:]
        return cls.from_private_key(bytes.fromhex(hex_key))
    
    @classmethod
    def from_mnemonic(cls, mnemonic: str, path: str = "m/44'/60'/0'/0/0") -> 'TraditionalWallet':
        """
        Create wallet from BIP-39 mnemonic.
        
        Args:
            mnemonic: 12 or 24 word mnemonic phrase
            path: Derivation path (default: Ethereum standard)
            
        Returns:
            TraditionalWallet instance
        """
        try:
            from eth_account import Account
            Account.enable_unaudited_hdwallet_features()
            
            acct = Account.from_mnemonic(mnemonic, account_path=path)
            return cls.from_private_key(acct.key)
        except ImportError:
            raise WalletError("eth-account required for mnemonic support: pip install eth-account")
    
    def derive_child(self, index: int) -> 'TraditionalWallet':
        """
        Derive child wallet (non-HD, uses key + index hash).
        
        For proper HD derivation, use from_mnemonic() instead.
        
        Args:
            index: Child index
            
        Returns:
            Derived TraditionalWallet
        """
        child_seed = keccak256(self._private_key.to_bytes() + index.to_bytes(4, 'big'))
        return TraditionalWallet.from_private_key(child_seed)


def generate_mnemonic(strength: int = 128) -> str:
    """
    Generate a new BIP-39 mnemonic phrase.
    
    Args:
        strength: Entropy bits (128 = 12 words, 256 = 24 words)
        
    Returns:
        Mnemonic phrase
    """
    try:
        from eth_account import Account
        Account.enable_unaudited_hdwallet_features()
        
        acct, mnemonic = Account.create_with_mnemonic(num_words=strength // 8 * 3 // 4)
        return mnemonic
    except ImportError:
        raise WalletError("eth-account required for mnemonic generation: pip install eth-account")
