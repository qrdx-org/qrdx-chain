"""
QRDX Unified Wallet

Manages both traditional (secp256k1) and post-quantum (Dilithium) wallets
in a single interface.
"""

import os
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Union, Tuple
from pathlib import Path

from .base import (
    BaseWallet,
    WalletType,
    WalletMetadata,
    WalletError,
    WalletNotFoundError,
    encrypt_key,
    decrypt_key,
)
from .traditional import TraditionalWallet
from .pq_wallet import PQWallet


class UnifiedWallet:
    """
    Unified wallet containing both traditional and PQ keys.
    
    Allows users to have a single wallet file with both key types,
    providing both Ethereum compatibility and quantum resistance.
    
    Example:
        # Generate unified wallet
        wallet = UnifiedWallet.generate()
        print(wallet.traditional.address)  # 0x...
        print(wallet.pq.address)           # 0xPQ...
        
        # Sign with either key type
        sig_trad = wallet.sign(message, WalletType.TRADITIONAL)
        sig_pq = wallet.sign(message, WalletType.POST_QUANTUM)
        
        # Save single encrypted file
        wallet.save(Path("unified_wallet.json"), "my-password")
    """
    
    def __init__(
        self,
        traditional: Optional[TraditionalWallet] = None,
        pq: Optional[PQWallet] = None,
        metadata: Optional[WalletMetadata] = None,
    ):
        """
        Initialize unified wallet.
        
        Args:
            traditional: Traditional wallet (optional)
            pq: Post-quantum wallet (optional)
            metadata: Wallet metadata
        """
        if traditional is None and pq is None:
            raise WalletError("At least one wallet type required")
        
        self._traditional = traditional
        self._pq = pq
        self._metadata = metadata
    
    @property
    def wallet_type(self) -> WalletType:
        return WalletType.UNIFIED
    
    @property
    def metadata(self) -> Optional[WalletMetadata]:
        return self._metadata
    
    @property
    def traditional(self) -> Optional[TraditionalWallet]:
        """Get traditional wallet."""
        return self._traditional
    
    @property
    def pq(self) -> Optional[PQWallet]:
        """Get post-quantum wallet."""
        return self._pq
    
    @property
    def has_traditional(self) -> bool:
        """Check if traditional wallet is present."""
        return self._traditional is not None
    
    @property
    def has_pq(self) -> bool:
        """Check if PQ wallet is present."""
        return self._pq is not None
    
    @property
    def addresses(self) -> Dict[str, str]:
        """Get all addresses."""
        result = {}
        if self._traditional:
            result['traditional'] = self._traditional.address
        if self._pq:
            result['pq'] = self._pq.address
        return result
    
    @property
    def primary_address(self) -> str:
        """
        Get primary address (traditional if available, else PQ).
        """
        if self._traditional:
            return self._traditional.address
        return self._pq.address
    
    def get_wallet(self, wallet_type: WalletType) -> BaseWallet:
        """
        Get specific wallet by type.
        
        Args:
            wallet_type: Wallet type to get
            
        Returns:
            Wallet instance
        """
        if wallet_type == WalletType.TRADITIONAL:
            if not self._traditional:
                raise WalletError("No traditional wallet in this unified wallet")
            return self._traditional
        elif wallet_type == WalletType.POST_QUANTUM:
            if not self._pq:
                raise WalletError("No PQ wallet in this unified wallet")
            return self._pq
        else:
            raise WalletError(f"Invalid wallet type: {wallet_type}")
    
    def sign(self, message: bytes, wallet_type: WalletType = WalletType.TRADITIONAL) -> bytes:
        """
        Sign message with specified wallet type.
        
        Args:
            message: Message to sign
            wallet_type: Which wallet to use
            
        Returns:
            Signature bytes
        """
        return self.get_wallet(wallet_type).sign(message)
    
    def sign_transaction(
        self,
        tx_hash: bytes,
        wallet_type: WalletType = WalletType.TRADITIONAL
    ) -> bytes:
        """
        Sign transaction hash with specified wallet type.
        
        Args:
            tx_hash: Transaction hash
            wallet_type: Which wallet to use
            
        Returns:
            Signature bytes
        """
        return self.get_wallet(wallet_type).sign_transaction(tx_hash)
    
    def sign_dual(self, message: bytes) -> Tuple[bytes, bytes]:
        """
        Sign with both wallet types.
        
        Args:
            message: Message to sign
            
        Returns:
            Tuple of (traditional_sig, pq_sig)
        """
        if not self.has_traditional or not self.has_pq:
            raise WalletError("Dual signing requires both wallet types")
        
        return (
            self._traditional.sign(message),
            self._pq.sign(message),
        )
    
    def to_keystore(self, password: str) -> Dict[str, Any]:
        """
        Export to encrypted keystore format.
        
        Args:
            password: Encryption password
            
        Returns:
            Keystore dictionary
        """
        keystore = {
            'version': 1,
            'id': os.urandom(16).hex(),
            'wallet_type': 'unified',
            'wallets': {},
        }
        
        if self._traditional:
            keystore['wallets']['traditional'] = self._traditional.to_keystore(password)
        
        if self._pq:
            keystore['wallets']['pq'] = self._pq.to_keystore(password)
        
        if self._metadata:
            keystore['metadata'] = self._metadata.to_dict()
        
        return keystore
    
    @classmethod
    def from_keystore(cls, keystore: Dict[str, Any], password: str) -> 'UnifiedWallet':
        """
        Load from encrypted keystore.
        
        Args:
            keystore: Keystore dictionary
            password: Decryption password
            
        Returns:
            UnifiedWallet instance
        """
        wallet_type = keystore.get('wallet_type', 'unified')
        if wallet_type != 'unified':
            raise WalletError(f"Expected unified wallet, got {wallet_type}")
        
        wallets = keystore.get('wallets', {})
        
        traditional = None
        pq = None
        
        if 'traditional' in wallets:
            traditional = TraditionalWallet.from_keystore(wallets['traditional'], password)
        
        if 'pq' in wallets:
            pq = PQWallet.from_keystore(wallets['pq'], password)
        
        metadata = None
        if 'metadata' in keystore:
            metadata = WalletMetadata.from_dict(keystore['metadata'])
        
        return cls(traditional, pq, metadata)
    
    @classmethod
    def generate(
        cls,
        name: str = "Unified Wallet",
        include_traditional: bool = True,
        include_pq: bool = True,
    ) -> 'UnifiedWallet':
        """
        Generate a new unified wallet.
        
        Args:
            name: Wallet name
            include_traditional: Include secp256k1 wallet
            include_pq: Include Dilithium wallet
            
        Returns:
            New UnifiedWallet instance
        """
        if not include_traditional and not include_pq:
            raise WalletError("At least one wallet type must be included")
        
        traditional = None
        pq = None
        
        if include_traditional:
            traditional = TraditionalWallet.generate(f"{name} (Traditional)")
        
        if include_pq:
            pq = PQWallet.generate(f"{name} (PQ)")
        
        metadata = WalletMetadata(
            name=name,
            wallet_type=WalletType.UNIFIED,
            created_at=datetime.now(timezone.utc).isoformat(),
            description="Unified wallet with traditional and post-quantum keys",
        )
        
        return cls(traditional, pq, metadata)
    
    def save(self, path: Path, password: str) -> None:
        """
        Save wallet to encrypted file.
        
        Args:
            path: File path
            password: Encryption password
        """
        keystore = self.to_keystore(password)
        
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(keystore, f, indent=2)
    
    @classmethod
    def load(cls, path: Path, password: str) -> 'UnifiedWallet':
        """
        Load wallet from encrypted file.
        
        Args:
            path: File path
            password: Decryption password
            
        Returns:
            UnifiedWallet instance
        """
        if not path.exists():
            raise WalletNotFoundError(f"Wallet not found: {path}")
        
        with open(path, 'r') as f:
            keystore = json.load(f)
        
        return cls.from_keystore(keystore, password)
    
    def __repr__(self) -> str:
        parts = []
        if self._traditional:
            parts.append(f"traditional={self._traditional.address}")
        if self._pq:
            parts.append(f"pq={self._pq.address}")
        return f"UnifiedWallet({', '.join(parts)})"


def load_wallet(path: Path, password: str) -> Union[TraditionalWallet, PQWallet, UnifiedWallet]:
    """
    Load any wallet type from file.
    
    Automatically detects wallet type and returns appropriate instance.
    
    Args:
        path: Wallet file path
        password: Decryption password
        
    Returns:
        Wallet instance (TraditionalWallet, PQWallet, or UnifiedWallet)
    """
    if not path.exists():
        raise WalletNotFoundError(f"Wallet not found: {path}")
    
    with open(path, 'r') as f:
        keystore = json.load(f)
    
    wallet_type = keystore.get('wallet_type', 'traditional')
    
    if wallet_type == 'unified':
        return UnifiedWallet.from_keystore(keystore, password)
    elif wallet_type == 'pq':
        return PQWallet.from_keystore(keystore, password)
    else:
        return TraditionalWallet.from_keystore(keystore, password)


def create_wallet(
    wallet_type: WalletType = WalletType.TRADITIONAL,
    name: str = "My Wallet",
) -> Union[TraditionalWallet, PQWallet, UnifiedWallet]:
    """
    Create a new wallet of specified type.
    
    Args:
        wallet_type: Type of wallet to create
        name: Wallet name
        
    Returns:
        New wallet instance
    """
    if wallet_type == WalletType.TRADITIONAL:
        return TraditionalWallet.generate(name)
    elif wallet_type == WalletType.POST_QUANTUM:
        return PQWallet.generate(name)
    elif wallet_type == WalletType.UNIFIED:
        return UnifiedWallet.generate(name)
    else:
        raise WalletError(f"Unknown wallet type: {wallet_type}")
