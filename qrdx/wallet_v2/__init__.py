"""
QRDX Unified Wallet Module

Provides wallet functionality supporting both:
- Traditional wallets (secp256k1, Ethereum-compatible)
- Post-Quantum wallets (Dilithium3, quantum-resistant)
"""

from .base import WalletType, BaseWallet, WalletError, WalletNotFoundError, WalletDecryptionError
from .traditional import TraditionalWallet

# Lazy imports for PQ wallet to avoid liboqs dependency issues
def __getattr__(name):
    """Lazy loading for PQ wallet classes."""
    if name == 'PQWallet':
        from .pq_wallet import PQWallet
        return PQWallet
    elif name == 'UnifiedWallet':
        from .unified import UnifiedWallet
        return UnifiedWallet
    elif name == 'load_wallet':
        from .unified import load_wallet
        return load_wallet
    elif name == 'create_wallet':
        from .unified import create_wallet
        return create_wallet
    raise AttributeError(f"module 'qrdx.wallet_v2' has no attribute {name!r}")

__all__ = [
    'WalletType',
    'BaseWallet',
    'WalletError',
    'WalletNotFoundError',
    'WalletDecryptionError',
    'TraditionalWallet',
    'PQWallet',
    'UnifiedWallet',
    'load_wallet',
    'create_wallet',
]
