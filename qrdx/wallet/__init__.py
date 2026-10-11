"""
QRDX Wallet Package

Provides:
  - PrefundedWalletManager: Hierarchical sub-wallet management (§6.2)
  - SpendingPolicy / SpendingScope: Budget and scope constraints
  - SubWallet: Delegated spending wallet
  - AutoRefillRule: Automatic balance refilling
"""

from .multisig import (
    AutoRefillRule,
    PrefundedWalletManager,
    SpendingPolicy,
    SpendingScope,
    SubWallet,
)

__all__ = [
    "SpendingScope",
    "SpendingPolicy",
    "AutoRefillRule",
    "SubWallet",
    "PrefundedWalletManager",
]
