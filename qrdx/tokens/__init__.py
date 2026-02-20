"""
QRDX Token Standard (qRC20) — Whitepaper §9

Provides:
  - QRC20Token       : PQ-verified fungible token with ERC-20–style interface
  - QRC20Registry    : Global token registry (deploy / lookup)
  - DoomsdayHook     : Advisory trading flag after Doomsday activation
"""

from .qrc20 import (
    QRC20Token,
    QRC20Registry,
    QRC20TransferEvent,
    QRC20ApprovalEvent,
    QRC20Error,
    InsufficientBalanceError,
    InsufficientAllowanceError,
)
from .doomsday_hook import (
    DoomsdayHook,
    DoomsdayTradingMode,
    DoomsdayTradingPreference,
)

__all__ = [
    # Core token
    "QRC20Token",
    "QRC20Registry",
    "QRC20TransferEvent",
    "QRC20ApprovalEvent",
    "QRC20Error",
    "InsufficientBalanceError",
    "InsufficientAllowanceError",
    # Doomsday hook
    "DoomsdayHook",
    "DoomsdayTradingMode",
    "DoomsdayTradingPreference",
]
