"""
The Doomsday advisory hook — Whitepaper §9.2.

Tokens are the native token standard (qrdx/exchange/tokens.py, docs/NATIVE_TOKENS.md); a token's
deployer sets the ``post_doomsday_trade`` extension. The in-memory qRC20 class that used to live
here backed no consensus path and is retired.
"""

from .doomsday_hook import (
    DoomsdayHook,
    DoomsdayTradingMode,
    DoomsdayTradingPreference,
)

__all__ = [
    "DoomsdayHook",
    "DoomsdayTradingMode",
    "DoomsdayTradingPreference",
]
