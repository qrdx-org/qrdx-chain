"""
shouldTradeAfterDoomsday() Hook — Whitepaper §9.2

Provides advisory trading flags for qRC20 tokens when the Doomsday
Protocol is active.  Three client modes are supported (Strict, Warning,
Permissionless) — enforcement is entirely client-side.

Integration:
  - Reads ``DoomsdayProtocol.is_active`` from qrdx.bridge.shielding
  - Each token carries a per-deployment ``post_doomsday_trade`` flag
  - The DoomsdayHook aggregates both signals for client use
"""

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional

from ..logger import get_logger

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════
#  ENUMS
# ══════════════════════════════════════════════════════════════════════

class DoomsdayTradingMode(IntEnum):
    """Client enforcement mode (§9.3)."""
    STRICT = 1          # Block trading UI for tokens returning False
    WARNING = 2         # Show warning, allow user to proceed (recommended)
    PERMISSIONLESS = 3  # Ignore flag entirely


# ══════════════════════════════════════════════════════════════════════
#  PREFERENCE RECORD
# ══════════════════════════════════════════════════════════════════════

@dataclass
class DoomsdayTradingPreference:
    """
    Per-token advisory preference returned by shouldTradeAfterDoomsday().

    Attributes:
        token_symbol:       Token ticker (e.g. "qETH")
        should_trade:       True if token is backed by locked classical assets
        reason:             Human-readable reason
        doomsday_active:    Whether the Doomsday Protocol is currently triggered
        updated_at:         Timestamp of last evaluation
    """
    token_symbol: str
    should_trade: bool
    reason: str
    doomsday_active: bool
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tokenSymbol": self.token_symbol,
            "shouldTrade": self.should_trade,
            "reason": self.reason,
            "doomsdayActive": self.doomsday_active,
            "updatedAt": self.updated_at,
        }


# ══════════════════════════════════════════════════════════════════════
#  DOOMSDAY HOOK
# ══════════════════════════════════════════════════════════════════════

class DoomsdayHook:
    """
    Evaluates ``shouldTradeAfterDoomsday()`` for any qRC20 token.

    Usage::

        from qrdx.bridge.shielding import DoomsdayProtocol
        doomsday = DoomsdayProtocol()
        hook = DoomsdayHook(doomsday_protocol=doomsday)

        pref = hook.should_trade_after_doomsday(token)
        if not pref.should_trade and mode == DoomsdayTradingMode.STRICT:
            raise TradingDisabledError(...)
    """

    def __init__(self, doomsday_protocol=None):
        """
        Args:
            doomsday_protocol: Instance of DoomsdayProtocol (or duck-typed
                               object with an ``is_active`` bool property).
        """
        self._protocol = doomsday_protocol
        self._preference_cache: Dict[str, DoomsdayTradingPreference] = {}

    # ── Public API ────────────────────────────────────────────────────

    @property
    def is_doomsday_active(self) -> bool:
        """Check whether Doomsday has been triggered."""
        if self._protocol is None:
            return False
        return self._protocol.is_active

    def should_trade_after_doomsday(self, token) -> DoomsdayTradingPreference:
        """
        Evaluate advisory trading preference for *token*.

        Args:
            token: A QRC20Token (or any object with ``.symbol`` and
                   ``.post_doomsday_trade`` attributes).

        Returns:
            DoomsdayTradingPreference
        """
        doomsday_active = self.is_doomsday_active

        # If doomsday is NOT active, all tokens can trade normally
        if not doomsday_active:
            pref = DoomsdayTradingPreference(
                token_symbol=token.symbol,
                should_trade=True,
                reason="Doomsday not active — normal trading",
                doomsday_active=False,
            )
            self._preference_cache[token.symbol] = pref
            return pref

        # Doomsday IS active — consult per-token flag
        should = getattr(token, "post_doomsday_trade", False)

        if should:
            reason = (
                f"{token.symbol} is backed by locked classical assets; "
                "trading remains advisable."
            )
        else:
            reason = (
                f"{token.symbol} has no classical backing; "
                "trading is NOT advisable during Doomsday."
            )

        pref = DoomsdayTradingPreference(
            token_symbol=token.symbol,
            should_trade=should,
            reason=reason,
            doomsday_active=True,
        )
        self._preference_cache[token.symbol] = pref
        logger.info(
            f"Doomsday trade advisory: {token.symbol} → "
            f"{'TRADE' if should else 'NO_TRADE'}"
        )
        return pref

    def evaluate_all(self, tokens) -> List[DoomsdayTradingPreference]:
        """Evaluate all tokens in a list or registry."""
        results = []
        for token in tokens:
            results.append(self.should_trade_after_doomsday(token))
        return results

    def check_client_mode(
        self,
        token,
        mode: DoomsdayTradingMode = DoomsdayTradingMode.WARNING,
    ) -> Dict[str, Any]:
        """
        Apply client enforcement mode to the advisory.

        Returns a dict with:
          - allowed: bool   (whether trading should proceed)
          - warning: str    (warning text if mode == WARNING)
          - preference: DoomsdayTradingPreference
        """
        pref = self.should_trade_after_doomsday(token)

        if mode == DoomsdayTradingMode.PERMISSIONLESS:
            return {
                "allowed": True,
                "warning": "",
                "preference": pref,
            }

        if mode == DoomsdayTradingMode.STRICT:
            return {
                "allowed": pref.should_trade,
                "warning": "" if pref.should_trade else pref.reason,
                "preference": pref,
            }

        # WARNING mode (default, recommended)
        return {
            "allowed": True,
            "warning": "" if pref.should_trade else pref.reason,
            "preference": pref,
        }

    def get_cached_preference(self, symbol: str) -> Optional[DoomsdayTradingPreference]:
        return self._preference_cache.get(symbol)

    def clear_cache(self):
        self._preference_cache.clear()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "doomsdayActive": self.is_doomsday_active,
            "cachedPreferences": {
                s: p.to_dict() for s, p in self._preference_cache.items()
            },
        }

    def __repr__(self) -> str:
        return (
            f"<DoomsdayHook active={self.is_doomsday_active} "
            f"cached={len(self._preference_cache)}>"
        )
