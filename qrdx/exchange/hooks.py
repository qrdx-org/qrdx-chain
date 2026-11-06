"""
QRDX Exchange Hook System  (Whitepaper §7 — extensibility)

Provides a hook interface for extending exchange behaviour:
  - beforeSwap / afterSwap
  - beforeLiquidity / afterLiquidity

Hooks run synchronously within the transaction and can:
  - Inspect parameters and revert the operation
  - Modify fee rates
  - Collect analytics
  - Enforce additional security constraints

All hooks are deterministic and consensus-safe.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Flag, auto
from typing import Any, Dict, List, Optional, Protocol

logger = logging.getLogger(__name__)

ZERO = Decimal("0")


# ---------------------------------------------------------------------------
# Hook flags — which hooks a plugin wants to receive
# ---------------------------------------------------------------------------


class HookFlags(Flag):
    NONE = 0
    BEFORE_SWAP = auto()
    AFTER_SWAP = auto()
    BEFORE_LIQUIDITY = auto()
    AFTER_LIQUIDITY = auto()
    ALL = BEFORE_SWAP | AFTER_SWAP | BEFORE_LIQUIDITY | AFTER_LIQUIDITY


# ---------------------------------------------------------------------------
# Hook context — data passed to hooks
# ---------------------------------------------------------------------------


@dataclass
class HookContext:
    """Data passed to hook callbacks."""

    pool_id: str = ""
    sender: str = ""
    token_in: str = ""
    token_out: str = ""
    amount_in: Decimal = ZERO
    amount_out: Decimal = ZERO
    fee: Decimal = ZERO
    tick_lower: int = 0
    tick_upper: int = 0
    liquidity: Decimal = ZERO
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HookResult:
    """Result from a hook execution."""

    allow: bool = True  # False = revert the operation
    reason: str = ""  # reason for revert (if allow=False)
    modified_fee: Optional[Decimal] = None  # optional fee override


# ---------------------------------------------------------------------------
# Hook interface (Protocol for structural typing)
# ---------------------------------------------------------------------------


class ExchangeHook(Protocol):
    """Protocol that exchange hooks must implement."""

    @property
    def flags(self) -> HookFlags: ...

    def on_before_swap(self, ctx: HookContext) -> HookResult: ...
    def on_after_swap(self, ctx: HookContext) -> HookResult: ...
    def on_before_liquidity(self, ctx: HookContext) -> HookResult: ...
    def on_after_liquidity(self, ctx: HookContext) -> HookResult: ...


# ---------------------------------------------------------------------------
# Hook Registry — manages all registered hooks
# ---------------------------------------------------------------------------


class HookRegistry:
    """
    Central registry for exchange hooks.

    Hooks are executed in registration order. If any hook
    returns allow=False, the operation is reverted.
    """

    def __init__(self) -> None:
        self._hooks: List[ExchangeHook] = []

    def register(self, hook: ExchangeHook) -> None:
        self._hooks.append(hook)
        logger.info("Hook registered: %s (flags=%s)", type(hook).__name__, hook.flags)

    def unregister(self, hook: ExchangeHook) -> None:
        self._hooks = [h for h in self._hooks if h is not hook]

    @property
    def hook_count(self) -> int:
        return len(self._hooks)

    def run_before_swap(self, ctx: HookContext) -> HookResult:
        return self._run(HookFlags.BEFORE_SWAP, "on_before_swap", ctx)

    def run_after_swap(self, ctx: HookContext) -> HookResult:
        return self._run(HookFlags.AFTER_SWAP, "on_after_swap", ctx)

    def run_before_liquidity(self, ctx: HookContext) -> HookResult:
        return self._run(HookFlags.BEFORE_LIQUIDITY, "on_before_liquidity", ctx)

    def run_after_liquidity(self, ctx: HookContext) -> HookResult:
        return self._run(HookFlags.AFTER_LIQUIDITY, "on_after_liquidity", ctx)

    def _run(self, flag: HookFlags, method: str, ctx: HookContext) -> HookResult:
        for hook in self._hooks:
            if flag in hook.flags:
                try:
                    result = getattr(hook, method)(ctx)
                    if not result.allow:
                        return result
                except Exception as e:
                    logger.error("Hook %s.%s failed: %s", type(hook).__name__, method, e)
                    return HookResult(allow=False, reason=f"Hook error: {e}")
        return HookResult(allow=True)
