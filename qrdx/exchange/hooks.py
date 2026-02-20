"""
QRDX Exchange Hook System  (Whitepaper §7 — extensibility)

Provides a hook interface for extending exchange behaviour:
  - beforeSwap / afterSwap
  - beforeLiquidity / afterLiquidity
  - Circuit breaker module (auto-pause on extreme conditions)

Hooks run synchronously within the transaction and can:
  - Inspect parameters and revert the operation
  - Modify fee rates
  - Collect analytics
  - Enforce additional security constraints

All hooks are deterministic and consensus-safe.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Flag, auto
from typing import Any, Callable, Dict, List, Optional, Protocol

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
    allow: bool = True        # False = revert the operation
    reason: str = ""          # reason for revert (if allow=False)
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


# ---------------------------------------------------------------------------
# Circuit Breaker — built-in hook for extreme condition protection
# ---------------------------------------------------------------------------

class CircuitBreaker:
    """
    Circuit breaker module — automatically pauses trading
    when extreme conditions are detected.

    Conditions:
      - Max price deviation per block (e.g. >15% in one block)
      - Max volume per block (e.g. >$10M equivalent)
      - Manual trip (emergency)

    When tripped, all swaps and liquidity operations are blocked
    until explicitly reset.
    """

    def __init__(
        self,
        max_price_deviation: Decimal = Decimal("0.15"),
        max_volume_per_block: Decimal = Decimal("10000000"),
    ):
        self.max_price_deviation = max_price_deviation
        self.max_volume_per_block = max_volume_per_block
        self._tripped: bool = False
        self._trip_reason: str = ""
        self._block_volume: Decimal = ZERO
        self._block_start_price: Optional[Decimal] = None
        self._trip_time: float = 0.0

    @property
    def flags(self) -> HookFlags:
        return HookFlags.BEFORE_SWAP | HookFlags.AFTER_SWAP

    @property
    def is_tripped(self) -> bool:
        return self._tripped

    @property
    def trip_reason(self) -> str:
        return self._trip_reason

    def new_block(self) -> None:
        """Reset per-block accumulators."""
        self._block_volume = ZERO
        self._block_start_price = None

    def trip(self, reason: str = "Manual emergency trip") -> None:
        """Manually trip the circuit breaker."""
        self._tripped = True
        self._trip_reason = reason
        self._trip_time = time.time()
        logger.warning("Circuit breaker TRIPPED: %s", reason)

    def reset(self) -> None:
        """Reset the circuit breaker (resume trading)."""
        self._tripped = False
        self._trip_reason = ""
        logger.info("Circuit breaker RESET")

    def on_before_swap(self, ctx: HookContext) -> HookResult:
        if self._tripped:
            return HookResult(allow=False, reason=f"Circuit breaker active: {self._trip_reason}")

        # Track block volume
        self._block_volume += ctx.amount_in
        if self._block_volume > self.max_volume_per_block:
            self.trip(f"Block volume exceeded: {self._block_volume}")
            return HookResult(allow=False, reason=self._trip_reason)

        return HookResult(allow=True)

    def on_after_swap(self, ctx: HookContext) -> HookResult:
        # Track price deviation within block
        if ctx.amount_out > 0 and ctx.amount_in > 0:
            price = ctx.amount_in / ctx.amount_out
            if self._block_start_price is None:
                self._block_start_price = price
            else:
                deviation = abs(price - self._block_start_price) / self._block_start_price
                if deviation > self.max_price_deviation:
                    self.trip(f"Price deviation {deviation:.2%} in block")
                    return HookResult(allow=False, reason=self._trip_reason)

        return HookResult(allow=True)

    def on_before_liquidity(self, ctx: HookContext) -> HookResult:
        if self._tripped:
            return HookResult(allow=False, reason=f"Circuit breaker active: {self._trip_reason}")
        return HookResult(allow=True)

    def on_after_liquidity(self, ctx: HookContext) -> HookResult:
        return HookResult(allow=True)
