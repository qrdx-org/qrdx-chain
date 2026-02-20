"""
QRDX TWAP Oracle  (Whitepaper §7.5)

Protocol-level time-weighted average price oracle:
  - Geometric mean TWAP:  exp( Σ(ln(P_i) * Δt_i) / ΣΔt_i )
  - Updated on every pool interaction (swap / add / remove liquidity)
  - Accumulator-based — O(1) reads for any historical window
  - Manipulation resistant through geometric mean + accumulator design

Security features:
  - Minimum observation period before TWAP is valid
  - Outlier price rejection (> MAX_PRICE_CHANGE_PCT from last)
  - Same-block observation dedup (overwrite, not append)
  - Staleness check method
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_UP
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

ZERO = Decimal("0")
MAX_OBSERVATIONS = 8640  # ~24 h at 10-second blocks
MIN_OBSERVATION_PERIOD = 60.0   # seconds — TWAP not valid until this much data
MAX_PRICE_CHANGE_PCT = Decimal("0.50")  # 50% max single-observation price change
STALENESS_THRESHOLD = 300.0     # 5 minutes — oracle considered stale


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Observation:
    """A single price observation recorded at a point in time."""
    timestamp: float
    price: Decimal
    log_price_cumulative: Decimal = ZERO  # Σ(ln(price) × dt)
    tick_cumulative: int = 0


# ---------------------------------------------------------------------------
# TWAP Oracle
# ---------------------------------------------------------------------------

class TWAPOracle:
    """
    Time-weighted average price oracle for a pool or market.

    Records price observations and computes geometric-mean TWAP
    over any requested window using an accumulator pattern.
    """

    def __init__(self, pool_id: str = "", max_observations: int = MAX_OBSERVATIONS):
        self.pool_id = pool_id
        self.max_observations = max_observations
        self._observations: List[Observation] = []

    @property
    def observation_count(self) -> int:
        return len(self._observations)

    @property
    def latest_price(self) -> Optional[Decimal]:
        if not self._observations:
            return None
        return self._observations[-1].price

    # -- Recording ----------------------------------------------------------

    def record(self, price: Decimal, timestamp: Optional[float] = None) -> Observation:
        """
        Record a new price observation.

        Should be called on every pool interaction.

        Security:
          - Rejects outlier prices (>50% change from last)
          - Same-block observations overwrite the previous (dedup)

        Args:
            price: current spot price
            timestamp: observation time (defaults to now)

        Returns:
            The recorded Observation
        """
        if price <= 0:
            raise ValueError("Price must be positive")

        now = timestamp if timestamp is not None else time.time()
        log_price = Decimal(str(math.log(float(price))))

        if self._observations:
            prev = self._observations[-1]

            # --- Outlier rejection ---
            if prev.price > 0:
                change = abs(price - prev.price) / prev.price
                if change > MAX_PRICE_CHANGE_PCT:
                    raise ValueError(
                        f"Outlier price rejected: {change:.2%} change exceeds "
                        f"max {MAX_PRICE_CHANGE_PCT:.2%}"
                    )

            dt = Decimal(str(now - prev.timestamp))
            if dt < 0:
                raise ValueError("Timestamp must be monotonically increasing")

            # --- Same-block dedup: if dt == 0, overwrite last observation ---
            if dt == 0:
                prev.price = price
                prev.log_price_cumulative = prev.log_price_cumulative  # no time elapsed
                return prev

            cumulative = prev.log_price_cumulative + log_price * dt
        else:
            cumulative = ZERO

        obs = Observation(
            timestamp=now,
            price=price,
            log_price_cumulative=cumulative,
        )
        self._observations.append(obs)

        # Trim to max
        if len(self._observations) > self.max_observations:
            self._observations = self._observations[-self.max_observations:]

        return obs

    # -- TWAP computation ---------------------------------------------------

    def twap(self, window_seconds: float) -> Optional[Decimal]:
        """
        Compute geometric-mean TWAP over the last `window_seconds`.

        Formula: exp( (cumulative_end - cumulative_start) / (t_end - t_start) )

        Returns:
            TWAP price, or None if insufficient data or min period not met
        """
        if len(self._observations) < 2:
            return None

        end = self._observations[-1]
        start_obs = self._observations[0]

        # --- Min observation period enforcement ---
        total_span = end.timestamp - start_obs.timestamp
        if total_span < MIN_OBSERVATION_PERIOD:
            return None  # not enough data yet

        target_time = end.timestamp - window_seconds

        # Find the observation closest to (but before) target_time
        start = self._find_observation_at(target_time)
        if start is None:
            return None

        dt = Decimal(str(end.timestamp - start.timestamp))
        if dt <= 0:
            return end.price

        avg_log = (end.log_price_cumulative - start.log_price_cumulative) / dt
        twap_price = Decimal(str(math.exp(float(avg_log)))).quantize(
            Decimal("0.00000001"), rounding=ROUND_HALF_UP
        )
        return twap_price

    def twap_tick(self, window_seconds: float) -> Optional[int]:
        """TWAP expressed as a tick index."""
        price = self.twap(window_seconds)
        if price is None or price <= 0:
            return None
        return int(math.floor(math.log(float(price), 1.0001)))

    # -- Helpers ------------------------------------------------------------

    def _find_observation_at(self, target_time: float) -> Optional[Observation]:
        """Binary search for observation at or just before target_time."""
        if not self._observations:
            return None
        if target_time <= self._observations[0].timestamp:
            return self._observations[0]

        lo, hi = 0, len(self._observations) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._observations[mid].timestamp <= target_time:
                lo = mid
            else:
                hi = mid - 1
        return self._observations[lo]

    def get_observations(self, count: int = 50) -> List[Observation]:
        """Return the most recent observations."""
        return self._observations[-count:]

    def price_at(self, timestamp: float) -> Optional[Decimal]:
        """Look up price at a specific timestamp."""
        obs = self._find_observation_at(timestamp)
        return obs.price if obs else None

    def is_stale(self, threshold: float = STALENESS_THRESHOLD) -> bool:
        """Check if the oracle data is stale (no recent observations)."""
        if not self._observations:
            return True
        age = time.time() - self._observations[-1].timestamp
        return age > threshold

    @property
    def age(self) -> float:
        """Seconds since last observation."""
        if not self._observations:
            return float("inf")
        return time.time() - self._observations[-1].timestamp
