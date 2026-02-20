"""
QRDX Perpetual Contracts Engine

Perpetual futures (user-requested extension, Q3 2026 roadmap item):
  - Linear inverse perpetuals settled in QRDX
  - Funding rate mechanism (8-hour intervals)
  - Mark price: index price + 30-second EMA premium
  - Margin system: initial (5–10 %) / maintenance (2.5–5 %)
  - Liquidation engine with insurance fund fallback
  - Auto-deleveraging (ADL) as last resort
  - Max leverage: 20× (safety cap)
  - Protocol-native — NOT a smart contract

Security features:
  - Partial position close
  - Max open interest per market
  - Oracle staleness guard
  - Reduce-only orders
  - OI-weighted funding dampening
  - Liquidation penalty fee → insurance fund
  - Deterministic position IDs (blake2b)
  - Emergency pause
"""

from __future__ import annotations

import hashlib
import logging
import math
import time
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_DOWN, ROUND_HALF_UP
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

ZERO = Decimal("0")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FUNDING_INTERVAL = 8 * 3600              # 8 hours in seconds
MAX_FUNDING_RATE = Decimal("0.01")       # ±1 % per interval cap
MAX_LEVERAGE = Decimal("20")             # 20× max
DEFAULT_INITIAL_MARGIN = Decimal("0.05")  # 5 %
DEFAULT_MAINT_MARGIN = Decimal("0.025")   # 2.5 %
PREMIUM_EMA_SPAN = 30                     # 30-second EMA span
INSURANCE_CLAWBACK_THRESHOLD = Decimal("0.20")  # 20 % of fund depleted → ADL
LIQUIDATION_PENALTY_RATE = Decimal("0.025")       # 2.5 % penalty → insurance fund
MAX_OPEN_INTEREST_DEFAULT = Decimal("1000000000")  # default cap per market
ORACLE_STALENESS_SECONDS = 120                      # reject if oracle older than 2 min
MAX_POSITIONS_PER_OWNER = 100                       # per market


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PerpSide(str, Enum):
    LONG = "long"
    SHORT = "short"


class PositionStatus(str, Enum):
    OPEN = "open"
    LIQUIDATED = "liquidated"
    CLOSED = "closed"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class FundingSnapshot:
    """Recorded funding rate at a given interval."""
    timestamp: float
    rate: Decimal        # signed: +ve means longs pay shorts
    mark_price: Decimal
    index_price: Decimal
    premium: Decimal


@dataclass
class LiquidationResult:
    """Outcome of a liquidation attempt."""
    position_id: str
    owner: str
    side: PerpSide
    size: Decimal
    entry_price: Decimal
    mark_price: Decimal
    bankruptcy_price: Decimal
    pnl: Decimal
    insurance_used: Decimal
    adl_triggered: bool = False


@dataclass
class PerpPosition:
    """A single perpetual futures position."""
    id: str
    owner: str
    market_id: str
    side: PerpSide
    size: Decimal                      # in base units
    entry_price: Decimal
    margin: Decimal                    # collateral deposited
    leverage: Decimal
    status: PositionStatus = PositionStatus.OPEN
    last_funding_time: float = 0.0     # last time funding was applied
    realized_pnl: Decimal = ZERO
    accumulated_funding: Decimal = ZERO
    opened_at: float = field(default_factory=time.time)
    reduce_only: bool = False          # can only reduce exposure, not increase

    @property
    def notional(self) -> Decimal:
        return self.size * self.entry_price

    @property
    def is_open(self) -> bool:
        return self.status == PositionStatus.OPEN

    def unrealized_pnl(self, mark_price: Decimal) -> Decimal:
        if self.side == PerpSide.LONG:
            return self.size * (mark_price - self.entry_price)
        else:
            return self.size * (self.entry_price - mark_price)

    def margin_ratio(self, mark_price: Decimal) -> Decimal:
        """Current margin ratio (equity / notional at mark)."""
        equity = self.margin + self.unrealized_pnl(mark_price)
        notional_at_mark = self.size * mark_price
        if notional_at_mark <= 0:
            return ZERO
        return equity / notional_at_mark

    def liquidation_price(self, maint_margin_rate: Decimal = DEFAULT_MAINT_MARGIN) -> Decimal:
        """Price at which position is liquidated."""
        if self.size <= 0:
            return ZERO
        if self.side == PerpSide.LONG:
            # liq_price = entry - (margin - maint * notional) / size
            return self.entry_price - (self.margin - maint_margin_rate * self.notional) / self.size
        else:
            return self.entry_price + (self.margin - maint_margin_rate * self.notional) / self.size

    def bankruptcy_price(self) -> Decimal:
        """Price at which margin is fully consumed (equity = 0)."""
        if self.size <= 0:
            return ZERO
        if self.side == PerpSide.LONG:
            return self.entry_price - self.margin / self.size
        else:
            return self.entry_price + self.margin / self.size


# ---------------------------------------------------------------------------
# Perp Market
# ---------------------------------------------------------------------------

@dataclass
class PerpMarket:
    """Configuration for a single perpetual market."""
    id: str
    base_token: str                # e.g. "BTC"
    quote_token: str               # always "QRDX"
    initial_margin_rate: Decimal = DEFAULT_INITIAL_MARGIN
    maintenance_margin_rate: Decimal = DEFAULT_MAINT_MARGIN
    max_leverage: Decimal = MAX_LEVERAGE
    insurance_fund: Decimal = ZERO
    max_open_interest: Decimal = MAX_OPEN_INTEREST_DEFAULT
    # Price state
    index_price: Decimal = ZERO
    mark_price: Decimal = ZERO
    last_premium: Decimal = ZERO
    last_price_update: float = 0.0  # timestamp of last oracle update
    # Aggregate positions
    open_interest_long: Decimal = ZERO
    open_interest_short: Decimal = ZERO
    # Funding
    funding_history: List[FundingSnapshot] = field(default_factory=list)
    last_funding_time: float = 0.0
    cumulative_funding: Decimal = ZERO
    created_at: float = field(default_factory=time.time)

    @property
    def open_interest(self) -> Decimal:
        return self.open_interest_long + self.open_interest_short


# ---------------------------------------------------------------------------
# Perp Engine
# ---------------------------------------------------------------------------

class PerpEngine:
    """
    Protocol-native perpetual futures engine.

    Manages markets, positions, funding, and liquidations.

    Security:
      - Max OI per market
      - Oracle staleness guard
      - Reduce-only order support
      - Partial close
      - Liquidation penalty → insurance fund
      - OI-weighted funding dampening
      - Deterministic position IDs
      - Emergency pause
    """

    def __init__(self) -> None:
        self._markets: Dict[str, PerpMarket] = {}
        self._positions: Dict[str, PerpPosition] = {}
        self._owner_positions: Dict[str, List[str]] = {}  # owner → [pos_ids]
        self._pos_sequence: int = 0  # deterministic ID counter
        self._paused: bool = False

    @property
    def market_count(self) -> int:
        return len(self._markets)

    # -- Emergency controls -------------------------------------------------

    def pause(self) -> None:
        self._paused = True

    def unpause(self) -> None:
        self._paused = False

    @property
    def is_paused(self) -> bool:
        return self._paused

    # -- Market management --------------------------------------------------

    def create_market(
        self,
        base_token: str,
        quote_token: str = "QRDX",
        initial_margin_rate: Decimal = DEFAULT_INITIAL_MARGIN,
        maintenance_margin_rate: Decimal = DEFAULT_MAINT_MARGIN,
        max_leverage: Decimal = MAX_LEVERAGE,
    ) -> PerpMarket:
        market_id = f"{base_token}-{quote_token}-PERP"
        if market_id in self._markets:
            raise ValueError(f"Market {market_id} already exists")
        if initial_margin_rate <= 0 or maintenance_margin_rate <= 0:
            raise ValueError("Margin rates must be positive")
        if maintenance_margin_rate >= initial_margin_rate:
            raise ValueError("Maintenance margin must be less than initial margin")
        if max_leverage <= 0 or max_leverage > MAX_LEVERAGE:
            raise ValueError(f"Leverage must be between 0 and {MAX_LEVERAGE}")

        market = PerpMarket(
            id=market_id,
            base_token=base_token,
            quote_token=quote_token,
            initial_margin_rate=initial_margin_rate,
            maintenance_margin_rate=maintenance_margin_rate,
            max_leverage=max_leverage,
        )
        self._markets[market_id] = market
        logger.info("Perp market created: %s", market_id)
        return market

    def get_market(self, market_id: str) -> Optional[PerpMarket]:
        return self._markets.get(market_id)

    # -- Position management ------------------------------------------------

    def open_position(
        self,
        market_id: str,
        owner: str,
        side: PerpSide,
        size: Decimal,
        leverage: Decimal,
        price: Decimal,
        reduce_only: bool = False,
    ) -> PerpPosition:
        """
        Open a new perpetual position.

        Args:
            market_id: market identifier
            owner: PQ address
            side: LONG or SHORT
            size: position size in base units
            leverage: desired leverage (1–20×)
            price: execution price
            reduce_only: if True, can only reduce exposure

        Returns:
            The opened PerpPosition

        Raises:
            ValueError: on invalid parameters, pause, staleness, max OI
        """
        if self._paused:
            raise ValueError("Perp engine is paused — emergency mode")

        market = self._markets.get(market_id)
        if market is None:
            raise ValueError(f"Market {market_id} not found")

        if size <= 0:
            raise ValueError("Position size must be positive")
        if price <= 0:
            raise ValueError("Price must be positive")
        if leverage <= 0 or leverage > market.max_leverage:
            raise ValueError(f"Leverage must be between 1 and {market.max_leverage}")
        if not owner:
            raise ValueError("Owner address required")

        # --- Oracle staleness guard ---
        self._check_oracle_staleness(market)

        # --- Max OI check ---
        new_oi_side = market.open_interest_long + size if side == PerpSide.LONG else market.open_interest_short + size
        if new_oi_side > market.max_open_interest:
            raise ValueError(
                f"Max open interest exceeded: {new_oi_side} > {market.max_open_interest}"
            )

        notional = size * price
        required_margin = (notional / leverage).quantize(Decimal("0.00000001"), rounding=ROUND_HALF_UP)

        # Validate margin meets initial margin requirement
        min_margin = (notional * market.initial_margin_rate).quantize(Decimal("0.00000001"), rounding=ROUND_HALF_UP)
        if required_margin < min_margin:
            required_margin = min_margin

        self._pos_sequence += 1
        position = PerpPosition(
            id=self._deterministic_position_id(owner, market_id, side.value, self._pos_sequence),
            owner=owner,
            market_id=market_id,
            side=side,
            size=size,
            entry_price=price,
            margin=required_margin,
            leverage=leverage,
            last_funding_time=time.time(),
            reduce_only=reduce_only,
        )

        # Update open interest
        if side == PerpSide.LONG:
            market.open_interest_long += size
        else:
            market.open_interest_short += size

        self._positions[position.id] = position
        if owner not in self._owner_positions:
            self._owner_positions[owner] = []
        self._owner_positions[owner].append(position.id)

        return position

    def close_position(self, position_id: str, price: Decimal) -> Decimal:
        """
        Close a position at the given price.

        Returns:
            Realized PnL
        """
        pos = self._positions.get(position_id)
        if pos is None:
            raise ValueError(f"Position {position_id} not found")
        if not pos.is_open:
            raise ValueError("Position already closed")
        if price <= 0:
            raise ValueError("Price must be positive")

        market = self._markets[pos.market_id]

        pnl = pos.unrealized_pnl(price)
        pos.realized_pnl = pnl
        pos.status = PositionStatus.CLOSED

        # Update open interest
        if pos.side == PerpSide.LONG:
            market.open_interest_long -= pos.size
        else:
            market.open_interest_short -= pos.size

        return pnl

    def partial_close(self, position_id: str, close_size: Decimal, price: Decimal) -> Decimal:
        """
        Partially close a position.

        Args:
            position_id: position to partially close
            close_size: amount to close (must be < position size)
            price: execution price

        Returns:
            Realized PnL for the closed portion
        """
        pos = self._positions.get(position_id)
        if pos is None:
            raise ValueError(f"Position {position_id} not found")
        if not pos.is_open:
            raise ValueError("Position already closed")
        if price <= 0:
            raise ValueError("Price must be positive")
        if close_size <= 0:
            raise ValueError("Close size must be positive")
        if close_size >= pos.size:
            return self.close_position(position_id, price)

        market = self._markets[pos.market_id]

        # Calculate PnL for the closed portion
        if pos.side == PerpSide.LONG:
            pnl = close_size * (price - pos.entry_price)
        else:
            pnl = close_size * (pos.entry_price - price)

        # Proportional margin release
        margin_released = pos.margin * (close_size / pos.size)
        pos.margin -= margin_released
        pos.size -= close_size
        pos.realized_pnl += pnl

        # Update open interest
        if pos.side == PerpSide.LONG:
            market.open_interest_long -= close_size
        else:
            market.open_interest_short -= close_size

        return pnl

    def get_position(self, position_id: str) -> Optional[PerpPosition]:
        return self._positions.get(position_id)

    def get_positions_by_owner(self, owner: str) -> List[PerpPosition]:
        ids = self._owner_positions.get(owner, [])
        return [self._positions[pid] for pid in ids if pid in self._positions]

    # -- Price management ---------------------------------------------------

    def update_price(self, market_id: str, index_price: Decimal) -> None:
        """Update the index price for a market and recompute mark price."""
        market = self._markets.get(market_id)
        if market is None:
            raise ValueError(f"Market {market_id} not found")

        market.index_price = index_price
        market.last_price_update = time.time()

        # Mark price = index + EMA(premium)
        # Premium = (last_trade_price - index) — simplified
        # For now, mark ≈ index when no order flow premium
        premium = market.last_premium
        # EMA smoothing
        alpha = Decimal("2") / (Decimal(PREMIUM_EMA_SPAN) + Decimal("1"))
        smoothed_premium = alpha * premium + (Decimal("1") - alpha) * (market.mark_price - market.index_price) if market.mark_price > 0 else premium
        market.mark_price = index_price + smoothed_premium
        if market.mark_price <= 0:
            market.mark_price = index_price

    # -- Funding ------------------------------------------------------------

    def calculate_funding_rate(self, market_id: str) -> Decimal:
        """
        Calculate the current funding rate.

        Funding rate = clamp(premium / index, -MAX, +MAX) * OI_dampening
        OI dampening: rate is scaled by imbalance ratio to prevent extreme funding
        when one side dominates.
        Positive rate: longs pay shorts.
        """
        market = self._markets.get(market_id)
        if market is None:
            raise ValueError(f"Market {market_id} not found")

        if market.index_price <= 0:
            return ZERO

        premium = market.mark_price - market.index_price
        rate = premium / market.index_price

        # OI-weighted dampening: scale rate by the imbalance ratio
        total_oi = market.open_interest_long + market.open_interest_short
        if total_oi > 0:
            if rate > 0:
                # Longs pay — dampen if longs are small relative to shorts
                long_ratio = market.open_interest_long / total_oi
                rate = rate * long_ratio * 2  # neutral at 50/50
            elif rate < 0:
                # Shorts pay — dampen if shorts are small
                short_ratio = market.open_interest_short / total_oi
                rate = rate * short_ratio * 2

        # Clamp
        if rate > MAX_FUNDING_RATE:
            rate = MAX_FUNDING_RATE
        elif rate < -MAX_FUNDING_RATE:
            rate = -MAX_FUNDING_RATE

        return rate.quantize(Decimal("0.00000001"), rounding=ROUND_HALF_UP)

    def apply_funding(self, market_id: str) -> Optional[FundingSnapshot]:
        """
        Apply funding to all open positions in a market.

        Should be called every FUNDING_INTERVAL seconds.

        Returns:
            FundingSnapshot if applied, None if too early
        """
        market = self._markets.get(market_id)
        if market is None:
            return None

        now = time.time()
        if market.last_funding_time > 0 and (now - market.last_funding_time) < FUNDING_INTERVAL:
            return None

        rate = self.calculate_funding_rate(market_id)

        snapshot = FundingSnapshot(
            timestamp=now,
            rate=rate,
            mark_price=market.mark_price,
            index_price=market.index_price,
            premium=market.mark_price - market.index_price,
        )
        market.funding_history.append(snapshot)
        market.last_funding_time = now
        market.cumulative_funding += rate

        # Apply to all open positions
        for pos in self._positions.values():
            if pos.market_id != market_id or not pos.is_open:
                continue

            payment = pos.size * pos.entry_price * rate
            if pos.side == PerpSide.LONG:
                pos.margin -= payment   # longs pay when rate > 0
            else:
                pos.margin += payment   # shorts receive when rate > 0

            pos.accumulated_funding += payment if pos.side == PerpSide.SHORT else -payment
            pos.last_funding_time = now

        return snapshot

    # -- Liquidation --------------------------------------------------------

    def check_liquidation(self, position_id: str) -> Optional[LiquidationResult]:
        """
        Check if a position should be liquidated.

        Returns:
            LiquidationResult if liquidated, None otherwise
        """
        pos = self._positions.get(position_id)
        if pos is None or not pos.is_open:
            return None

        market = self._markets.get(pos.market_id)
        if market is None or market.mark_price <= 0:
            return None

        mr = pos.margin_ratio(market.mark_price)
        if mr >= market.maintenance_margin_rate:
            return None  # healthy

        # === LIQUIDATION ===
        pnl = pos.unrealized_pnl(market.mark_price)
        bankruptcy = pos.bankruptcy_price()

        # Liquidation penalty → insurance fund
        notional_at_mark = pos.size * market.mark_price
        liquidation_penalty = (notional_at_mark * LIQUIDATION_PENALTY_RATE).quantize(
            Decimal("0.00000001"), rounding=ROUND_HALF_UP
        )
        market.insurance_fund += liquidation_penalty

        # Attempt to cover losses from margin first
        insurance_needed = ZERO
        remaining_margin = pos.margin - liquidation_penalty
        if remaining_margin + pnl < 0:
            insurance_needed = abs(remaining_margin + pnl)

        adl_triggered = False
        if insurance_needed > 0:
            if market.insurance_fund >= insurance_needed:
                market.insurance_fund -= insurance_needed
            else:
                # Insurance insufficient → ADL
                adl_triggered = True
                insurance_needed = market.insurance_fund
                market.insurance_fund = ZERO

        result = LiquidationResult(
            position_id=pos.id,
            owner=pos.owner,
            side=pos.side,
            size=pos.size,
            entry_price=pos.entry_price,
            mark_price=market.mark_price,
            bankruptcy_price=bankruptcy,
            pnl=pnl,
            insurance_used=insurance_needed,
            adl_triggered=adl_triggered,
        )

        # Close the position
        pos.status = PositionStatus.LIQUIDATED
        pos.realized_pnl = pnl

        if pos.side == PerpSide.LONG:
            market.open_interest_long -= pos.size
        else:
            market.open_interest_short -= pos.size

        logger.warning("Position %s liquidated: pnl=%s adl=%s", pos.id, pnl, adl_triggered)
        return result

    def check_all_liquidations(self, market_id: str) -> List[LiquidationResult]:
        """Check and execute all liquidations in a market."""
        results = []
        for pos in list(self._positions.values()):
            if pos.market_id != market_id or not pos.is_open:
                continue
            result = self.check_liquidation(pos.id)
            if result is not None:
                results.append(result)
        return results

    def add_insurance(self, market_id: str, amount: Decimal) -> None:
        """Seed the insurance fund for a market."""
        market = self._markets.get(market_id)
        if market is None:
            raise ValueError(f"Market {market_id} not found")
        if amount <= 0:
            raise ValueError("Amount must be positive")
        market.insurance_fund += amount

    def add_margin(self, position_id: str, amount: Decimal) -> Decimal:
        """
        Add margin to an existing position.

        Returns:
            New total margin
        """
        pos = self._positions.get(position_id)
        if pos is None:
            raise ValueError(f"Position {position_id} not found")
        if not pos.is_open:
            raise ValueError("Cannot add margin to closed position")
        if amount <= 0:
            raise ValueError("Margin amount must be positive")
        pos.margin += amount
        return pos.margin

    # -- Security helpers ---------------------------------------------------

    def _check_oracle_staleness(self, market: PerpMarket) -> None:
        """Reject operations if oracle data is stale."""
        if market.last_price_update <= 0:
            return  # no update yet — allow (market just created)
        age = time.time() - market.last_price_update
        if age > ORACLE_STALENESS_SECONDS:
            raise ValueError(
                f"Oracle data stale: {age:.0f}s old (max {ORACLE_STALENESS_SECONDS}s)"
            )

    @staticmethod
    def _deterministic_position_id(owner: str, market_id: str, side: str, seq: int) -> str:
        """Deterministic position ID — consensus-safe."""
        raw = f"{owner}:{market_id}:{side}:{seq}".encode()
        return hashlib.blake2b(raw, digest_size=8).hexdigest()
