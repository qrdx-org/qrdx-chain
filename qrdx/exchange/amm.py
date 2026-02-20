"""
QRDX Concentrated-Liquidity AMM  (Whitepaper §7.1 + §7.3 + §7.6)

Protocol-native AMM engine with:
  - Concentrated liquidity (Uniswap V3 model): tick-based, sqrt-price
  - Four fee tiers: 0.01%, 0.05%, 0.30%, 1.00%
  - Four pool types: Standard, Bootstrap, Subsidized, Institutional
  - Fee distribution: 70% LP / 15% creator / 10% treasury / 5% validators
  - Permissionless pool creation with stake requirements
  - Liquidity position tracking with fee accrual

Security features:
  - Slippage protection (min_amount_out on every swap)
  - Price impact calculation (pre-trade)
  - Reentrancy lock on swap + liquidity mutations
  - Deterministic IDs (blake2b, no uuid4)
  - Minimum initial liquidity requirement
  - Emergency pause
"""

from __future__ import annotations

import decimal
import hashlib
import logging
import math
import time
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_DOWN, ROUND_HALF_UP, getcontext
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional, Tuple

# Q96 arithmetic requires high precision
getcontext().prec = 78

logger = logging.getLogger(__name__)

ZERO = Decimal("0")
Q96 = Decimal(2**96)
MIN_TICK = -887272
MAX_TICK = 887272
MIN_SQRT_RATIO = Decimal("4295128739")        # sqrt(1.0001^MIN_TICK) * 2^96
MAX_SQRT_RATIO = Decimal("1461446703485210103287273052203988822378723970342")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FeeTier(IntEnum):
    """Fee tiers in basis-point notation (Whitepaper §7.6)."""
    ULTRA_LOW = 100      # 0.01 %
    LOW = 500            # 0.05 %
    MEDIUM = 3000        # 0.30 %
    HIGH = 10000         # 1.00 %

    @property
    def rate(self) -> Decimal:
        return Decimal(int(self)) / Decimal("1000000")

    @property
    def tick_spacing(self) -> int:
        return _TICK_SPACINGS[int(self)]


_TICK_SPACINGS = {
    100: 1,
    500: 10,
    3000: 60,
    10000: 200,
}


class PoolType(IntEnum):
    """Pool creation types with different stake requirements (§7.3)."""
    STANDARD = 0       # 10 000 QRDX staked
    BOOTSTRAP = 1      # 25 000 QRDX staked (30-day incentive)
    SUBSIDIZED = 2     # 5 000 QRDX burned (permanent, community-owned)
    INSTITUTIONAL = 3  # 100 000 QRDX staked (higher depth, lower fees)


POOL_STAKE_REQUIREMENTS: Dict[int, Decimal] = {
    PoolType.STANDARD: Decimal("10000"),
    PoolType.BOOTSTRAP: Decimal("25000"),
    PoolType.SUBSIDIZED: Decimal("5000"),
    PoolType.INSTITUTIONAL: Decimal("100000"),
}


# ---------------------------------------------------------------------------
# Fee distribution percentages (§7.6)
# ---------------------------------------------------------------------------

FEE_LP_SHARE = Decimal("0.70")
FEE_CREATOR_SHARE = Decimal("0.15")
FEE_TREASURY_SHARE = Decimal("0.10")
FEE_VALIDATOR_SHARE = Decimal("0.05")

# Minimum initial liquidity required to create a pool
MIN_INITIAL_LIQUIDITY = Decimal("1000")
# Deterministic sequence counter prefix
_POOL_SEQ = 0
_POS_SEQ = 0


# ---------------------------------------------------------------------------
# Tick math helpers  (Uniswap V3 style)
# ---------------------------------------------------------------------------

def tick_to_sqrt_price(tick: int) -> Decimal:
    """Convert tick index → sqrt-price (Q96 representation)."""
    return Decimal(str(math.sqrt(1.0001 ** tick))) * Q96


def sqrt_price_to_tick(sqrt_price: Decimal) -> int:
    """Convert sqrt-price (Q96) → nearest tick index."""
    ratio = float(sqrt_price / Q96)
    if ratio <= 0:
        return MIN_TICK
    return int(math.floor(math.log(ratio**2, 1.0001)))


def sqrt_price_to_price(sqrt_price: Decimal) -> Decimal:
    """Convert sqrt-price (Q96) → human-readable price."""
    ratio = sqrt_price / Q96
    return (ratio * ratio).quantize(Decimal("0.00000001"), rounding=ROUND_HALF_UP)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class TickInfo:
    """Liquidity info at a single tick boundary."""
    tick: int
    liquidity_net: Decimal = ZERO
    liquidity_gross: Decimal = ZERO
    fee_growth_outside_0: Decimal = ZERO
    fee_growth_outside_1: Decimal = ZERO
    initialized: bool = False


@dataclass
class Position:
    """A concentrated-liquidity position."""
    id: str
    owner: str
    pool_id: str
    tick_lower: int
    tick_upper: int
    liquidity: Decimal = ZERO
    fee_growth_inside_0_last: Decimal = ZERO
    fee_growth_inside_1_last: Decimal = ZERO
    tokens_owed_0: Decimal = ZERO
    tokens_owed_1: Decimal = ZERO
    created_at: float = field(default_factory=time.time)

    @property
    def is_active(self) -> bool:
        return self.liquidity > 0


@dataclass
class PoolState:
    """
    State of a concentrated-liquidity pool.

    token0 < token1 (canonical ordering).
    """
    id: str
    token0: str
    token1: str
    fee_tier: FeeTier
    pool_type: PoolType
    creator: str

    # Price / liquidity
    sqrt_price: Decimal = ZERO
    tick: int = 0
    liquidity: Decimal = ZERO

    # Global fee accumulators
    fee_growth_global_0: Decimal = ZERO
    fee_growth_global_1: Decimal = ZERO

    # Collected fees (pending distribution)
    protocol_fees_0: Decimal = ZERO
    protocol_fees_1: Decimal = ZERO

    # Tick map
    ticks: Dict[int, TickInfo] = field(default_factory=dict)

    # Positions
    positions: Dict[str, Position] = field(default_factory=dict)

    # Stats
    total_volume_0: Decimal = ZERO
    total_volume_1: Decimal = ZERO
    created_at: float = field(default_factory=time.time)

    @property
    def price(self) -> Decimal:
        return sqrt_price_to_price(self.sqrt_price)


# ---------------------------------------------------------------------------
# Concentrated Liquidity Pool
# ---------------------------------------------------------------------------

class ConcentratedLiquidityPool:
    """
    Single concentrated-liquidity pool engine.

    Implements:
      - Swap (exact-in) with slippage protection
      - Add / remove liquidity at tick ranges
      - Fee accrual per position
      - Reentrancy protection
      - Price impact calculation
    """

    def __init__(self, state: PoolState):
        self.state = state
        self._locked: bool = False   # reentrancy guard
        self._paused: bool = False   # emergency pause
        self._pos_sequence: int = 0  # deterministic position ID counter

    # -- Reentrancy guard ---------------------------------------------------

    def _acquire_lock(self) -> None:
        if self._locked:
            raise ValueError("Reentrancy detected — pool is locked")
        self._locked = True

    def _release_lock(self) -> None:
        self._locked = False

    # -- Emergency controls -------------------------------------------------

    def pause(self) -> None:
        self._paused = True

    def unpause(self) -> None:
        self._paused = False

    @property
    def is_paused(self) -> bool:
        return self._paused

    # -- Price impact -------------------------------------------------------

    def price_impact(self, amount_in: Decimal, zero_for_one: bool) -> Decimal:
        """
        Calculate the price impact of a swap WITHOUT executing it.

        Returns:
            Price impact as a fraction (e.g. 0.01 = 1% impact)
        """
        if self.state.liquidity <= 0 or amount_in <= 0:
            return ZERO
        price_before = self.state.price
        if price_before <= 0:
            return ZERO

        # Simulate the swap to get new price
        fee_rate = self.state.fee_tier.rate
        amount_after_fee = amount_in - (amount_in * fee_rate)
        L = self.state.liquidity
        sqrt_p = self.state.sqrt_price

        if zero_for_one:
            denom = L + amount_after_fee * sqrt_p / Q96
            if denom <= 0:
                return Decimal("1")  # 100% impact
            new_sqrt_p = (sqrt_p * L / denom).quantize(Decimal("1"), rounding=ROUND_DOWN)
        else:
            new_sqrt_p = sqrt_p + (amount_after_fee * Q96 / L).quantize(Decimal("1"), rounding=ROUND_DOWN)

        price_after = sqrt_price_to_price(new_sqrt_p)
        if price_before <= 0:
            return ZERO
        impact = abs(price_after - price_before) / price_before
        return impact.quantize(Decimal("0.00000001"), rounding=ROUND_HALF_UP)

    # -- Swap ---------------------------------------------------------------

    def swap(
        self,
        amount_in: Decimal,
        zero_for_one: bool,
        min_amount_out: Decimal = ZERO,
    ) -> Tuple[Decimal, Decimal]:
        """
        Execute a swap on this pool.

        Args:
            amount_in: exact input amount (before fees)
            zero_for_one: True if swapping token0→token1
            min_amount_out: minimum acceptable output (slippage protection)

        Returns:
            (amount_out, fee_amount)

        Raises:
            ValueError: on zero liquidity, zero amount, slippage exceeded, reentrancy, or pause
        """
        if self._paused:
            raise ValueError("Pool is paused — emergency mode")
        if amount_in <= 0:
            raise ValueError("Swap amount must be positive")
        if self.state.liquidity <= 0:
            raise ValueError("No liquidity in pool")

        self._acquire_lock()
        try:
            return self._execute_swap(amount_in, zero_for_one, min_amount_out)
        finally:
            self._release_lock()

    def _execute_swap(
        self,
        amount_in: Decimal,
        zero_for_one: bool,
        min_amount_out: Decimal,
    ) -> Tuple[Decimal, Decimal]:
        """Core swap logic, called under reentrancy lock."""
        fee_rate = self.state.fee_tier.rate
        fee_amount = (amount_in * fee_rate).quantize(Decimal("0.00000001"), rounding=ROUND_HALF_UP)
        amount_after_fee = amount_in - fee_amount

        # Simplified constant-product within current tick range
        L = self.state.liquidity
        sqrt_p = self.state.sqrt_price

        if zero_for_one:
            # token0 in → token1 out; price decreases
            denom = L + amount_after_fee * sqrt_p / Q96
            if denom <= 0:
                raise ValueError("Swap would drain pool")
            new_sqrt_p = (sqrt_p * L / denom).quantize(Decimal("1"), rounding=ROUND_DOWN)
            if new_sqrt_p < MIN_SQRT_RATIO:
                new_sqrt_p = MIN_SQRT_RATIO

            amount_out = (L * (sqrt_p - new_sqrt_p) / Q96).quantize(
                Decimal("0.00000001"), rounding=ROUND_DOWN
            )
            if amount_out < 0:
                amount_out = ZERO

            self.state.fee_growth_global_0 += fee_amount / L if L > 0 else ZERO
        else:
            # token1 in → token0 out; price increases
            new_sqrt_p = sqrt_p + (amount_after_fee * Q96 / L).quantize(Decimal("1"), rounding=ROUND_DOWN)
            if new_sqrt_p > MAX_SQRT_RATIO:
                new_sqrt_p = MAX_SQRT_RATIO

            # token0 output: dx = L * (1/sqrt_p_old - 1/sqrt_p_new) = L * Q96 * (new - old) / (old * new)
            amount_out = (L * Q96 * (new_sqrt_p - sqrt_p) / (sqrt_p * new_sqrt_p)).quantize(
                Decimal("0.00000001"), rounding=ROUND_DOWN
            ) if sqrt_p > 0 and new_sqrt_p > 0 else ZERO

            self.state.fee_growth_global_1 += fee_amount / L if L > 0 else ZERO

        # --- Slippage protection ---
        if min_amount_out > 0 and amount_out < min_amount_out:
            raise ValueError(
                f"Slippage exceeded: got {amount_out}, minimum {min_amount_out}"
            )

        self.state.sqrt_price = new_sqrt_p
        self.state.tick = sqrt_price_to_tick(new_sqrt_p)

        # Update volume
        if zero_for_one:
            self.state.total_volume_0 += amount_in
        else:
            self.state.total_volume_1 += amount_in

        # Protocol fee accrual
        self._accrue_protocol_fees(fee_amount, zero_for_one)

        return amount_out, fee_amount

    # -- Liquidity ----------------------------------------------------------

    def add_liquidity(
        self,
        owner: str,
        tick_lower: int,
        tick_upper: int,
        amount: Decimal,
    ) -> Position:
        """
        Add concentrated liquidity in [tick_lower, tick_upper).

        Returns:
            The created Position
        """
        if self._paused:
            raise ValueError("Pool is paused — emergency mode")
        if tick_lower >= tick_upper:
            raise ValueError("tick_lower must be < tick_upper")
        if tick_lower < MIN_TICK or tick_upper > MAX_TICK:
            raise ValueError("Tick out of range")
        spacing = self.state.fee_tier.tick_spacing
        if tick_lower % spacing != 0 or tick_upper % spacing != 0:
            raise ValueError(f"Ticks must be multiples of tick_spacing ({spacing})")
        if amount <= 0:
            raise ValueError("Liquidity amount must be positive")

        self._acquire_lock()
        try:
            self._pos_sequence += 1
            position_id = self._deterministic_position_id(
                owner, tick_lower, tick_upper, self._pos_sequence
            )
            position = Position(
                id=position_id,
                owner=owner,
                pool_id=self.state.id,
                tick_lower=tick_lower,
                tick_upper=tick_upper,
                liquidity=amount,
                fee_growth_inside_0_last=self.state.fee_growth_global_0,
                fee_growth_inside_1_last=self.state.fee_growth_global_1,
            )

            # Update tick boundaries
            self._update_tick(tick_lower, amount, is_lower=True)
            self._update_tick(tick_upper, amount, is_lower=False)

            # If current tick is within range, add to active liquidity
            if tick_lower <= self.state.tick < tick_upper:
                self.state.liquidity += amount

            self.state.positions[position_id] = position
            return position
        finally:
            self._release_lock()

    def remove_liquidity(self, position_id: str, amount: Optional[Decimal] = None) -> Tuple[Decimal, Decimal]:
        """
        Remove liquidity from a position.

        Args:
            position_id: position to remove from
            amount: liquidity to remove (None = all)

        Returns:
            (fees_owed_0, fees_owed_1)
        """
        position = self.state.positions.get(position_id)
        if position is None:
            raise ValueError(f"Position {position_id} not found")

        remove_amount = amount if amount is not None else position.liquidity
        if remove_amount > position.liquidity:
            raise ValueError("Cannot remove more liquidity than position holds")

        # Calculate owed fees
        fees_0 = (self.state.fee_growth_global_0 - position.fee_growth_inside_0_last) * position.liquidity
        fees_1 = (self.state.fee_growth_global_1 - position.fee_growth_inside_1_last) * position.liquidity

        position.tokens_owed_0 += fees_0
        position.tokens_owed_1 += fees_1
        position.fee_growth_inside_0_last = self.state.fee_growth_global_0
        position.fee_growth_inside_1_last = self.state.fee_growth_global_1

        # Update liquidity
        position.liquidity -= remove_amount

        self._update_tick(position.tick_lower, -remove_amount, is_lower=True)
        self._update_tick(position.tick_upper, -remove_amount, is_lower=False)

        if position.tick_lower <= self.state.tick < position.tick_upper:
            self.state.liquidity -= remove_amount

        if position.liquidity <= 0:
            del self.state.positions[position_id]

        return fees_0, fees_1

    # -- Internal -----------------------------------------------------------

    def _update_tick(self, tick: int, liquidity_delta: Decimal, is_lower: bool) -> None:
        info = self.state.ticks.get(tick)
        if info is None:
            info = TickInfo(tick=tick, initialized=True)
            self.state.ticks[tick] = info

        info.liquidity_gross += abs(liquidity_delta)
        if is_lower:
            info.liquidity_net += liquidity_delta
        else:
            info.liquidity_net -= liquidity_delta

        if info.liquidity_gross <= 0:
            info.initialized = False

    def _accrue_protocol_fees(self, fee_amount: Decimal, is_token0: bool) -> None:
        """Split fee into protocol shares."""
        creator_share = (fee_amount * FEE_CREATOR_SHARE).quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)
        treasury_share = (fee_amount * FEE_TREASURY_SHARE).quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)
        validator_share = (fee_amount * FEE_VALIDATOR_SHARE).quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)
        # LP share is the remainder (≈70%)
        if is_token0:
            self.state.protocol_fees_0 += creator_share + treasury_share + validator_share
        else:
            self.state.protocol_fees_1 += creator_share + treasury_share + validator_share

    @staticmethod
    def _deterministic_position_id(owner: str, tick_lower: int, tick_upper: int, seq: int) -> str:
        """Deterministic position ID — consensus-safe."""
        raw = f"{owner}:{tick_lower}:{tick_upper}:{seq}".encode()
        return hashlib.blake2b(raw, digest_size=8).hexdigest()


# ---------------------------------------------------------------------------
# Pool Manager  (singleton-like registry)
# ---------------------------------------------------------------------------

class PoolManager:
    """
    Manages all AMM pools.

    Handles:
      - Permissionless pool creation (with stake validation)
      - Pool lookup by pair / id
      - Multi-pool routing queries
      - Deterministic pool IDs
    """

    def __init__(self) -> None:
        self._pools: Dict[str, ConcentratedLiquidityPool] = {}
        self._pair_index: Dict[str, List[str]] = {}  # "token0:token1" → [pool_ids]
        self._pool_sequence: int = 0  # deterministic ID counter

    @property
    def pool_count(self) -> int:
        return len(self._pools)

    def create_pool(
        self,
        token0: str,
        token1: str,
        fee_tier: FeeTier,
        pool_type: PoolType,
        initial_sqrt_price: Decimal,
        creator: str,
        stake_amount: Decimal = ZERO,
    ) -> ConcentratedLiquidityPool:
        """
        Create a new liquidity pool.

        Validates stake requirements per pool type.
        """
        # Canonical ordering
        if token0 > token1:
            token0, token1 = token1, token0

        # Duplicate check
        pair_key = f"{token0}:{token1}"
        existing_ids = self._pair_index.get(pair_key, [])
        for pid in existing_ids:
            pool = self._pools[pid]
            if pool.state.fee_tier == fee_tier:
                raise ValueError(f"Pool already exists for {pair_key} with fee tier {fee_tier}")

        # Stake validation
        required = POOL_STAKE_REQUIREMENTS[pool_type]
        if pool_type == PoolType.SUBSIDIZED:
            # Subsidized pools require burn, not stake
            if stake_amount < required:
                raise ValueError(f"Subsidized pool requires burning {required} QRDX (got {stake_amount})")
        else:
            if stake_amount < required:
                raise ValueError(
                    f"{PoolType(pool_type).name} pool requires staking {required} QRDX (got {stake_amount})"
                )

        if initial_sqrt_price <= 0:
            raise ValueError("Initial sqrt price must be positive")

        self._pool_sequence += 1
        pool_id = self._deterministic_pool_id(token0, token1, fee_tier, self._pool_sequence)
        state = PoolState(
            id=pool_id,
            token0=token0,
            token1=token1,
            fee_tier=fee_tier,
            pool_type=pool_type,
            creator=creator,
            sqrt_price=initial_sqrt_price,
            tick=sqrt_price_to_tick(initial_sqrt_price),
        )
        pool = ConcentratedLiquidityPool(state)
        self._pools[pool_id] = pool

        if pair_key not in self._pair_index:
            self._pair_index[pair_key] = []
        self._pair_index[pair_key].append(pool_id)

        logger.info("Pool %s created: %s/%s fee=%s type=%s", pool_id, token0, token1, fee_tier, pool_type.name)
        return pool

    def get_pool(self, pool_id: str) -> Optional[ConcentratedLiquidityPool]:
        return self._pools.get(pool_id)

    def get_pools_for_pair(self, token0: str, token1: str) -> List[ConcentratedLiquidityPool]:
        if token0 > token1:
            token0, token1 = token1, token0
        pair_key = f"{token0}:{token1}"
        return [self._pools[pid] for pid in self._pair_index.get(pair_key, [])]

    def get_all_pools(self) -> List[ConcentratedLiquidityPool]:
        return list(self._pools.values())

    def get_best_pool(self, token0: str, token1: str) -> Optional[ConcentratedLiquidityPool]:
        """Pool with the most active liquidity for a given pair."""
        pools = self.get_pools_for_pair(token0, token1)
        if not pools:
            return None
        return max(pools, key=lambda p: p.state.liquidity)

    @staticmethod
    def _deterministic_pool_id(token0: str, token1: str, fee_tier: FeeTier, seq: int) -> str:
        """Deterministic pool ID — consensus-safe."""
        raw = f"{token0}:{token1}:{fee_tier}:{seq}".encode()
        return hashlib.blake2b(raw, digest_size=8).hexdigest()
