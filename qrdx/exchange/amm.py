"""
QRDX Concentrated-Liquidity AMM  (Whitepaper §7.1 + §7.3 + §7.6) — Uniswap V3 mathematics.

A pool trades two tokens. Liquidity providers deposit into price ranges [tick_lower, tick_upper);
a swap moves the price along x·y = L² for the liquidity active at each price, CROSSING range
boundaries (ticks) as it goes and activating / deactivating the liquidity there, exactly as
Uniswap V3 does. A position earns fees only while the price is inside its range.

Determinism. Every value is Decimal arithmetic in one pinned context — no floats (``math.pow`` /
``math.log`` can differ in the last bit across platforms, which in consensus code splits the
chain). Tick ↔ price conversions use ``Decimal`` powers and logarithms, computed identically by
the software decimal library on every node.

Solvency. Rounding always favours the pool: a deposit and a swap's input are rounded UP, a
withdrawal and a swap's output rounded DOWN, each bound computed with directed rounding at every
step. So the tokens the pool holds always cover every position's principal and fees.

Fees (§7.6). Each swap's fee is split: 70 % to the liquidity providers in range (pro rata, via
fee growth inside each position's range) and 30 % to the protocol (creator / treasury /
validators), which the pool holds in ``protocol_fees_*`` until collected.

Atomicity. ``quote`` simulates a swap without touching the pool and returns its exact plan;
``apply`` executes a plan. A caller checks slippage, balances and solvency on the plan first, so
a swap that fails a check changes nothing — and a quote is exactly what executes.

Oracle. Each pool records Uniswap-style tick-cumulative observations on block time (at most one
per block, written before the block's first change), so its time-weighted price cannot be moved
within a block and replays to the same value on every node.
"""

from __future__ import annotations

import bisect
import functools
import hashlib
import logging
from dataclasses import dataclass, field
from decimal import (
    ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_EVEN, ROUND_HALF_UP, Context, Decimal,
    getcontext, localcontext,
)
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple

# Q96 arithmetic requires high precision. (Kept for modules that relied on importing this one to
# raise the process-wide default; this module's own arithmetic runs in the pinned contexts below.)
getcontext().prec = 78

logger = logging.getLogger(__name__)

ZERO = Decimal("0")
ONE = Decimal("1")
Q96 = Decimal(2 ** 96)
MIN_TICK = -887272
MAX_TICK = 887272
TICK_BASE = Decimal("1.0001")
AMOUNT_QUANTUM = Decimal("1e-18")        # token amounts: 18 decimals
MAX_OBSERVATIONS = 64

_PREC = 78
_CTX = Context(prec=_PREC, rounding=ROUND_HALF_EVEN)
_UP = Context(prec=_PREC, rounding=ROUND_CEILING)
_DOWN = Context(prec=_PREC, rounding=ROUND_FLOOR)


def _pinned(method):
    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        with localcontext(_CTX):
            return method(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FeeTier(IntEnum):
    """Fee tiers in pips (1e-6), Whitepaper §7.6."""
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


_TICK_SPACINGS = {100: 1, 500: 10, 3000: 60, 10000: 200}


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

# Fee distribution (§7.6): liquidity providers in range get FEE_LP_SHARE; the rest is the
# protocol's (creator / treasury / validators), held by the pool until collected.
FEE_LP_SHARE = Decimal("0.70")
FEE_CREATOR_SHARE = Decimal("0.15")
FEE_TREASURY_SHARE = Decimal("0.10")
FEE_VALIDATOR_SHARE = Decimal("0.05")

MIN_INITIAL_LIQUIDITY = Decimal("1000")


# ---------------------------------------------------------------------------
# Deterministic tick math
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=1 << 16)
def _sqrt_ratio(tick: int) -> Decimal:
    """√(1.0001^tick), plain (not Q96)."""
    with localcontext(_CTX):
        return (TICK_BASE ** tick).sqrt()


@functools.lru_cache(maxsize=1)
def _ln_base() -> Decimal:
    with localcontext(_CTX):
        return TICK_BASE.ln()


def tick_to_sqrt_price(tick: int) -> Decimal:
    """Tick → √price in Q96 (the representation pool state stores)."""
    with localcontext(_CTX):
        return _sqrt_ratio(int(tick)) * Q96


def _tick_at(s: Decimal) -> int:
    """The tick t with √ratio(t) ≤ s < √ratio(t+1), for a plain √price s."""
    with localcontext(_CTX):
        if s <= 0:
            return MIN_TICK
        t = int(((s * s).ln() / _ln_base()).to_integral_value(rounding=ROUND_FLOOR))
        t = max(MIN_TICK, min(MAX_TICK, t))
        while t < MAX_TICK and _sqrt_ratio(t + 1) <= s:
            t += 1
        while t > MIN_TICK and _sqrt_ratio(t) > s:
            t -= 1
        return t


def sqrt_price_to_tick(sqrt_price: Decimal) -> int:
    """√price (Q96) → the tick whose range contains it, judged against exactly the Q96 values
    ``tick_to_sqrt_price`` produces (so a price stored at a tick reads back as that tick)."""
    with localcontext(_CTX):
        x = Decimal(sqrt_price)
        t = _tick_at(x / Q96)
        while t < MAX_TICK and tick_to_sqrt_price(t + 1) <= x:
            t += 1
        while t > MIN_TICK and tick_to_sqrt_price(t) > x:
            t -= 1
        return t


_DISPLAY = Context(prec=18, rounding=ROUND_HALF_UP)


def sqrt_price_to_price(sqrt_price: Decimal) -> Decimal:
    """√price (Q96) → token1 per token0, to 18 significant digits (display — fixed decimal
    places would show a 1e-10 price as zero)."""
    with localcontext(_CTX):
        ratio = Decimal(sqrt_price) / Q96
        square = ratio * ratio
    with localcontext(_DISPLAY):
        return +square


MIN_SQRT_RATIO = tick_to_sqrt_price(MIN_TICK)
MAX_SQRT_RATIO = tick_to_sqrt_price(MAX_TICK)


def _q_up(x: Decimal) -> Decimal:
    return x.quantize(AMOUNT_QUANTUM, rounding=ROUND_CEILING)


def _q_down(x: Decimal) -> Decimal:
    return x.quantize(AMOUNT_QUANTUM, rounding=ROUND_FLOOR)


def amount0_delta(s_a: Decimal, s_b: Decimal, liquidity: Decimal, round_up: bool) -> Decimal:
    """token0 between plain √prices s_a < s_b for liquidity L: L·(s_b − s_a)/(s_a·s_b)."""
    if s_a > s_b:
        s_a, s_b = s_b, s_a
    if liquidity <= 0 or s_a == s_b:
        return ZERO
    hi, lo = (_UP, _DOWN) if round_up else (_DOWN, _UP)
    with localcontext(hi):
        numerator = liquidity * (s_b - s_a)
    with localcontext(lo):
        denominator = s_a * s_b
    with localcontext(hi):
        value = numerator / denominator
    return _q_up(value) if round_up else _q_down(value)


def amount1_delta(s_a: Decimal, s_b: Decimal, liquidity: Decimal, round_up: bool) -> Decimal:
    """token1 between plain √prices s_a < s_b for liquidity L: L·(s_b − s_a)."""
    if s_a > s_b:
        s_a, s_b = s_b, s_a
    if liquidity <= 0 or s_a == s_b:
        return ZERO
    with localcontext(_UP if round_up else _DOWN):
        value = liquidity * (s_b - s_a)
    return _q_up(value) if round_up else _q_down(value)


def _next_sqrt_from_input(s: Decimal, liquidity: Decimal, amount: Decimal,
                          zero_for_one: bool) -> Decimal:
    """The √price after adding ``amount`` of the input token, rounded so the pool keeps the
    better side: up when token0 comes in (price falls), down when token1 comes in."""
    if zero_for_one:
        with localcontext(_UP):
            numerator = liquidity * s
        with localcontext(_DOWN):
            denominator = liquidity + amount * s
        with localcontext(_UP):
            return numerator / denominator
    with localcontext(_DOWN):
        return s + amount / liquidity


def _swap_step(s: Decimal, s_target: Decimal, liquidity: Decimal, remaining: Decimal,
               fee_rate: Decimal, zero_for_one: bool) -> Tuple[Decimal, Decimal, Decimal, Decimal]:
    """One exact-input step toward ``s_target``: (√price after, input, output, fee)."""
    with localcontext(_DOWN):
        remaining_less_fee = _q_down(remaining * (ONE - fee_rate))
    if zero_for_one:
        to_target = amount0_delta(s_target, s, liquidity, round_up=True)
    else:
        to_target = amount1_delta(s, s_target, liquidity, round_up=True)
    if liquidity > 0 and remaining_less_fee < to_target:
        s_next = _next_sqrt_from_input(s, liquidity, remaining_less_fee, zero_for_one)
        reached = False
    else:
        s_next, reached = s_target, True
    if zero_for_one:
        amount_in = amount0_delta(s_next, s, liquidity, round_up=True)
        amount_out = amount1_delta(s_next, s, liquidity, round_up=False)
    else:
        amount_in = amount1_delta(s, s_next, liquidity, round_up=True)
        amount_out = amount0_delta(s, s_next, liquidity, round_up=False)
    if not reached:
        fee = remaining - amount_in              # the input left over is all fee
    elif amount_in > 0:
        with localcontext(_UP):
            fee = _q_up(amount_in * fee_rate / (ONE - fee_rate))
    else:
        fee = ZERO
    return s_next, amount_in, amount_out, fee


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
    tokens_owed_0: Decimal = ZERO            # fees earned, not yet paid out
    tokens_owed_1: Decimal = ZERO
    created_at: float = 0.0

    @property
    def is_active(self) -> bool:
        return self.liquidity > 0


@dataclass
class Observation:
    """Tick-cumulative observation (block time, Σ tick·dt)."""
    time: int
    tick_cumulative: int


@dataclass
class PoolState:
    """
    State of a concentrated-liquidity pool. token0 < token1 (canonical ordering);
    ``sqrt_price`` is √(token1 per token0) in Q96.
    """
    id: str
    token0: str
    token1: str
    fee_tier: FeeTier
    pool_type: PoolType
    creator: str

    # QRDX staked to create the pool (debited from the creator's account_state under
    # ENFORCE_POOL_STAKE); REMOVE_POOL refunds it for a staking pool (SUBSIDIZED burns it).
    stake_amount: Decimal = ZERO

    sqrt_price: Decimal = ZERO
    tick: int = 0
    liquidity: Decimal = ZERO                # active (in-range) liquidity

    # Fee growth per unit of liquidity, LP share only (§7.6)
    fee_growth_global_0: Decimal = ZERO
    fee_growth_global_1: Decimal = ZERO

    # The protocol's share of fees (creator / treasury / validators), held until collected
    protocol_fees_0: Decimal = ZERO
    protocol_fees_1: Decimal = ZERO

    ticks: Dict[int, TickInfo] = field(default_factory=dict)
    positions: Dict[str, Position] = field(default_factory=dict)
    observations: List[Observation] = field(default_factory=list)

    total_volume_0: Decimal = ZERO
    total_volume_1: Decimal = ZERO
    created_at: float = 0.0

    @property
    def price(self) -> Decimal:
        return sqrt_price_to_price(self.sqrt_price)


@dataclass
class SwapPlan:
    """A simulated exact-input swap — what ``apply`` will do, to the last unit."""
    zero_for_one: bool
    amount_in: Decimal                       # input consumed, fee included
    amount_out: Decimal
    fee: Decimal                             # total fee (LP + protocol)
    protocol_fee: Decimal
    sqrt_price: Decimal                      # Q96, after
    tick: int
    liquidity: Decimal
    fee_growth_global: Decimal               # the input token's, after
    crossings: List[Tuple[int, Decimal, Decimal]] = field(default_factory=list)  # tick, fg0, fg1

    @property
    def price(self) -> Decimal:
        """Average execution price: input per unit of output."""
        return self.amount_in / self.amount_out if self.amount_out > 0 else ZERO


# ---------------------------------------------------------------------------
# Concentrated Liquidity Pool
# ---------------------------------------------------------------------------

class ConcentratedLiquidityPool:
    """One pool: swaps (quote → apply), liquidity (mint / burn), fees, oracle."""

    def __init__(self, state: PoolState):
        self.state = state
        self._paused: bool = False
        self._pos_sequence: int = 0  # deterministic position ID counter
        self._tick_index: List[int] = sorted(t for t, i in state.ticks.items() if i.initialized)

    # -- Atomicity ------------------------------------------------------------

    def snapshot(self) -> Any:
        import copy
        return copy.deepcopy((self.state, self._tick_index, self._pos_sequence, self._paused))

    def restore(self, snap: Any) -> None:
        self.state, self._tick_index, self._pos_sequence, self._paused = snap

    # -- Emergency controls -------------------------------------------------

    def pause(self) -> None:
        self._paused = True

    def unpause(self) -> None:
        self._paused = False

    @property
    def is_paused(self) -> bool:
        return self._paused

    # -- Ticks --------------------------------------------------------------

    def _next_tick(self, tick: int, zero_for_one: bool) -> Optional[int]:
        """The next initialized tick in the swap's direction: the highest ≤ ``tick`` moving
        down, the lowest > ``tick`` moving up."""
        idx = self._tick_index
        if zero_for_one:
            i = bisect.bisect_right(idx, tick)
            return idx[i - 1] if i > 0 else None
        i = bisect.bisect_right(idx, tick)
        return idx[i] if i < len(idx) else None

    def _update_tick(self, tick: int, liquidity_delta: Decimal, upper: bool) -> None:
        st = self.state
        info = st.ticks.get(tick)
        if info is None:
            info = st.ticks[tick] = TickInfo(tick=tick)
        if not info.initialized and liquidity_delta > 0:
            # Uniswap's convention: growth "outside" starts as all growth so far if the tick
            # is at or below the price, none if above.
            if tick <= st.tick:
                info.fee_growth_outside_0 = st.fee_growth_global_0
                info.fee_growth_outside_1 = st.fee_growth_global_1
            info.initialized = True
            bisect.insort(self._tick_index, tick)
        info.liquidity_gross += liquidity_delta
        info.liquidity_net += -liquidity_delta if upper else liquidity_delta
        if info.liquidity_gross <= 0:
            del st.ticks[tick]
            i = bisect.bisect_left(self._tick_index, tick)
            if i < len(self._tick_index) and self._tick_index[i] == tick:
                del self._tick_index[i]

    def _fee_growth_inside(self, lower: int, upper: int) -> Tuple[Decimal, Decimal]:
        st = self.state
        g0, g1 = st.fee_growth_global_0, st.fee_growth_global_1
        lo, up = st.ticks[lower], st.ticks[upper]
        if st.tick >= lower:
            below0, below1 = lo.fee_growth_outside_0, lo.fee_growth_outside_1
        else:
            below0, below1 = g0 - lo.fee_growth_outside_0, g1 - lo.fee_growth_outside_1
        if st.tick < upper:
            above0, above1 = up.fee_growth_outside_0, up.fee_growth_outside_1
        else:
            above0, above1 = g0 - up.fee_growth_outside_0, g1 - up.fee_growth_outside_1
        return g0 - below0 - above0, g1 - below1 - above1

    def _pending_fees(self, position: Position) -> Tuple[Decimal, Decimal, Decimal, Decimal]:
        """(fee growth inside now ×2, fees earned since the position last accrued ×2)."""
        inside0, inside1 = self._fee_growth_inside(position.tick_lower, position.tick_upper)
        with localcontext(_DOWN):
            fees0 = _q_down(position.liquidity * (inside0 - position.fee_growth_inside_0_last))
            fees1 = _q_down(position.liquidity * (inside1 - position.fee_growth_inside_1_last))
        return inside0, inside1, fees0, fees1

    def _accrue(self, position: Position) -> None:
        inside0, inside1, fees0, fees1 = self._pending_fees(position)
        position.tokens_owed_0 += fees0
        position.tokens_owed_1 += fees1
        position.fee_growth_inside_0_last = inside0
        position.fee_growth_inside_1_last = inside1

    @_pinned
    def position_value(self, position_id: str) -> Tuple[Decimal, Decimal, Decimal, Decimal]:
        """What removing the whole position would pay right now — (principal0, principal1,
        fees0, fees1), exactly as ``remove_liquidity`` computes them — without changing
        anything."""
        position = self.state.positions[position_id]
        _, _, fees0, fees1 = self._pending_fees(position)
        principal0, principal1 = self.amounts_for_liquidity(
            position.tick_lower, position.tick_upper, position.liquidity, round_up=False)
        return principal0, principal1, position.tokens_owed_0 + fees0, position.tokens_owed_1 + fees1

    # -- Oracle -------------------------------------------------------------

    def observe_block(self, now: Optional[int]) -> None:
        """Write this block's observation before the block's first change (once per block)."""
        if now is None:
            return
        now = int(now)
        obs = self.state.observations
        if not obs:
            obs.append(Observation(time=now, tick_cumulative=0))
            return
        last = obs[-1]
        if now <= last.time:
            return
        obs.append(Observation(time=now, tick_cumulative=last.tick_cumulative
                               + self.state.tick * (now - last.time)))
        if len(obs) > MAX_OBSERVATIONS:
            del obs[:len(obs) - MAX_OBSERVATIONS]

    def _cumulative_at(self, when: int) -> Optional[int]:
        """Σ tick·dt up to block time ``when``. Between two observations the tick was constant
        (observations are written before each block's first change), so this is exact."""
        obs = self.state.observations
        if not obs or when < obs[0].time:
            return None
        i = bisect.bisect_right([o.time for o in obs], when) - 1
        o = obs[i]
        if i + 1 < len(obs):
            nxt = obs[i + 1]
            tick = (nxt.tick_cumulative - o.tick_cumulative) // (nxt.time - o.time)
        else:
            tick = self.state.tick
        return o.tick_cumulative + tick * (when - o.time)

    @_pinned
    def twap_price(self, window: int, now: int) -> Optional[Decimal]:
        """Time-weighted average price (token1 per token0) over the ``window`` seconds of block
        time up to ``now`` — the geometric mean, from tick cumulatives. None without enough
        history."""
        window, now = int(window), int(now)
        if window <= 0:
            return None
        end, start = self._cumulative_at(now), self._cumulative_at(now - window)
        if end is None or start is None:
            return None
        return TICK_BASE ** ((end - start) // window)

    # -- Swap ---------------------------------------------------------------

    @_pinned
    def quote(self, amount_in: Decimal, zero_for_one: bool) -> SwapPlan:
        """Simulate an exact-input swap without changing the pool. Raises if the pool cannot
        absorb the whole input (no liquidity left in that direction)."""
        if self._paused:
            raise ValueError("Pool is paused — emergency mode")
        amount_in = Decimal(str(amount_in))
        if amount_in <= 0:
            raise ValueError("Swap amount must be positive")
        if amount_in != amount_in.quantize(AMOUNT_QUANTUM):
            raise ValueError("Swap amount has more than 18 decimal places")
        st = self.state
        if st.liquidity <= 0 and self._next_tick(st.tick, zero_for_one) is None:
            raise ValueError("No liquidity in pool")
        fee_rate = st.fee_tier.rate
        s = st.sqrt_price / Q96
        tick, liquidity = st.tick, st.liquidity
        fg = st.fee_growth_global_0 if zero_for_one else st.fee_growth_global_1
        other = st.fee_growth_global_1 if zero_for_one else st.fee_growth_global_0
        ticks = st.ticks
        remaining, out, fee_total, protocol = amount_in, ZERO, ZERO, ZERO
        crossings: List[Tuple[int, Decimal, Decimal]] = []
        cursor = tick
        while remaining > 0:
            nxt = self._next_tick(cursor, zero_for_one)
            boundary = nxt is None
            target_tick = (MIN_TICK if zero_for_one else MAX_TICK) if boundary else nxt
            s_target = _sqrt_ratio(target_tick)
            if (zero_for_one and s_target >= s) or (not zero_for_one and s_target <= s):
                if boundary:
                    raise ValueError("Insufficient liquidity for this swap")
            s_next, step_in, step_out, step_fee = _swap_step(
                s, s_target, liquidity, remaining, fee_rate, zero_for_one)
            remaining -= step_in + step_fee
            out += step_out
            fee_total += step_fee
            if liquidity > 0 and step_fee > 0:
                lp_fee = _q_down(step_fee * FEE_LP_SHARE)
                protocol += step_fee - lp_fee
                with localcontext(_DOWN):
                    fg += lp_fee / liquidity
            else:
                protocol += step_fee
            s = s_next
            if s_next == s_target:
                if boundary:
                    if remaining > 0:
                        raise ValueError("Insufficient liquidity for this swap")
                    tick = target_tick
                    break
                net = ticks[nxt].liquidity_net
                fg0, fg1 = (fg, other) if zero_for_one else (other, fg)
                crossings.append((nxt, fg0, fg1))
                liquidity = liquidity - net if zero_for_one else liquidity + net
                if liquidity < 0:
                    raise ValueError("pool liquidity accounting broke")  # cannot happen
                tick = nxt - 1 if zero_for_one else nxt
                cursor = tick
            else:
                tick = _tick_at(s)
                break
        if out <= 0:
            raise ValueError("Swap too small: no output")
        return SwapPlan(zero_for_one=zero_for_one, amount_in=amount_in, amount_out=out,
                        fee=fee_total, protocol_fee=protocol, sqrt_price=s * Q96, tick=tick,
                        liquidity=liquidity, fee_growth_global=fg, crossings=crossings)

    @_pinned
    def apply(self, plan: SwapPlan, now: Optional[int] = None) -> SwapPlan:
        """Execute a plan from ``quote`` on the current (unchanged) state."""
        st = self.state
        self.observe_block(now)
        for tick, fg0, fg1 in plan.crossings:
            info = st.ticks[tick]
            info.fee_growth_outside_0 = fg0 - info.fee_growth_outside_0
            info.fee_growth_outside_1 = fg1 - info.fee_growth_outside_1
        if plan.zero_for_one:
            st.fee_growth_global_0 = plan.fee_growth_global
            st.protocol_fees_0 += plan.protocol_fee
            st.total_volume_0 += plan.amount_in
        else:
            st.fee_growth_global_1 = plan.fee_growth_global
            st.protocol_fees_1 += plan.protocol_fee
            st.total_volume_1 += plan.amount_in
        st.sqrt_price, st.tick, st.liquidity = plan.sqrt_price, plan.tick, plan.liquidity
        return plan

    def swap(self, amount_in: Decimal, zero_for_one: bool, min_amount_out: Decimal = ZERO,
             now: Optional[int] = None) -> Tuple[Decimal, Decimal]:
        """Quote, check slippage, apply. Returns (amount_out, fee). Raises — changing
        nothing — if the output would be below ``min_amount_out``."""
        plan = self.quote(amount_in, zero_for_one)
        if min_amount_out > 0 and plan.amount_out < min_amount_out:
            raise ValueError(f"Slippage exceeded: got {plan.amount_out}, minimum {min_amount_out}")
        self.apply(plan, now)
        return plan.amount_out, plan.fee

    @_pinned
    def price_impact(self, amount_in: Decimal, zero_for_one: bool) -> Decimal:
        """How far a swap would move the price, as a fraction. Read-only."""
        try:
            plan = self.quote(amount_in, zero_for_one)
        except ValueError:
            return ONE
        before = (self.state.sqrt_price / Q96) ** 2
        after = (plan.sqrt_price / Q96) ** 2
        return (abs(after - before) / before).quantize(Decimal("0.00000001"),
                                                       rounding=ROUND_HALF_UP) if before > 0 else ZERO

    # -- Liquidity ----------------------------------------------------------

    def _check_range(self, tick_lower: int, tick_upper: int) -> None:
        if tick_lower >= tick_upper:
            raise ValueError("tick_lower must be < tick_upper")
        if tick_lower < MIN_TICK or tick_upper > MAX_TICK:
            raise ValueError("Tick out of range")
        spacing = self.state.fee_tier.tick_spacing
        if tick_lower % spacing != 0 or tick_upper % spacing != 0:
            raise ValueError(f"Ticks must be multiples of tick_spacing ({spacing})")

    @_pinned
    def amounts_for_liquidity(self, tick_lower: int, tick_upper: int, liquidity: Decimal,
                              round_up: bool) -> Tuple[Decimal, Decimal]:
        """token0 / token1 that ``liquidity`` in the range is worth at the current price —
        rounded up for a deposit, down for a withdrawal."""
        st = self.state
        s, s_l, s_u = st.sqrt_price / Q96, _sqrt_ratio(tick_lower), _sqrt_ratio(tick_upper)
        if st.tick < tick_lower:
            return amount0_delta(s_l, s_u, liquidity, round_up), ZERO
        if st.tick < tick_upper:
            return (amount0_delta(s, s_u, liquidity, round_up),
                    amount1_delta(s_l, s, liquidity, round_up))
        return ZERO, amount1_delta(s_l, s_u, liquidity, round_up)

    @_pinned
    def liquidity_for_amounts(self, tick_lower: int, tick_upper: int,
                              amount0: Optional[Decimal], amount1: Optional[Decimal]) -> Decimal:
        """The most liquidity in the range that ``amount0`` / ``amount1`` can pay for at the
        current price (None = unlimited) — the deposit ``amounts_for_liquidity(..., round_up=
        True)`` charges for it never exceeds them. Read-only."""
        self._check_range(tick_lower, tick_upper)
        st = self.state
        s, s_l, s_u = st.sqrt_price / Q96, _sqrt_ratio(tick_lower), _sqrt_ratio(tick_upper)
        lo, hi = (s_l, s_u) if st.tick < tick_lower else ((s, s_u) if st.tick < tick_upper
                                                            else (s_l, s_l))
        candidates = []
        with localcontext(_DOWN):
            if amount0 is not None and hi > lo:          # the token0 side of the range
                candidates.append(Decimal(amount0) * lo * hi / (hi - lo))
            lo1, hi1 = (s_l, s_l) if st.tick < tick_lower else ((s_l, s) if st.tick < tick_upper
                                                                 else (s_l, s_u))
            if amount1 is not None and hi1 > lo1:        # the token1 side
                candidates.append(Decimal(amount1) / (hi1 - lo1))
        if not candidates:
            raise ValueError("amounts give no liquidity in this range at the current price")
        liquidity = min(candidates).quantize(AMOUNT_QUANTUM, rounding=ROUND_FLOOR)
        limit0 = Decimal(amount0) if amount0 is not None else None
        limit1 = Decimal(amount1) if amount1 is not None else None
        for _ in range(64):              # the deposit rounds up: step under it if it overshoots
            if liquidity <= 0:
                break
            cost0, cost1 = self.amounts_for_liquidity(tick_lower, tick_upper, liquidity, True)
            if (limit0 is None or cost0 <= limit0) and (limit1 is None or cost1 <= limit1):
                return liquidity
            liquidity -= AMOUNT_QUANTUM
        return ZERO

    @_pinned
    def add_liquidity(self, owner: str, tick_lower: int, tick_upper: int, amount: Decimal,
                      now: Optional[int] = None) -> Position:
        """Mint ``amount`` of liquidity in [tick_lower, tick_upper) for ``owner``. The tokens
        it costs are ``amounts_for_liquidity(..., round_up=True)``, computed beforehand."""
        if self._paused:
            raise ValueError("Pool is paused — emergency mode")
        self._check_range(tick_lower, tick_upper)
        amount = Decimal(str(amount))
        if amount <= 0:
            raise ValueError("Liquidity amount must be positive")
        st = self.state
        self.observe_block(now)
        self._pos_sequence += 1
        position_id = self._deterministic_position_id(owner, tick_lower, tick_upper,
                                                      self._pos_sequence)
        self._update_tick(tick_lower, amount, upper=False)
        self._update_tick(tick_upper, amount, upper=True)
        inside0, inside1 = self._fee_growth_inside(tick_lower, tick_upper)
        position = Position(id=position_id, owner=owner, pool_id=st.id, tick_lower=tick_lower,
                            tick_upper=tick_upper, liquidity=amount,
                            fee_growth_inside_0_last=inside0, fee_growth_inside_1_last=inside1)
        if tick_lower <= st.tick < tick_upper:
            st.liquidity += amount
        st.positions[position_id] = position
        return position

    @_pinned
    def remove_liquidity(self, position_id: str, amount: Optional[Decimal] = None,
                         owner: Optional[str] = None,
                         now: Optional[int] = None) -> Tuple[Decimal, Decimal]:
        """Burn ``amount`` (default: all) of a position's liquidity and collect its fees.
        Returns the tokens it releases: principal at the current price (rounded down) plus
        every fee the position has earned. With ``owner`` given, only the owner may."""
        position = self.state.positions.get(position_id)
        if position is None:
            raise ValueError(f"Position {position_id} not found")
        if owner is not None and position.owner != owner:
            raise ValueError("only the position's owner may remove its liquidity")
        remove = position.liquidity if amount is None else Decimal(str(amount))
        if remove < 0 or remove > position.liquidity:
            raise ValueError("Cannot remove more liquidity than position holds")
        st = self.state
        self.observe_block(now)
        self._accrue(position)
        principal0, principal1 = self.amounts_for_liquidity(
            position.tick_lower, position.tick_upper, remove, round_up=False)
        if remove > 0:
            if position.tick_lower <= st.tick < position.tick_upper:
                st.liquidity -= remove
            position.liquidity -= remove
            self._update_tick(position.tick_lower, -remove, upper=False)
            self._update_tick(position.tick_upper, -remove, upper=True)
        out0 = principal0 + position.tokens_owed_0
        out1 = principal1 + position.tokens_owed_1
        position.tokens_owed_0 = position.tokens_owed_1 = ZERO
        if position.liquidity <= 0:
            del st.positions[position_id]
        return out0, out1

    @staticmethod
    def _deterministic_position_id(owner: str, tick_lower: int, tick_upper: int, seq: int) -> str:
        """Deterministic position ID — consensus-safe."""
        raw = f"{owner}:{tick_lower}:{tick_upper}:{seq}".encode()
        return hashlib.blake2b(raw, digest_size=8).hexdigest()

    # -- State commitment ---------------------------------------------------

    def state_digest(self) -> bytes:
        """Every consensus-relevant field of the pool, hashed in a canonical order."""
        st = self.state
        parts = [st.id, st.token0, st.token1, str(int(st.fee_tier)), str(st.sqrt_price),
                 str(st.tick), str(st.liquidity), str(st.fee_growth_global_0),
                 str(st.fee_growth_global_1), str(st.protocol_fees_0), str(st.protocol_fees_1)]
        for t in sorted(st.ticks):
            i = st.ticks[t]
            parts.append(f"t{t}:{i.liquidity_net}:{i.liquidity_gross}:{i.fee_growth_outside_0}:"
                         f"{i.fee_growth_outside_1}")
        for pid in sorted(st.positions):
            p = st.positions[pid]
            parts.append(f"p{pid}:{p.owner}:{p.tick_lower}:{p.tick_upper}:{p.liquidity}:"
                         f"{p.fee_growth_inside_0_last}:{p.fee_growth_inside_1_last}:"
                         f"{p.tokens_owed_0}:{p.tokens_owed_1}")
        for o in st.observations:
            parts.append(f"o{o.time}:{o.tick_cumulative}")
        parts.append(f"seq{self._pos_sequence}")
        return hashlib.blake2b("|".join(parts).encode(), digest_size=32).digest()


# ---------------------------------------------------------------------------
# Pool Manager  (registry)
# ---------------------------------------------------------------------------

class PoolManager:
    """All AMM pools: permissionless creation (with stake), lookup by id or pair."""

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
        """Create a pool. ``initial_sqrt_price`` is √(token1 per token0) in Q96, for the
        pair in canonical order."""
        if token0 == token1:
            raise ValueError("A pool needs two different tokens")
        if token0 > token1:
            token0, token1 = token1, token0
        pair_key = f"{token0}:{token1}"
        for pid in self._pair_index.get(pair_key, []):
            if self._pools[pid].state.fee_tier == fee_tier:
                raise ValueError(f"Pool already exists for {pair_key} with fee tier {fee_tier}")

        required = POOL_STAKE_REQUIREMENTS[pool_type]
        if stake_amount < required:
            verb = "burning" if pool_type == PoolType.SUBSIDIZED else "staking"
            raise ValueError(f"{PoolType(pool_type).name} pool requires {verb} {required} QRDX "
                             f"(got {stake_amount})")
        initial_sqrt_price = Decimal(str(initial_sqrt_price))
        if 0 < initial_sqrt_price < MIN_SQRT_RATIO:
            # Below the smallest Q96 value there is: a plain √price (callers wrote √30000 as
            # "173.205…"; the old engine read it as Q96 and priced the pool at ~5e-54).
            with localcontext(_CTX):
                initial_sqrt_price = initial_sqrt_price * Q96
        if not (MIN_SQRT_RATIO <= initial_sqrt_price < MAX_SQRT_RATIO):
            raise ValueError("Initial sqrt price out of range")

        self._pool_sequence += 1
        pool_id = self._deterministic_pool_id(token0, token1, fee_tier, self._pool_sequence)
        state = PoolState(
            id=pool_id, token0=token0, token1=token1, fee_tier=fee_tier, pool_type=pool_type,
            creator=creator, stake_amount=stake_amount, sqrt_price=initial_sqrt_price,
            tick=sqrt_price_to_tick(initial_sqrt_price),
        )
        pool = ConcentratedLiquidityPool(state)
        self._pools[pool_id] = pool
        self._pair_index.setdefault(pair_key, []).append(pool_id)
        logger.info("Pool %s created: %s/%s fee=%s type=%s", pool_id, token0, token1, fee_tier,
                    pool_type.name)
        return pool

    def remove_pool(self, pool_id: str) -> Optional[ConcentratedLiquidityPool]:
        """Remove a pool (REMOVE_POOL); returns it so the caller can refund the stake."""
        pool = self._pools.pop(pool_id, None)
        if pool is None:
            return None
        pair_key = f"{pool.state.token0}:{pool.state.token1}"
        ids = self._pair_index.get(pair_key)
        if ids and pool_id in ids:
            ids.remove(pool_id)
            if not ids:
                self._pair_index.pop(pair_key, None)
        return pool

    def get_pool(self, pool_id: str) -> Optional[ConcentratedLiquidityPool]:
        return self._pools.get(pool_id)

    def get_pools_for_pair(self, token0: str, token1: str) -> List[ConcentratedLiquidityPool]:
        if token0 > token1:
            token0, token1 = token1, token0
        return [self._pools[pid] for pid in self._pair_index.get(f"{token0}:{token1}", [])]

    def get_all_pools(self) -> List[ConcentratedLiquidityPool]:
        return list(self._pools.values())

    def get_best_pool(self, token0: str, token1: str) -> Optional[ConcentratedLiquidityPool]:
        """Pool with the most active liquidity for a pair (ties: lowest id)."""
        pools = self.get_pools_for_pair(token0, token1)
        if not pools:
            return None
        return max(pools, key=lambda p: (p.state.liquidity, [-ord(c) for c in p.state.id]))

    @staticmethod
    def _deterministic_pool_id(token0: str, token1: str, fee_tier: FeeTier, seq: int) -> str:
        raw = f"{token0}:{token1}:{fee_tier}:{seq}".encode()
        return hashlib.blake2b(raw, digest_size=8).hexdigest()
