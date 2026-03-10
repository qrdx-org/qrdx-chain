"""
Pool Operator — Create and operate AMM pools on the testnet.

Uses the real QRDX exchange module:
  - ConcentratedLiquidityPool (Uniswap V3-style)
  - PoolManager (pool factory + registry)
  - ExchangePersistence (SQLite persistence)

Operations:
  1. Create pools (STANDARD, BOOTSTRAP, SUBSIDIZED, INSTITUTIONAL)
  2. Add concentrated liquidity positions
  3. Execute swaps with slippage protection
  4. Remove liquidity
  5. Verify pool state consistency (memory vs persistence)

No stubs — every pool is a real ConcentratedLiquidityPool with
full tick math, fee accrual, and reentrancy protection.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from qrdx.exchange.amm import (
    ConcentratedLiquidityPool,
    PoolManager,
    PoolState,
    PoolType,
    FeeTier,
    Position,
    tick_to_sqrt_price,
    sqrt_price_to_tick,
    sqrt_price_to_price,
    Q96,
    MIN_TICK,
    MAX_TICK,
    ZERO,
)
from qrdx.exchange.persistence import ExchangePersistence

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from integration_tests.token_deployer import TokenDeployer


# Default testnet pool configurations
TESTNET_POOLS = [
    {
        "token0": "QRDX",
        "token1": "qETH",
        "fee_tier": FeeTier.MEDIUM,
        "pool_type": PoolType.STANDARD,
        "initial_price": Decimal("0.0005"),   # 1 QRDX = 0.0005 qETH
        "initial_liquidity": Decimal("50000"),
        "description": "QRDX/qETH standard pool",
    },
    {
        "token0": "QRDX",
        "token1": "qUSDC",
        "fee_tier": FeeTier.LOW,
        "pool_type": PoolType.STANDARD,
        "initial_price": Decimal("2.5"),     # 1 QRDX = $2.50
        "initial_liquidity": Decimal("100000"),
        "description": "QRDX/qUSDC low-fee pool",
    },
    {
        "token0": "qETH",
        "token1": "qUSDC",
        "fee_tier": FeeTier.MEDIUM,
        "pool_type": PoolType.BOOTSTRAP,
        "initial_price": Decimal("5000"),    # 1 qETH = $5000
        "initial_liquidity": Decimal("25000"),
        "description": "qETH/qUSDC bootstrap pool",
    },
    {
        "token0": "QRDX",
        "token1": "qBTC",
        "fee_tier": FeeTier.HIGH,
        "pool_type": PoolType.STANDARD,
        "initial_price": Decimal("0.00000005"),  # 1 QRDX = 0.00000005 BTC
        "initial_liquidity": Decimal("20000"),
        "description": "QRDX/qBTC high-fee pool",
    },
]


def price_to_sqrt_price_q96(price: Decimal) -> Decimal:
    """Convert human-readable price to Q96 sqrt price."""
    if price <= 0:
        raise ValueError("Price must be positive")
    sqrt_p = Decimal(str(math.sqrt(float(price)))) * Q96
    return sqrt_p.quantize(Decimal("1"))


class PoolOperator:
    """
    Create and operate AMM pools on the testnet.

    Usage:
        operator = PoolOperator(db_path="testnet/databases/node0.db")
        await operator.initialize()

        pool = operator.create_pool(
            token0="QRDX",
            token1="qETH",
            fee_tier=FeeTier.MEDIUM,
            pool_type=PoolType.STANDARD,
            initial_price=Decimal("0.0005"),
            creator="DKxyz...",
            stake_amount=Decimal("10000"),
        )

        position = operator.add_liquidity(
            pool_id=pool.state.id,
            owner="DKxyz...",
            tick_lower=-60,
            tick_upper=60,
            amount=Decimal("5000"),
        )

        amount_out, fee = operator.swap(
            pool_id=pool.state.id,
            amount_in=Decimal("100"),
            zero_for_one=True,
        )
    """

    def __init__(self, db_path: str, token_deployer: Optional[TokenDeployer] = None):
        self.db_path = db_path
        self._persistence: Optional[ExchangePersistence] = None
        self._pool_manager = PoolManager()
        self._db: Optional[aiosqlite.Connection] = None
        self._token_deployer: Optional[TokenDeployer] = token_deployer

    async def initialize(self) -> None:
        """Initialize persistence layer."""
        import aiosqlite as _aiosqlite
        self._db = await _aiosqlite.connect(self.db_path)
        self._db.row_factory = _aiosqlite.Row
        self._persistence = ExchangePersistence(self._db)
        await self._persistence.initialize()
        logger.info("Pool operator initialized (db=%s)", self.db_path)

    async def close(self) -> None:
        if self._db:
            await self._db.close()

    async def __aenter__(self):
        await self.initialize()
        return self

    async def __aexit__(self, *exc):
        await self.close()

    @staticmethod
    def _pool_vault_address(pool_id: str) -> str:
        """Deterministic vault address for a pool's escrowed tokens."""
        raw = hashlib.blake2b(f"pool-vault:{pool_id}".encode(), digest_size=20).hexdigest()
        return f"0xVAULT{raw}"

    # ─────────── Pool Creation ───────────

    def create_pool(
        self,
        token0: str,
        token1: str,
        fee_tier: FeeTier,
        pool_type: PoolType,
        initial_price: Decimal,
        creator: str,
        stake_amount: Decimal = ZERO,
    ) -> ConcentratedLiquidityPool:
        """
        Create a new liquidity pool using the real PoolManager.

        Calculates the Q96 sqrt price from the human-readable price
        and calls PoolManager.create_pool() with full validation.
        """
        initial_sqrt_price = price_to_sqrt_price_q96(initial_price)

        logger.info("Creating pool: %s/%s, fee=%s, type=%s, price=%s, creator=%s",
                     token0, token1, fee_tier.name, pool_type.name, initial_price, creator[:20])

        pool = self._pool_manager.create_pool(
            token0=token0,
            token1=token1,
            fee_tier=fee_tier,
            pool_type=pool_type,
            initial_sqrt_price=initial_sqrt_price,
            creator=creator,
            stake_amount=stake_amount,
        )

        logger.info("  ✓ Pool created: %s (tick=%d, sqrt_price=%s)",
                     pool.state.id, pool.state.tick, pool.state.sqrt_price)
        return pool

    async def create_pool_persisted(
        self,
        token0: str,
        token1: str,
        fee_tier: FeeTier,
        pool_type: PoolType,
        initial_price: Decimal,
        creator: str,
        stake_amount: Decimal = ZERO,
    ) -> ConcentratedLiquidityPool:
        """Create pool and persist to database."""
        pool = self.create_pool(
            token0, token1, fee_tier, pool_type,
            initial_price, creator, stake_amount,
        )

        # Persist — pass the in-memory pool_id so DB uses the same key
        await self._persistence.create_pool(
            token_a=pool.state.token0,
            token_b=pool.state.token1,
            fee_tier=int(pool.state.fee_tier),
            pool_type=pool.state.pool_type.name,
            initial_sqrt_price=pool.state.sqrt_price,
            initial_tick=pool.state.tick,
            creator_address=creator,
            pool_id=pool.state.id,
        )

        return pool

    async def create_standard_pools(
        self,
        creator: str,
        stake_amount: Decimal = Decimal("10000"),
    ) -> Dict[str, ConcentratedLiquidityPool]:
        """Create all standard testnet pools."""
        pools = {}
        for spec in TESTNET_POOLS:
            # Use the required stake for each pool type
            required_stake = stake_amount
            if spec["pool_type"] == PoolType.BOOTSTRAP:
                required_stake = Decimal("25000")
            elif spec["pool_type"] == PoolType.SUBSIDIZED:
                required_stake = Decimal("5000")

            pool = await self.create_pool_persisted(
                token0=spec["token0"],
                token1=spec["token1"],
                fee_tier=spec["fee_tier"],
                pool_type=spec["pool_type"],
                initial_price=spec["initial_price"],
                creator=creator,
                stake_amount=required_stake,
            )
            pools[pool.state.id] = pool
        return pools

    # ─────────── Liquidity ───────────

    def add_liquidity(
        self,
        pool_id: str,
        owner: str,
        tick_lower: int,
        tick_upper: int,
        amount: Decimal,
    ) -> Position:
        """
        Add concentrated liquidity to a pool.
        Uses the real ConcentratedLiquidityPool.add_liquidity().
        """
        pool = self._pool_manager.get_pool(pool_id)
        if not pool:
            raise ValueError(f"Pool {pool_id} not found")

        logger.debug("Adding liquidity: pool=%s, owner=%s, ticks=[%d,%d], amount=%s",
                      pool_id, owner[:16], tick_lower, tick_upper, amount)

        position = pool.add_liquidity(
            owner=owner,
            tick_lower=tick_lower,
            tick_upper=tick_upper,
            amount=amount,
        )

        logger.debug("  ✓ Position %s created, active=%s", position.id, position.is_active)
        return position

    def calculate_token_amounts(
        self,
        pool_id: str,
        tick_lower: int,
        tick_upper: int,
        liquidity: Decimal,
    ) -> Tuple[Decimal, Decimal]:
        """
        Calculate token0 and token1 amounts required for a liquidity position.

        Uses Uniswap V3 formulas:
          If current_tick < tick_lower  → only token0 needed
          If current_tick >= tick_upper → only token1 needed
          Otherwise                    → both tokens needed
        """
        pool = self._pool_manager.get_pool(pool_id)
        if not pool:
            raise ValueError(f"Pool {pool_id} not found")

        sqrt_p = pool.state.sqrt_price
        sqrt_a = tick_to_sqrt_price(tick_lower)
        sqrt_b = tick_to_sqrt_price(tick_upper)
        current_tick = pool.state.tick

        token0_amount = ZERO
        token1_amount = ZERO

        if current_tick < tick_lower:
            # Entirely above current price — only token0
            token0_amount = liquidity * Q96 * (sqrt_b - sqrt_a) / (sqrt_a * sqrt_b)
        elif current_tick >= tick_upper:
            # Entirely below current price — only token1
            token1_amount = liquidity * (sqrt_b - sqrt_a) / Q96
        else:
            # Current price in range — both tokens
            token0_amount = liquidity * Q96 * (sqrt_b - sqrt_p) / (sqrt_p * sqrt_b)
            token1_amount = liquidity * (sqrt_p - sqrt_a) / Q96

        # Quantize to 8 decimal places
        token0_amount = abs(token0_amount).quantize(Decimal("0.00000001"))
        token1_amount = abs(token1_amount).quantize(Decimal("0.00000001"))
        return token0_amount, token1_amount

    async def add_liquidity_persisted(
        self,
        pool_id: str,
        owner: str,
        tick_lower: int,
        tick_upper: int,
        amount: Decimal,
    ) -> Position:
        """
        Add liquidity and persist to database.

        If a token_deployer is attached, this also escrows the required
        token0/token1 amounts from the LP's balance into the pool vault.
        """
        pool = self._pool_manager.get_pool(pool_id)
        if not pool:
            raise ValueError(f"Pool {pool_id} not found")

        # Calculate required token deposits BEFORE modifying pool state
        token0_needed, token1_needed = self.calculate_token_amounts(
            pool_id, tick_lower, tick_upper, amount,
        )

        # Transfer tokens from LP → pool vault (if token_deployer wired)
        if self._token_deployer:
            vault = self._pool_vault_address(pool_id)
            t0, t1 = pool.state.token0, pool.state.token1
            if token0_needed > 0:
                await self._token_deployer.transfer(t0, owner, vault, token0_needed)
                logger.debug("  escrow %s %s → vault %s", token0_needed, t0, vault[:16])
            if token1_needed > 0:
                await self._token_deployer.transfer(t1, owner, vault, token1_needed)
                logger.debug("  escrow %s %s → vault %s", token1_needed, t1, vault[:16])

        # Now add liquidity in the AMM engine
        position = self.add_liquidity(pool_id, owner, tick_lower, tick_upper, amount)

        await self._persistence.add_position(
            pool_id=pool_id,
            owner_address=owner,
            tick_lower=tick_lower,
            tick_upper=tick_upper,
            liquidity=amount,
        )

        # Sync in-memory pool state to DB
        await self._persistence.update_pool_state(
            pool_id=pool_id,
            sqrt_price=pool.state.sqrt_price,
            tick=pool.state.tick,
            liquidity=pool.state.liquidity,
        )

        return position

    def remove_liquidity(
        self,
        pool_id: str,
        position_id: str,
        amount: Optional[Decimal] = None,
    ) -> Tuple[Decimal, Decimal]:
        """
        Remove liquidity from a position.
        Returns (token0_amount, token1_amount) withdrawn.
        """
        pool = self._pool_manager.get_pool(pool_id)
        if not pool:
            raise ValueError(f"Pool {pool_id} not found")

        logger.debug("Removing liquidity: pool=%s, position=%s, amount=%s",
                      pool_id, position_id, amount or "ALL")

        token0_out, token1_out = pool.remove_liquidity(position_id, amount)

        logger.debug("  ✓ Withdrawn: token0=%s, token1=%s", token0_out, token1_out)
        return token0_out, token1_out

    # ─────────── Swaps ───────────

    def swap(
        self,
        pool_id: str,
        amount_in: Decimal,
        zero_for_one: bool,
        min_amount_out: Decimal = ZERO,
    ) -> Tuple[Decimal, Decimal]:
        """
        Execute a swap on a pool.
        Uses the real ConcentratedLiquidityPool.swap().

        Returns (amount_out, fee_amount).
        """
        pool = self._pool_manager.get_pool(pool_id)
        if not pool:
            raise ValueError(f"Pool {pool_id} not found")

        direction = "token0→token1" if zero_for_one else "token1→token0"
        logger.debug("Swap: pool=%s, %s, amount_in=%s, min_out=%s",
                      pool_id, direction, amount_in, min_amount_out)

        amount_out, fee = pool.swap(amount_in, zero_for_one, min_amount_out)

        logger.debug("  ✓ Swap: out=%s, fee=%s, new_tick=%d", amount_out, fee, pool.state.tick)
        return amount_out, fee

    async def swap_persisted(
        self,
        pool_id: str,
        amount_in: Decimal,
        zero_for_one: bool,
        sender: str,
        min_amount_out: Decimal = ZERO,
    ) -> Tuple[Decimal, Decimal]:
        """
        Execute swap, transfer real token balances, and persist to database.

        If a token_deployer is attached:
          1. Debit amount_in of token_in from sender
          2. Credit amount_out of token_out to sender
          (fees remain in the pool vault as LP revenue)
        """
        pool = self._pool_manager.get_pool(pool_id)
        token_in = pool.state.token0 if zero_for_one else pool.state.token1
        token_out = pool.state.token1 if zero_for_one else pool.state.token0
        vault = self._pool_vault_address(pool_id)

        # Transfer token_in from sender → pool vault BEFORE executing swap
        if self._token_deployer:
            await self._token_deployer.transfer(token_in, sender, vault, amount_in)

        # Execute the AMM swap (updates prices, fees, volumes)
        amount_out, fee = self.swap(pool_id, amount_in, zero_for_one, min_amount_out)

        # Transfer token_out from pool vault → sender
        if self._token_deployer:
            await self._token_deployer.transfer(token_out, vault, sender, amount_out)

        await self._persistence.record_swap(
            pool_id=pool_id,
            sender_address=sender,
            token_in=token_in,
            token_out=token_out,
            amount_in=amount_in,
            amount_out=amount_out,
            fee_amount=fee,
            sqrt_price_after=pool.state.sqrt_price,
            tick_after=pool.state.tick,
        )

        # Sync in-memory pool state to DB
        await self._persistence.update_pool_state(
            pool_id=pool_id,
            sqrt_price=pool.state.sqrt_price,
            tick=pool.state.tick,
            liquidity=pool.state.liquidity,
        )

        return amount_out, fee

    async def execute_swap_sequence(
        self,
        pool_id: str,
        trader: str,
        swaps: List[Tuple[Decimal, bool]],
        delay: float = 0.5,
    ) -> List[Tuple[Decimal, Decimal]]:
        """
        Execute a sequence of swaps on a pool.

        Args:
            swaps: List of (amount_in, zero_for_one) tuples.
        """
        results = []
        for amount_in, direction in swaps:
            amount_out, fee = await self.swap_persisted(
                pool_id=pool_id,
                amount_in=amount_in,
                zero_for_one=direction,
                sender=trader,
            )
            results.append((amount_out, fee))
            if delay > 0:
                await asyncio.sleep(delay)
        return results

    # ─────────── Query ───────────

    def get_pool(self, pool_id: str) -> Optional[ConcentratedLiquidityPool]:
        return self._pool_manager.get_pool(pool_id)

    def get_pools_for_pair(self, token0: str, token1: str) -> List[ConcentratedLiquidityPool]:
        return self._pool_manager.get_pools_for_pair(token0, token1)

    def get_pool_price(self, pool_id: str) -> Optional[Decimal]:
        """Get current human-readable price for a pool."""
        pool = self._pool_manager.get_pool(pool_id)
        if pool:
            return sqrt_price_to_price(pool.state.sqrt_price)
        return None

    def get_pool_liquidity(self, pool_id: str) -> Optional[Decimal]:
        """Get current active liquidity for a pool."""
        pool = self._pool_manager.get_pool(pool_id)
        if pool:
            return pool.state.liquidity
        return None

    async def get_pool_stats(self, pool_id: str) -> Dict[str, Any]:
        """Get comprehensive pool statistics."""
        pool = self._pool_manager.get_pool(pool_id)
        if not pool:
            return {}

        s = pool.state
        return {
            "pool_id": s.id,
            "token0": s.token0,
            "token1": s.token1,
            "fee_tier": s.fee_tier.name,
            "pool_type": s.pool_type.name,
            "tick": s.tick,
            "sqrt_price": str(s.sqrt_price),
            "price": str(sqrt_price_to_price(s.sqrt_price)),
            "liquidity": str(s.liquidity),
            "volume_0": str(s.total_volume_0),
            "volume_1": str(s.total_volume_1),
            "positions": len(s.positions),
            "protocol_fees_0": str(s.protocol_fees_0),
            "protocol_fees_1": str(s.protocol_fees_1),
        }

    def list_pools(self) -> List[str]:
        """List all pool IDs."""
        return [p.state.id for p in self._pool_manager.get_all_pools()]

    async def get_deployment_summary(self) -> Dict[str, Any]:
        """Get summary of all deployed pools."""
        summary = {}
        for pool in self._pool_manager.get_all_pools():
            summary[pool.state.id] = await self.get_pool_stats(pool.state.id)
        return summary

    # ─────────── Consistency ───────────

    async def verify_pool_consistency(self, pool_id: str) -> bool:
        """Verify in-memory pool state matches database."""
        pool = self._pool_manager.get_pool(pool_id)
        if not pool:
            return False

        db_stats = await self._persistence.get_pool_stats(pool_id)
        if not db_stats:
            logger.warning("Pool %s not found in database", pool_id)
            return False

        memory_liq = str(pool.state.liquidity)
        db_liq = db_stats.get("liquidity", "0")

        if memory_liq != db_liq:
            logger.warning("Pool %s liquidity mismatch: memory=%s, db=%s",
                           pool_id, memory_liq, db_liq)
            return False

        return True
