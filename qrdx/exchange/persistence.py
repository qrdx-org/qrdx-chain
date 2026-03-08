"""
Exchange State Persistence — SQLite Backend

Provides durable storage for the AMM and order book:
  - Pool registry (token pair, fee tier, price, liquidity)
  - Liquidity positions (owner, tick range, liquidity amount)
  - Swap history (token in/out, amounts, fees)
  - Order book orders (limit/market/stop, price-time priority)
  - Fee distribution records

No stubs. All operations are real SQL against the node's SQLite database.
"""

import aiosqlite
from decimal import Decimal
from typing import Dict, List, Optional, Tuple
import logging
import time
import hashlib

logger = logging.getLogger(__name__)

EXCHANGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS amm_pools (
    pool_id TEXT PRIMARY KEY,
    token_a TEXT NOT NULL,
    token_b TEXT NOT NULL,
    fee_tier INTEGER NOT NULL,
    pool_type TEXT NOT NULL DEFAULT 'STANDARD',
    sqrt_price TEXT NOT NULL,
    liquidity TEXT NOT NULL DEFAULT '0',
    tick_current INTEGER NOT NULL DEFAULT 0,
    fee_growth_global_a TEXT NOT NULL DEFAULT '0',
    fee_growth_global_b TEXT NOT NULL DEFAULT '0',
    volume_a TEXT NOT NULL DEFAULT '0',
    volume_b TEXT NOT NULL DEFAULT '0',
    creator_address TEXT NOT NULL,
    paused INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS amm_positions (
    position_id TEXT PRIMARY KEY,
    pool_id TEXT NOT NULL,
    owner_address TEXT NOT NULL,
    tick_lower INTEGER NOT NULL,
    tick_upper INTEGER NOT NULL,
    liquidity TEXT NOT NULL,
    tokens_owed_a TEXT NOT NULL DEFAULT '0',
    tokens_owed_b TEXT NOT NULL DEFAULT '0',
    fee_growth_inside_a TEXT NOT NULL DEFAULT '0',
    fee_growth_inside_b TEXT NOT NULL DEFAULT '0',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (pool_id) REFERENCES amm_pools(pool_id)
);

CREATE TABLE IF NOT EXISTS amm_swaps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pool_id TEXT NOT NULL,
    sender_address TEXT NOT NULL,
    token_in TEXT NOT NULL,
    token_out TEXT NOT NULL,
    amount_in TEXT NOT NULL,
    amount_out TEXT NOT NULL,
    fee_amount TEXT NOT NULL,
    sqrt_price_after TEXT NOT NULL,
    tick_after INTEGER NOT NULL,
    block_height INTEGER,
    tx_hash TEXT,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (pool_id) REFERENCES amm_pools(pool_id)
);

CREATE TABLE IF NOT EXISTS amm_fee_distributions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pool_id TEXT NOT NULL,
    swap_id INTEGER NOT NULL,
    total_fee TEXT NOT NULL,
    lp_fee TEXT NOT NULL,
    creator_fee TEXT NOT NULL,
    treasury_fee TEXT NOT NULL,
    validator_fee TEXT NOT NULL,
    block_height INTEGER,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (pool_id) REFERENCES amm_pools(pool_id),
    FOREIGN KEY (swap_id) REFERENCES amm_swaps(id)
);

CREATE TABLE IF NOT EXISTS orderbook_orders (
    order_id TEXT PRIMARY KEY,
    pool_id TEXT NOT NULL,
    owner_address TEXT NOT NULL,
    order_type TEXT NOT NULL,
    side TEXT NOT NULL,
    price TEXT NOT NULL,
    quantity TEXT NOT NULL,
    filled_quantity TEXT NOT NULL DEFAULT '0',
    status TEXT NOT NULL DEFAULT 'OPEN',
    nonce INTEGER NOT NULL,
    expires_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (pool_id) REFERENCES amm_pools(pool_id)
);

CREATE TABLE IF NOT EXISTS orderbook_trades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pool_id TEXT NOT NULL,
    maker_order_id TEXT NOT NULL,
    taker_order_id TEXT NOT NULL,
    price TEXT NOT NULL,
    quantity TEXT NOT NULL,
    maker_fee TEXT NOT NULL,
    taker_fee TEXT NOT NULL,
    block_height INTEGER,
    tx_hash TEXT,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (pool_id) REFERENCES amm_pools(pool_id)
);

CREATE INDEX IF NOT EXISTS idx_amm_pools_tokens ON amm_pools(token_a, token_b);
CREATE INDEX IF NOT EXISTS idx_amm_pools_creator ON amm_pools(creator_address);
CREATE INDEX IF NOT EXISTS idx_amm_positions_pool ON amm_positions(pool_id);
CREATE INDEX IF NOT EXISTS idx_amm_positions_owner ON amm_positions(owner_address);
CREATE INDEX IF NOT EXISTS idx_amm_swaps_pool ON amm_swaps(pool_id);
CREATE INDEX IF NOT EXISTS idx_amm_swaps_sender ON amm_swaps(sender_address);
CREATE INDEX IF NOT EXISTS idx_amm_swaps_block ON amm_swaps(block_height);
CREATE INDEX IF NOT EXISTS idx_orderbook_orders_pool ON orderbook_orders(pool_id);
CREATE INDEX IF NOT EXISTS idx_orderbook_orders_owner ON orderbook_orders(owner_address);
CREATE INDEX IF NOT EXISTS idx_orderbook_orders_status ON orderbook_orders(status);
CREATE INDEX IF NOT EXISTS idx_orderbook_trades_pool ON orderbook_trades(pool_id);
"""


def _make_pool_id(token_a: str, token_b: str, fee_tier: int) -> str:
    """Deterministic pool ID from token pair + fee tier (no uuid4)."""
    raw = f"{token_a}:{token_b}:{fee_tier}".encode()
    return hashlib.blake2b(raw, digest_size=20).hexdigest()


def _make_position_id(pool_id: str, owner: str, tick_lower: int, tick_upper: int) -> str:
    """Deterministic position ID."""
    raw = f"{pool_id}:{owner}:{tick_lower}:{tick_upper}".encode()
    return hashlib.blake2b(raw, digest_size=20).hexdigest()


def _make_order_id(pool_id: str, owner: str, nonce: int) -> str:
    """Deterministic order ID."""
    raw = f"{pool_id}:{owner}:{nonce}".encode()
    return hashlib.blake2b(raw, digest_size=20).hexdigest()


class ExchangePersistence:
    """
    SQLite persistence for exchange state (AMM + orderbook).
    
    All operations hit the real database — no in-memory fallback.
    """

    def __init__(self, connection: aiosqlite.Connection):
        self.connection = connection

    async def initialize(self) -> None:
        """Create exchange tables if they don't exist."""
        await self.connection.executescript(EXCHANGE_SCHEMA)
        await self.connection.commit()
        logger.info("Exchange persistence schema initialized")

    # ─────────── Pool Operations ───────────

    async def create_pool(
        self,
        token_a: str,
        token_b: str,
        fee_tier: int,
        pool_type: str,
        initial_sqrt_price: Decimal,
        initial_tick: int,
        creator_address: str,
        pool_id: str | None = None,
    ) -> str:
        """Create a new AMM pool. Returns pool_id."""
        if pool_id is None:
            pool_id = _make_pool_id(token_a, token_b, fee_tier)
        now = int(time.time())
        
        # Check for duplicate
        existing = await self.get_pool(pool_id)
        if existing:
            raise ValueError(f"Pool already exists: {pool_id} ({token_a}/{token_b} fee={fee_tier})")
        
        await self.connection.execute(
            """INSERT INTO amm_pools
               (pool_id, token_a, token_b, fee_tier, pool_type, sqrt_price, liquidity,
                tick_current, fee_growth_global_a, fee_growth_global_b,
                volume_a, volume_b, creator_address, paused, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, '0', ?, '0', '0', '0', '0', ?, 0, ?, ?)""",
            (pool_id, token_a, token_b, fee_tier, pool_type,
             str(initial_sqrt_price), initial_tick, creator_address, now, now),
        )
        await self.connection.commit()
        logger.info("Pool created: %s (%s/%s fee=%d)", pool_id, token_a, token_b, fee_tier)
        return pool_id

    async def get_pool(self, pool_id: str) -> Optional[dict]:
        """Get pool metadata."""
        cursor = await self.connection.execute(
            "SELECT * FROM amm_pools WHERE pool_id = ?", (pool_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def list_pools(self) -> List[dict]:
        """List all pools."""
        cursor = await self.connection.execute("SELECT * FROM amm_pools ORDER BY created_at")
        return [dict(r) for r in await cursor.fetchall()]

    async def update_pool_state(
        self,
        pool_id: str,
        sqrt_price: Decimal,
        tick: int,
        liquidity: Decimal,
    ) -> None:
        """Update pool price/tick/liquidity after a swap or liquidity change."""
        now = int(time.time())
        await self.connection.execute(
            """UPDATE amm_pools SET sqrt_price = ?, tick_current = ?, liquidity = ?, updated_at = ?
               WHERE pool_id = ?""",
            (str(sqrt_price), tick, str(liquidity), now, pool_id),
        )
        await self.connection.commit()

    async def update_pool_volume(
        self, pool_id: str, amount_a: Decimal, amount_b: Decimal
    ) -> None:
        """Increment cumulative volume counters."""
        now = int(time.time())
        await self.connection.execute(
            """UPDATE amm_pools
               SET volume_a = CAST(CAST(volume_a AS DECIMAL) + ? AS TEXT),
                   volume_b = CAST(CAST(volume_b AS DECIMAL) + ? AS TEXT),
                   updated_at = ?
               WHERE pool_id = ?""",
            (str(amount_a), str(amount_b), now, pool_id),
        )
        await self.connection.commit()

    # ─────────── Position Operations ───────────

    async def add_position(
        self,
        pool_id: str,
        owner_address: str,
        tick_lower: int,
        tick_upper: int,
        liquidity: Decimal,
    ) -> str:
        """Add a liquidity position. Returns position_id."""
        position_id = _make_position_id(pool_id, owner_address, tick_lower, tick_upper)
        now = int(time.time())
        
        await self.connection.execute(
            """INSERT INTO amm_positions
               (position_id, pool_id, owner_address, tick_lower, tick_upper, liquidity,
                tokens_owed_a, tokens_owed_b, fee_growth_inside_a, fee_growth_inside_b,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, '0', '0', '0', '0', ?, ?)
               ON CONFLICT(position_id) DO UPDATE SET
                liquidity = CAST(CAST(liquidity AS DECIMAL) + ? AS TEXT), updated_at = ?""",
            (position_id, pool_id, owner_address, tick_lower, tick_upper,
             str(liquidity), now, now, str(liquidity), now),
        )
        await self.connection.commit()
        return position_id

    async def get_position(self, position_id: str) -> Optional[dict]:
        """Get a specific position."""
        cursor = await self.connection.execute(
            "SELECT * FROM amm_positions WHERE position_id = ?", (position_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_positions_by_owner(self, owner_address: str) -> List[dict]:
        """Get all positions for an owner."""
        cursor = await self.connection.execute(
            "SELECT * FROM amm_positions WHERE owner_address = ? ORDER BY created_at",
            (owner_address,),
        )
        return [dict(r) for r in await cursor.fetchall()]

    async def get_positions_by_pool(self, pool_id: str) -> List[dict]:
        """Get all positions in a pool."""
        cursor = await self.connection.execute(
            "SELECT * FROM amm_positions WHERE pool_id = ? ORDER BY tick_lower",
            (pool_id,),
        )
        return [dict(r) for r in await cursor.fetchall()]

    # ─────────── Swap Recording ───────────

    async def record_swap(
        self,
        pool_id: str,
        sender_address: str,
        token_in: str,
        token_out: str,
        amount_in: Decimal,
        amount_out: Decimal,
        fee_amount: Decimal,
        sqrt_price_after: Decimal,
        tick_after: int,
        block_height: Optional[int] = None,
        tx_hash: Optional[str] = None,
    ) -> int:
        """Record a swap. Returns swap ID."""
        now = int(time.time())
        cursor = await self.connection.execute(
            """INSERT INTO amm_swaps
               (pool_id, sender_address, token_in, token_out, amount_in, amount_out,
                fee_amount, sqrt_price_after, tick_after, block_height, tx_hash, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (pool_id, sender_address, token_in, token_out,
             str(amount_in), str(amount_out), str(fee_amount),
             str(sqrt_price_after), tick_after, block_height, tx_hash, now),
        )
        await self.connection.commit()
        return cursor.lastrowid

    async def record_fee_distribution(
        self,
        pool_id: str,
        swap_id: int,
        total_fee: Decimal,
        lp_fee: Decimal,
        creator_fee: Decimal,
        treasury_fee: Decimal,
        validator_fee: Decimal,
        block_height: Optional[int] = None,
    ) -> None:
        """Record fee distribution for a swap (Whitepaper §7.6 split)."""
        now = int(time.time())
        await self.connection.execute(
            """INSERT INTO amm_fee_distributions
               (pool_id, swap_id, total_fee, lp_fee, creator_fee, treasury_fee, validator_fee,
                block_height, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (pool_id, swap_id, str(total_fee), str(lp_fee), str(creator_fee),
             str(treasury_fee), str(validator_fee), block_height, now),
        )
        await self.connection.commit()

    async def get_swaps(self, pool_id: str, limit: int = 100) -> List[dict]:
        """Get recent swaps for a pool."""
        cursor = await self.connection.execute(
            "SELECT * FROM amm_swaps WHERE pool_id = ? ORDER BY id DESC LIMIT ?",
            (pool_id, limit),
        )
        return [dict(r) for r in await cursor.fetchall()]

    # ─────────── Order Book ───────────

    async def place_order(
        self,
        pool_id: str,
        owner_address: str,
        order_type: str,
        side: str,
        price: Decimal,
        quantity: Decimal,
        nonce: int,
        expires_at: Optional[int] = None,
    ) -> str:
        """Place an order on the order book. Returns order_id."""
        order_id = _make_order_id(pool_id, owner_address, nonce)
        now = int(time.time())
        
        await self.connection.execute(
            """INSERT INTO orderbook_orders
               (order_id, pool_id, owner_address, order_type, side, price, quantity,
                filled_quantity, status, nonce, expires_at, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, '0', 'OPEN', ?, ?, ?, ?)""",
            (order_id, pool_id, owner_address, order_type, side,
             str(price), str(quantity), nonce, expires_at, now, now),
        )
        await self.connection.commit()
        return order_id

    async def fill_order(self, order_id: str, filled_qty: Decimal) -> None:
        """Update order with filled quantity."""
        now = int(time.time())
        cursor = await self.connection.execute(
            "SELECT quantity, filled_quantity FROM orderbook_orders WHERE order_id = ?",
            (order_id,),
        )
        row = await cursor.fetchone()
        if not row:
            raise ValueError(f"Order not found: {order_id}")
        
        total_filled = Decimal(row["filled_quantity"]) + filled_qty
        total_qty = Decimal(row["quantity"])
        status = "FILLED" if total_filled >= total_qty else "PARTIAL"
        
        await self.connection.execute(
            "UPDATE orderbook_orders SET filled_quantity = ?, status = ?, updated_at = ? WHERE order_id = ?",
            (str(total_filled), status, now, order_id),
        )
        await self.connection.commit()

    async def cancel_order(self, order_id: str) -> None:
        """Cancel an open order."""
        now = int(time.time())
        await self.connection.execute(
            "UPDATE orderbook_orders SET status = 'CANCELLED', updated_at = ? WHERE order_id = ? AND status = 'OPEN'",
            (now, order_id),
        )
        await self.connection.commit()

    async def record_trade(
        self,
        pool_id: str,
        maker_order_id: str,
        taker_order_id: str,
        price: Decimal,
        quantity: Decimal,
        maker_fee: Decimal,
        taker_fee: Decimal,
        block_height: Optional[int] = None,
        tx_hash: Optional[str] = None,
    ) -> None:
        """Record an order book trade."""
        now = int(time.time())
        await self.connection.execute(
            """INSERT INTO orderbook_trades
               (pool_id, maker_order_id, taker_order_id, price, quantity,
                maker_fee, taker_fee, block_height, tx_hash, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (pool_id, maker_order_id, taker_order_id,
             str(price), str(quantity), str(maker_fee), str(taker_fee),
             block_height, tx_hash, now),
        )
        await self.connection.commit()

    async def get_open_orders(self, pool_id: str, side: Optional[str] = None) -> List[dict]:
        """Get open orders for a pool, optionally filtered by side."""
        if side:
            cursor = await self.connection.execute(
                """SELECT * FROM orderbook_orders
                   WHERE pool_id = ? AND status = 'OPEN' AND side = ?
                   ORDER BY price ASC, created_at ASC""",
                (pool_id, side),
            )
        else:
            cursor = await self.connection.execute(
                """SELECT * FROM orderbook_orders
                   WHERE pool_id = ? AND status = 'OPEN'
                   ORDER BY side ASC, price ASC, created_at ASC""",
                (pool_id,),
            )
        return [dict(r) for r in await cursor.fetchall()]

    # ─────────── Statistics ───────────

    async def get_pool_stats(self, pool_id: str) -> dict:
        """Get aggregate stats for a pool."""
        pool = await self.get_pool(pool_id)
        if not pool:
            raise ValueError(f"Pool not found: {pool_id}")

        # Count swaps
        cursor = await self.connection.execute(
            "SELECT COUNT(*) as count FROM amm_swaps WHERE pool_id = ?", (pool_id,)
        )
        swap_count = (await cursor.fetchone())["count"]

        # Count positions
        cursor = await self.connection.execute(
            "SELECT COUNT(*) as count FROM amm_positions WHERE pool_id = ?", (pool_id,)
        )
        position_count = (await cursor.fetchone())["count"]

        # Total fees
        cursor = await self.connection.execute(
            "SELECT COALESCE(SUM(CAST(total_fee AS REAL)), 0) as total FROM amm_fee_distributions WHERE pool_id = ?",
            (pool_id,),
        )
        total_fees = (await cursor.fetchone())["total"]

        return {
            **pool,
            "swap_count": swap_count,
            "position_count": position_count,
            "total_fees_collected": str(total_fees),
        }
