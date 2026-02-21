"""
QRDX Doomsday State Store — Production Persistence

Provides a PostgreSQL-backed ``DoomsdayStateStore`` implementation that
writes to the shared chain database so doomsday state survives node
restarts and is visible to all validators.

Schema:
    doomsday_state — single-row table holding the current protocol state.
    doomsday_attestations — per-validator attestation log for auditability.

Usage:
    from qrdx.database import Database
    store = DatabaseDoomsdayStateStore(Database.instance.pool)
    await store.initialize()       # creates tables if absent
    doomsday = DoomsdayProtocol(state_store=store)
"""

import json
import logging
from decimal import Decimal
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── SQL DDL ─────────────────────────────────────────────────────────

_CREATE_STATE_TABLE = """
CREATE TABLE IF NOT EXISTS doomsday_state (
    id               INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    doomsday_active  BOOLEAN     NOT NULL DEFAULT FALSE,
    triggered_at     BIGINT      NOT NULL DEFAULT 0,
    trigger_block    BIGINT      NOT NULL DEFAULT 0,
    verification_hash TEXT       NOT NULL DEFAULT '',
    trigger_address   TEXT       NOT NULL DEFAULT '',
    bounty_recipient  TEXT       NOT NULL DEFAULT '',
    bounty_paid       BOOLEAN   NOT NULL DEFAULT FALSE,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

_CREATE_ATTESTATION_TABLE = """
CREATE TABLE IF NOT EXISTS doomsday_attestations (
    id                    SERIAL PRIMARY KEY,
    validator_address     TEXT    NOT NULL,
    canary_address        TEXT    NOT NULL,
    observed_balance      TEXT    NOT NULL,
    observed_block_height BIGINT  NOT NULL,
    observed_block_hash   TEXT    NOT NULL,
    attestation_timestamp BIGINT  NOT NULL,
    signature             TEXT    NOT NULL DEFAULT '',
    received_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (validator_address, observed_block_height)
);
"""

_UPSERT_STATE = """
INSERT INTO doomsday_state (
    id, doomsday_active, triggered_at, trigger_block,
    verification_hash, trigger_address, bounty_recipient, bounty_paid, updated_at
) VALUES (1, $1, $2, $3, $4, $5, $6, $7, NOW())
ON CONFLICT (id) DO UPDATE SET
    doomsday_active   = EXCLUDED.doomsday_active,
    triggered_at      = EXCLUDED.triggered_at,
    trigger_block     = EXCLUDED.trigger_block,
    verification_hash = EXCLUDED.verification_hash,
    trigger_address   = EXCLUDED.trigger_address,
    bounty_recipient  = EXCLUDED.bounty_recipient,
    bounty_paid       = EXCLUDED.bounty_paid,
    updated_at        = NOW();
"""

_SELECT_STATE = "SELECT * FROM doomsday_state WHERE id = 1;"

_INSERT_ATTESTATION = """
INSERT INTO doomsday_attestations (
    validator_address, canary_address, observed_balance,
    observed_block_height, observed_block_hash,
    attestation_timestamp, signature
) VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (validator_address, observed_block_height) DO NOTHING;
"""

_SELECT_ATTESTATIONS = """
SELECT * FROM doomsday_attestations
ORDER BY attestation_timestamp DESC
LIMIT $1;
"""


class DatabaseDoomsdayStateStore:
    """
    PostgreSQL-backed DoomsdayStateStore implementation.

    Uses the same ``asyncpg.Pool`` as the rest of the node for
    consistency and automatic connection management.

    This class satisfies the ``DoomsdayStateStore`` protocol defined
    in ``qrdx.bridge.shielding``.

    Note: The protocol methods (``save_doomsday_state`` / ``load_doomsday_state``)
    are **synchronous** signatures to match the Protocol.  Internally the
    class uses ``asyncio.get_event_loop().run_until_complete()`` as a
    bridge.  If you are already in an async context, prefer the explicit
    ``async_save`` / ``async_load`` methods.
    """

    def __init__(self, pool):
        """
        Args:
            pool: asyncpg connection pool (``Database.instance.pool``).
        """
        self._pool = pool
        self._initialized = False

    # ── Async lifecycle ─────────────────────────────────────────────

    async def initialize(self) -> None:
        """Create tables if they do not exist."""
        async with self._pool.acquire() as conn:
            await conn.execute(_CREATE_STATE_TABLE)
            await conn.execute(_CREATE_ATTESTATION_TABLE)
        self._initialized = True
        logger.info("DatabaseDoomsdayStateStore: tables initialized")

    # ── Protocol methods (sync façade) ──────────────────────────────

    def save_doomsday_state(self, state: Dict[str, Any]) -> bool:
        """Sync wrapper — prefer ``async_save`` in async code."""
        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Schedule as a task and return True optimistically.
                # The caller is inside an event loop (normal for QRDX node).
                loop.create_task(self.async_save(state))
                return True
            else:
                loop.run_until_complete(self.async_save(state))
                return True
        except Exception as exc:
            logger.error(f"save_doomsday_state failed: {exc}", exc_info=True)
            return False

    def load_doomsday_state(self) -> Optional[Dict[str, Any]]:
        """Sync wrapper — prefer ``async_load`` in async code."""
        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Cannot block — return None and let _load_state() be
                # called explicitly via ``await async_load()`` during init.
                return None
            return loop.run_until_complete(self.async_load())
        except Exception as exc:
            logger.error(f"load_doomsday_state failed: {exc}", exc_info=True)
            return None

    # ── Async core ──────────────────────────────────────────────────

    async def async_save(self, state: Dict[str, Any]) -> bool:
        """Persist doomsday state to PostgreSQL."""
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    _UPSERT_STATE,
                    state.get("doomsday_active", False),
                    state.get("triggered_at", 0),
                    state.get("trigger_block_height", 0),
                    state.get("verification_hash", ""),
                    state.get("trigger_address", ""),
                    state.get("bounty_recipient", ""),
                    state.get("bounty_paid", False),
                )
            return True
        except Exception as exc:
            logger.error(f"async_save failed: {exc}", exc_info=True)
            return False

    async def async_load(self) -> Optional[Dict[str, Any]]:
        """Load doomsday state from PostgreSQL."""
        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(_SELECT_STATE)
            if row is None:
                return None
            return {
                "doomsday_active": row["doomsday_active"],
                "triggered_at": row["triggered_at"],
                "trigger_block_height": row["trigger_block"],
                "verification_hash": row["verification_hash"],
                "trigger_address": row["trigger_address"],
                "bounty_recipient": row["bounty_recipient"],
                "bounty_paid": row["bounty_paid"],
            }
        except Exception as exc:
            logger.error(f"async_load failed: {exc}", exc_info=True)
            return None

    # ── Attestation audit log ───────────────────────────────────────

    async def save_attestation(
        self,
        validator_address: str,
        canary_address: str,
        observed_balance: str,
        observed_block_height: int,
        observed_block_hash: str,
        timestamp: int,
        signature: str = "",
    ) -> bool:
        """Record a doomsday attestation for audit/forensics."""
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    _INSERT_ATTESTATION,
                    validator_address,
                    canary_address,
                    observed_balance,
                    observed_block_height,
                    observed_block_hash,
                    timestamp,
                    signature,
                )
            return True
        except Exception as exc:
            logger.error(f"save_attestation failed: {exc}", exc_info=True)
            return False

    async def get_attestations(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent attestations for API / forensic queries."""
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(_SELECT_ATTESTATIONS, limit)
            return [dict(r) for r in rows]
        except Exception as exc:
            logger.error(f"get_attestations failed: {exc}", exc_info=True)
            return []
