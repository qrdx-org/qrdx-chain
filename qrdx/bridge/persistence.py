"""
Bridge Event Persistence — SQLite Backend

Stores bridge deposit/withdrawal events and fraud proof windows.
No stubs — real SQL operations.
"""

import aiosqlite
from decimal import Decimal
from typing import List, Optional
import logging
import time

logger = logging.getLogger(__name__)

BRIDGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS bridge_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    source_chain TEXT NOT NULL,
    dest_chain TEXT NOT NULL,
    from_address TEXT NOT NULL,
    to_address TEXT NOT NULL,
    token_symbol TEXT NOT NULL,
    amount TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    confirmations INTEGER NOT NULL DEFAULT 0,
    required_confirmations INTEGER NOT NULL,
    fraud_proof_deadline INTEGER,
    source_tx_hash TEXT,
    dest_tx_hash TEXT,
    attestation_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS bridge_attestations (
    event_id TEXT NOT NULL,
    validator_address TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (event_id, validator_address),
    FOREIGN KEY (event_id) REFERENCES bridge_events(event_id)
);

CREATE TABLE IF NOT EXISTS doomsday_canary (
    id INTEGER PRIMARY KEY DEFAULT 1,
    canary_address TEXT NOT NULL,
    canary_balance TEXT NOT NULL,
    bounty_amount TEXT NOT NULL,
    is_triggered INTEGER NOT NULL DEFAULT 0,
    last_checked INTEGER NOT NULL,
    triggered_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_bridge_events_type ON bridge_events(event_type);
CREATE INDEX IF NOT EXISTS idx_bridge_events_status ON bridge_events(status);
CREATE INDEX IF NOT EXISTS idx_bridge_events_source ON bridge_events(source_chain);
CREATE INDEX IF NOT EXISTS idx_bridge_attestations_event ON bridge_attestations(event_id);
"""


class BridgePersistence:
    """SQLite persistence for bridge state."""

    def __init__(self, connection: aiosqlite.Connection):
        self.connection = connection

    async def initialize(self) -> None:
        """Create bridge tables."""
        await self.connection.executescript(BRIDGE_SCHEMA)
        await self.connection.commit()
        logger.info("Bridge persistence schema initialized")

    async def record_deposit(
        self,
        event_id: str,
        source_chain: str,
        from_address: str,
        to_address: str,
        token_symbol: str,
        amount: Decimal,
        required_confirmations: int,
        source_tx_hash: Optional[str] = None,
    ) -> None:
        """Record an incoming bridge deposit."""
        now = int(time.time())
        await self.connection.execute(
            """INSERT INTO bridge_events
               (event_id, event_type, source_chain, dest_chain, from_address, to_address,
                token_symbol, amount, status, confirmations, required_confirmations,
                source_tx_hash, attestation_count, created_at, updated_at)
               VALUES (?, 'DEPOSIT', ?, 'QRDX', ?, ?, ?, ?, 'PENDING', 0, ?, ?, 0, ?, ?)""",
            (event_id, source_chain, from_address, to_address,
             token_symbol, str(amount), required_confirmations, source_tx_hash, now, now),
        )
        await self.connection.commit()

    async def record_withdrawal(
        self,
        event_id: str,
        dest_chain: str,
        from_address: str,
        to_address: str,
        token_symbol: str,
        amount: Decimal,
        fraud_proof_deadline: int,
    ) -> None:
        """Record an outgoing bridge withdrawal with fraud proof window."""
        now = int(time.time())
        await self.connection.execute(
            """INSERT INTO bridge_events
               (event_id, event_type, source_chain, dest_chain, from_address, to_address,
                token_symbol, amount, status, confirmations, required_confirmations,
                fraud_proof_deadline, attestation_count, created_at, updated_at)
               VALUES (?, 'WITHDRAWAL', 'QRDX', ?, ?, ?, ?, ?, 'PENDING', 0, 0, ?, 0, ?, ?)""",
            (event_id, dest_chain, from_address, to_address,
             token_symbol, str(amount), fraud_proof_deadline, now, now),
        )
        await self.connection.commit()

    async def add_attestation(
        self, event_id: str, validator_address: str, signature: str
    ) -> int:
        """Add a validator attestation for a bridge event. Returns new count."""
        now = int(time.time())
        await self.connection.execute(
            """INSERT OR IGNORE INTO bridge_attestations
               (event_id, validator_address, signature, created_at)
               VALUES (?, ?, ?, ?)""",
            (event_id, validator_address, signature, now),
        )
        await self.connection.execute(
            """UPDATE bridge_events SET attestation_count = (
                SELECT COUNT(*) FROM bridge_attestations WHERE event_id = ?
               ), updated_at = ? WHERE event_id = ?""",
            (event_id, now, event_id),
        )
        await self.connection.commit()
        event = await self.get_event(event_id)
        return event["attestation_count"] if event else 0

    async def update_confirmations(self, event_id: str, confirmations: int) -> None:
        """Update source chain confirmation count."""
        now = int(time.time())
        await self.connection.execute(
            "UPDATE bridge_events SET confirmations = ?, updated_at = ? WHERE event_id = ?",
            (confirmations, now, event_id),
        )
        # Auto-finalize if confirmations meet requirement
        await self.connection.execute(
            """UPDATE bridge_events SET status = 'CONFIRMED', updated_at = ?
               WHERE event_id = ? AND confirmations >= required_confirmations AND status = 'PENDING'""",
            (now, event_id),
        )
        await self.connection.commit()

    async def finalize_event(self, event_id: str, dest_tx_hash: Optional[str] = None) -> None:
        """Mark a bridge event as finalized."""
        now = int(time.time())
        await self.connection.execute(
            "UPDATE bridge_events SET status = 'FINALIZED', dest_tx_hash = ?, updated_at = ? WHERE event_id = ?",
            (dest_tx_hash, now, event_id),
        )
        await self.connection.commit()

    async def get_event(self, event_id: str) -> Optional[dict]:
        """Get bridge event details."""
        cursor = await self.connection.execute(
            "SELECT * FROM bridge_events WHERE event_id = ?", (event_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def list_events(self, status: Optional[str] = None, limit: int = 100) -> List[dict]:
        """List bridge events."""
        if status:
            cursor = await self.connection.execute(
                "SELECT * FROM bridge_events WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status, limit),
            )
        else:
            cursor = await self.connection.execute(
                "SELECT * FROM bridge_events ORDER BY created_at DESC LIMIT ?", (limit,)
            )
        return [dict(r) for r in await cursor.fetchall()]

    # ─────────── Doomsday Canary ───────────

    async def initialize_canary(self, address: str, balance: Decimal, bounty: Decimal) -> None:
        """Initialize the doomsday canary monitoring."""
        now = int(time.time())
        await self.connection.execute(
            """INSERT OR REPLACE INTO doomsday_canary
               (id, canary_address, canary_balance, bounty_amount, is_triggered, last_checked)
               VALUES (1, ?, ?, ?, 0, ?)""",
            (address, str(balance), str(bounty), now),
        )
        await self.connection.commit()

    async def check_canary(self) -> Optional[dict]:
        """Get current canary state."""
        cursor = await self.connection.execute("SELECT * FROM doomsday_canary WHERE id = 1")
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def trigger_canary(self) -> None:
        """Trigger the doomsday protocol."""
        now = int(time.time())
        await self.connection.execute(
            "UPDATE doomsday_canary SET is_triggered = 1, triggered_at = ?, last_checked = ? WHERE id = 1",
            (now, now),
        )
        await self.connection.commit()
        logger.critical("DOOMSDAY CANARY TRIGGERED!")
