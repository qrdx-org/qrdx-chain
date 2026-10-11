"""
Per-block undo journal for the derived database state — reorgs without a replay from genesis.

A reorg used to delete the orphaned blocks and rebuild every derived domain by replaying the
whole chain (derived_state_rebuild.rebuild_derived_state_interleaved): about 26 µs a block, so
~9 s after one day of 250 ms blocks — and at short slots reorgs are routine. Instead, SQLite
triggers record every change a block makes to the derived tables, keyed by the block's height:

    INSERT → (height, table, 'I', rowid)            undo: delete the row
    UPDATE → (height, table, 'U', rowid, old row)   undo: write the old values back
    DELETE → (height, table, 'D', rowid, old row)   undo: re-insert the old row

``rollback_to(h)`` reverses every entry above ``h`` in reverse order, inside the caller's
transaction (the LtHash triggers of qrdx/state_commitment.py follow the reversed rows, so the
state roots come back too). Entries at or below the finalized checkpoint can never be needed
and are pruned.

Every block-application path wraps its writes in ``recording(db, height)``. A write to a
journaled table outside it is recorded as UNATTRIBUTED; while one exists the journal cannot
vouch for exactness and ``rollback_to`` refuses, so the caller falls back to the full rebuild —
a write path that forgot to record costs time, never correctness. A full rebuild resets the
journal and re-records every block it replays.
"""

from __future__ import annotations

import contextlib
import marshal
from typing import Any, AsyncIterator, Dict, List, Optional

from .logger import get_logger

logger = get_logger(__name__)

# The derived tables blocks change and the rollback used to rebuild: account and contract
# state, the token ledger and its registry mirror, and the EVM balance-sync bookkeeping.
JOURNALED = (
    "account_state",
    "contract_storage",
    "token_balances",
    "token_registry",
    "evm_balance_sync_registry",
    "evm_balance_changes",
)

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS undo_log ("
    " seq INTEGER PRIMARY KEY AUTOINCREMENT,"
    " height INTEGER NOT NULL,"  # the block that made the change; -1: unattributed
    " tbl TEXT NOT NULL,"
    " op TEXT NOT NULL,"
    " rid INTEGER NOT NULL,"
    " old BLOB)",
    "CREATE INDEX IF NOT EXISTS idx_undo_log_height ON undo_log(height)",
)

UNATTRIBUTED = -1


class _ConnState:
    def __init__(self) -> None:
        self.height: Optional[int] = None
        self.suspended = 0
        self.columns: Dict[str, List[str]] = {}
        self.rowid_alias: Dict[str, bool] = {}  # an INTEGER PRIMARY KEY column is the rowid


def _state(conn: Any) -> _ConnState:
    st = getattr(conn, "qrdx_undo", None)
    if st is None:
        st = _ConnState()
        conn.qrdx_undo = st
    return st


async def install(conn: Any) -> None:
    """Create the journal and register its functions on this connection; triggers are added
    by ``ensure`` for each journaled table that exists."""
    for sql in _SCHEMA:
        await conn.execute(sql)
    st = _state(conn)

    def height() -> Optional[int]:
        if st.suspended:
            return None
        return UNATTRIBUTED if st.height is None else st.height

    await conn.create_function("qrdx_undo_h", 0, height)
    await conn.create_function("qrdx_undo_pack", -1, lambda *cols: marshal.dumps(cols))
    await ensure(conn)


async def ensure(conn: Any) -> None:
    """Install the triggers for every journaled table that now exists (some are created later,
    when the EVM initialises)."""
    st = _state(conn)
    for table in JOURNALED:
        if table in st.columns:
            continue
        cur = await conn.execute(f"PRAGMA table_info({table})")
        info = await cur.fetchall()
        cols = [r[1] for r in info]
        if not cols:
            continue
        pk = [r for r in info if r[5]]
        st.rowid_alias[table] = len(pk) == 1 and str(pk[0][2]).upper() == "INTEGER"
        old = ", ".join(f"OLD.{c}" for c in cols)
        for sql in (
            f"CREATE TEMP TRIGGER IF NOT EXISTS qrdx_undo_{table}_ins AFTER INSERT ON main.{table} "
            f"WHEN qrdx_undo_h() IS NOT NULL BEGIN INSERT INTO undo_log (height, tbl, op, rid, old) "
            f"VALUES (qrdx_undo_h(), '{table}', 'I', NEW.rowid, NULL); END",
            f"CREATE TEMP TRIGGER IF NOT EXISTS qrdx_undo_{table}_upd AFTER UPDATE ON main.{table} "
            f"WHEN qrdx_undo_h() IS NOT NULL BEGIN INSERT INTO undo_log (height, tbl, op, rid, old) "
            f"VALUES (qrdx_undo_h(), '{table}', 'U', OLD.rowid, qrdx_undo_pack({old})); END",
            f"CREATE TEMP TRIGGER IF NOT EXISTS qrdx_undo_{table}_del AFTER DELETE ON main.{table} "
            f"WHEN qrdx_undo_h() IS NOT NULL BEGIN INSERT INTO undo_log (height, tbl, op, rid, old) "
            f"VALUES (qrdx_undo_h(), '{table}', 'D', OLD.rowid, qrdx_undo_pack({old})); END",
        ):
            await conn.execute(sql)
        st.columns[table] = cols


@contextlib.asynccontextmanager
async def recording(db: Any, height: int) -> AsyncIterator[None]:
    """Attribute every journaled write inside the block to block ``height``."""
    conn = db.connection
    if getattr(conn, "qrdx_undo", None) is None:
        yield
        return
    await ensure(conn)
    st = _state(conn)
    previous, st.height = st.height, int(height)
    try:
        yield
    finally:
        st.height = previous


@contextlib.asynccontextmanager
async def suspended(db: Any) -> AsyncIterator[None]:
    """Writes that are not a block's — a clear before a full rebuild, genesis seeding — are not
    journaled (and are not unattributed: the caller resets the journal around them)."""
    conn = db.connection
    if getattr(conn, "qrdx_undo", None) is None:
        yield
        return
    st = _state(conn)
    st.suspended += 1
    try:
        yield
    finally:
        st.suspended -= 1


async def reset(db: Any) -> None:
    """Forget the journal (before a full rebuild, which re-records what it replays)."""
    if getattr(db.connection, "qrdx_undo", None) is not None:
        await db.connection.execute("DELETE FROM undo_log")


async def can_roll_back_to(db: Any, height: int) -> bool:
    """Whether ``rollback_to(height)`` would be exact: the journal is installed, holds no
    unattributed write, and covers every block above ``height``."""
    conn = db.connection
    if getattr(conn, "qrdx_undo", None) is None:
        return False
    cur = await conn.execute("SELECT 1 FROM undo_log WHERE height = ? LIMIT 1", (UNATTRIBUTED,))
    if await cur.fetchone():
        return False
    cur = await conn.execute("SELECT value FROM chain_metadata WHERE key = 'undo_floor'")
    row = await cur.fetchone()
    return row is not None and int(row[0]) <= int(height)


async def set_floor(db: Any, height: int) -> None:
    """The journal covers every block above ``height`` from now on."""
    await db.connection.execute(
        "INSERT OR REPLACE INTO chain_metadata (key, value) VALUES ('undo_floor', ?)",
        (str(int(height)),),
    )


async def rollback_to(db: Any, height: int) -> Optional[int]:
    """Reverse every journaled change made by blocks above ``height``. Returns the number of
    entries reversed, or None (nothing done) when the journal cannot vouch for exactness."""
    if not await can_roll_back_to(db, height):
        return None
    conn = db.connection
    st = _state(conn)
    await ensure(conn)
    cur = await conn.execute(
        "SELECT seq, tbl, op, rid, old FROM undo_log WHERE height > ? ORDER BY seq DESC",
        (int(height),),
    )
    rows = await cur.fetchall()
    async with suspended(db):
        for _seq, table, op, rid, old in rows:
            cols = st.columns[table]
            if op == "I":
                await conn.execute(f"DELETE FROM {table} WHERE rowid = ?", (rid,))
                continue
            values = list(marshal.loads(old))
            if op == "U":
                assign = ", ".join(f"{c} = ?" for c in cols)
                await conn.execute(f"UPDATE {table} SET {assign} WHERE rowid = ?", (*values, rid))
            elif st.rowid_alias[table]:  # the key column carries the rowid
                marks = ", ".join("?" * len(cols))
                await conn.execute(
                    f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({marks})", values
                )
            else:
                names = ", ".join(["rowid", *cols])
                marks = ", ".join("?" * (len(cols) + 1))
                await conn.execute(
                    f"INSERT INTO {table} ({names}) VALUES ({marks})", (rid, *values)
                )
    await conn.execute("DELETE FROM undo_log WHERE height > ?", (int(height),))
    return len(rows)


async def prune(db: Any, finalized_height: int) -> None:
    """Drop entries no reorg can reach (the finalized checkpoint is never rolled back)."""
    conn = db.connection
    if getattr(conn, "qrdx_undo", None) is None:
        return
    await conn.execute(
        "DELETE FROM undo_log WHERE height >= 0 AND height <= ?", (int(finalized_height),)
    )
    cur = await conn.execute("SELECT value FROM chain_metadata WHERE key = 'undo_floor'")
    row = await cur.fetchone()
    if row is not None and int(row[0]) < int(finalized_height):
        await set_floor(db, finalized_height)
