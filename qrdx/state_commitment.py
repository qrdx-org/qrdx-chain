"""
Incremental commitments to the database-backed state domains (chain-spec feature
``incremental_state_root``; docs/KNOWN_ISSUES.md "State roots were recomputed from all state
every block").

The account, token and UTXO roots used to hash every row of their tables, in order, on every
block. Each domain now keeps an LtHash accumulator (qrdx/crypto/lthash.py) in
``state_commitment``, and SQLite triggers fold every row change into it as it happens:

    INSERT  → + entry(new row)
    UPDATE  → − entry(old row) + entry(new row)   (only when a committed column changed)
    DELETE  → − entry(old row)

The triggers run in the writing statement's transaction, so a rolled-back block takes its
accumulator changes with it, and no write path can forget to update the commitment. A root is
then one hash of a 4 KB accumulator, whatever the size of the state.

Domains:

* ``account``: every ``account_state`` row (address, balance, nonce, code hash, storage root)
  and every ``contract_storage`` row (contract, key, value).
* ``token``: every ``token_balances`` row with a non-zero balance. A zero balance contributes
  nothing, as in the sequential root, so a holder that nets to zero leaves the root unchanged.
* ``utxo``: every ``unspent_outputs`` row.

The triggers are TEMP triggers on the node's own connection, calling a Python function, so any
other connection (the sqlite3 shell, a tool) writes without them. ``reconcile`` recomputes every
accumulator from the rows at startup and repairs any that disagree; ``full_accumulator`` is the
same computation, and the tests' reference.
"""

from __future__ import annotations

import logging
import time
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Dict, Iterable, Optional, Sequence, Tuple

from .crypto import lthash

logger = logging.getLogger(__name__)

FEATURE = "incremental_state_root"

DOMAINS = ("account", "token", "utxo")

# Root width per domain, in bytes: as the sequential roots they replace (BLAKE3-512 for the
# account and token domains, a 256-bit hash for the legacy UTXO set).
ROOT_LENGTH = {"account": 64, "token": 64, "utxo": 32}

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS state_commitment ("
    " domain TEXT PRIMARY KEY,"
    " acc BLOB NOT NULL)"
)


def _s(value: Any) -> str:
    return "" if value is None else str(value)


def _fields(values: Iterable[Any]) -> bytes:
    return "\x00".join(_s(v) for v in values).encode()


def _account(row: Sequence[Any]) -> Optional[int]:
    return lthash.entry(b"qrdx/account/v1", _fields(row[:5]))


def _storage(row: Sequence[Any]) -> Optional[int]:
    return lthash.entry(b"qrdx/storage/v1", _fields(row[:3]))


def _token(row: Sequence[Any]) -> Optional[int]:
    try:
        if Decimal(_s(row[2])) == 0:
            return None
    except (InvalidOperation, ValueError):
        return None  # the sequential root skipped unreadable balances too
    return lthash.entry(b"qrdx/token/v1", _fields(row[:3]))


def _utxo(row: Sequence[Any]) -> Optional[int]:
    return lthash.entry(b"qrdx/utxo/v1", _fields(row[:4]))


# kind → (domain, encoder, table, committed columns)
TABLES: Dict[str, Tuple[str, Callable[[Sequence[Any]], Optional[int]], str, Tuple[str, ...]]] = {
    "account": (
        "account",
        _account,
        "account_state",
        ("address", "balance", "nonce", "code_hash", "storage_root"),
    ),
    "storage": (
        "account",
        _storage,
        "contract_storage",
        ("contract_address", "storage_key", "storage_value"),
    ),
    "token": ("token", _token, "token_balances", ("token_address", "holder_address", "balance")),
    "utxo": ("utxo", _utxo, "unspent_outputs", ("tx_hash", "output_index", "address", "amount")),
}

_WIDTH = 5  # the widest committed row (account_state)


def _udf_apply(acc: bytes, kind: str, has_old: int, has_new: int, *cols: Any) -> bytes:
    encode = TABLES[kind][1]
    old = encode(cols[:_WIDTH]) if has_old else None
    new = encode(cols[_WIDTH:]) if has_new else None
    if old == new:
        return acc
    return lthash.mix(acc, old, new)


def _trigger_sql(kind: str) -> Sequence[str]:
    domain, _enc, table, cols = TABLES[kind]
    pad = ["NULL"] * (_WIDTH - len(cols))

    def row(prefix: Optional[str]) -> str:
        if prefix is None:
            return ", ".join(["NULL"] * _WIDTH)
        return ", ".join([f"{prefix}.{c}" for c in cols] + pad)

    def body(has_old: int, has_new: int, old: Optional[str], new: Optional[str]) -> str:
        return (
            f"UPDATE state_commitment SET acc = qrdx_lt_apply(acc, '{kind}', {has_old}, "
            f"{has_new}, {row(old)}, {row(new)}) WHERE domain = '{domain}';"
        )

    changed = " OR ".join(f"OLD.{c} IS NOT NEW.{c}" for c in cols)
    return (
        f"CREATE TEMP TRIGGER IF NOT EXISTS qrdx_lt_{kind}_ins AFTER INSERT ON main.{table} "
        f"WHEN qrdx_lt_on('{domain}') BEGIN {body(0, 1, None, 'NEW')} END",
        f"CREATE TEMP TRIGGER IF NOT EXISTS qrdx_lt_{kind}_upd AFTER UPDATE ON main.{table} "
        f"WHEN qrdx_lt_on('{domain}') AND ({changed}) BEGIN {body(1, 1, 'OLD', 'NEW')} END",
        f"CREATE TEMP TRIGGER IF NOT EXISTS qrdx_lt_{kind}_del AFTER DELETE ON main.{table} "
        f"WHEN qrdx_lt_on('{domain}') BEGIN {body(1, 0, 'OLD', None)} END",
    )


async def install(conn: Any) -> None:
    """Create the accumulator table, register the functions and install the triggers on this
    connection, then make every accumulator agree with the rows (``reconcile``)."""
    await conn.execute(SCHEMA)
    # Domains whose triggers are off on this connection (inside ``suspended``).
    off: set = set()
    conn.qrdx_lt_off = off
    await conn.create_function("qrdx_lt_on", 1, lambda domain: 0 if domain in off else 1)
    await conn.create_function("qrdx_lt_apply", 4 + 2 * _WIDTH, _udf_apply, deterministic=True)
    # INSERT OR REPLACE removes the conflicting row without firing its DELETE trigger unless
    # recursive triggers are on — and the accumulator would keep the replaced row.
    await conn.execute("PRAGMA recursive_triggers = ON")
    for kind in TABLES:
        for stmt in _trigger_sql(kind):
            await conn.execute(stmt)
    await reconcile(conn)


async def full_accumulator(conn: Any, domain: str) -> bytes:
    """The domain's accumulator computed from every row — what the triggers maintain."""
    acc = lthash.Accumulator()
    for d, encode, table, cols in TABLES.values():
        if d != domain:
            continue
        cursor = await conn.execute(f"SELECT {', '.join(cols)} FROM {table}")
        while True:
            rows = await cursor.fetchmany(4096)
            if not rows:
                break
            for r in rows:
                v = encode(tuple(r))
                if v is not None:
                    acc.add(v)
    return acc.digest()


async def stored_accumulator(conn: Any, domain: str) -> bytes:
    cursor = await conn.execute("SELECT acc FROM state_commitment WHERE domain = ?", (domain,))
    row = await cursor.fetchone()
    return bytes(row[0]) if row is not None else lthash.ZERO


async def reconcile(conn: Any) -> Dict[str, bool]:
    """Recompute every domain's accumulator from its rows and store it where the stored one
    differs (a database from before the triggers existed, or rows written by a connection
    without them). Returns which domains were repaired. O(state): run at startup only."""
    started = time.monotonic()
    repaired: Dict[str, bool] = {}
    for domain in DOMAINS:
        cursor = await conn.execute("SELECT acc FROM state_commitment WHERE domain = ?", (domain,))
        row = await cursor.fetchone()
        full = await full_accumulator(conn, domain)
        if row is None or bytes(row[0]) != full:
            if row is not None:
                logger.warning(
                    "state commitment %r disagreed with its rows (written without the "
                    "triggers?); recomputed",
                    domain,
                )
            await conn.execute(
                "INSERT OR REPLACE INTO state_commitment (domain, acc) VALUES (?, ?)",
                (domain, full),
            )
            repaired[domain] = row is not None
    await conn.commit()
    logger.info("state commitments reconciled in %.2fs", time.monotonic() - started)
    return repaired


class suspended:
    """Empty a domain's tables without folding in each deleted row: inside the block the
    domain's triggers are off on this connection, and on leaving it the domain's accumulator is
    set to empty. Use only around statements that delete every row of every table of the
    domain."""

    def __init__(self, conn: Any, domain: str) -> None:
        self._conn = conn
        self._domain = domain

    async def __aenter__(self) -> "suspended":
        off = getattr(self._conn, "qrdx_lt_off", None)
        if off is not None:
            off.add(self._domain)
        return self

    async def __aexit__(self, *exc: Any) -> None:
        off = getattr(self._conn, "qrdx_lt_off", None)
        if off is not None:
            off.discard(self._domain)
        if exc[0] is None:
            await self._conn.execute(
                "UPDATE state_commitment SET acc = ? WHERE domain = ?",
                (lthash.ZERO, self._domain),
            )


async def root(conn: Any, domain: str) -> str:
    """The domain's incremental root: one hash of its accumulator."""
    return lthash.root(domain, await stored_accumulator(conn, domain), ROOT_LENGTH[domain])


def active(height: int) -> bool:
    """Is the incremental root the rule for the block at ``height``?"""
    from . import chain_spec

    return chain_spec.is_active(FEATURE, int(height))
