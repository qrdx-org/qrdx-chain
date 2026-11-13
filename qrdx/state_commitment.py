"""
Incremental commitments to the database-backed state domains (chain-spec feature
``incremental_state_root``; docs/KNOWN_ISSUES.md "State roots were recomputed from all state
every block").

The account, token and UTXO roots used to hash every row of their tables, in order, on every
block. Each domain now keeps an LtHash accumulator (qrdx/crypto/lthash.py), and the store
(qrdx/store.py) folds every row change into it as it happens:

    a new row       → + entry(new row)
    a changed row   → − entry(old row) + entry(new row)
    a deleted row   → − entry(old row)

The store does it natively for every write, in the writes' own transaction, so a rolled-back
block takes its accumulator changes with it, and no write path can forget to update the
commitment. A root is then one hash of a 4 KB accumulator, whatever the size of the state.

Domains:

* ``account``: every ``account_state`` row (address, balance, nonce, code hash, storage root)
  and every ``contract_storage`` row (contract, key, value).
* ``token``: every ``token_balances`` row with a non-zero balance. A zero balance contributes
  nothing, as in the sequential root, so a holder that nets to zero leaves the root unchanged.
* ``utxo``: every ``unspent_outputs`` row.

The encoders below are the reference: the store computes the same entries natively and hands
them any row it cannot read exactly. ``full_accumulator`` is the same computation over every row,
and the tests' reference.
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


async def full_accumulator(db: Any, domain: str) -> bytes:
    """The domain's accumulator computed from every row, in Python — what the store keeps."""
    acc = lthash.Accumulator()
    for d, encode, table, cols in TABLES.values():
        if d != domain:
            continue
        t = db.store[table]
        at = [t.spec.columns.index(c) for c in cols]
        for row in t.scan():
            v = encode(tuple(row[i] for i in at))
            if v is not None:
                acc.add(v)
    return acc.digest()


async def stored_accumulator(db: Any, domain: str) -> bytes:
    return db.store.acc(domain)


async def reconcile(db: Any) -> Dict[str, bool]:
    """Recompute every domain's accumulator from its rows (natively) and store it where the
    stored one differs. Returns which domains were repaired. O(state)."""
    started = time.monotonic()
    repaired: Dict[str, bool] = {}
    for domain in DOMAINS:
        full = db.store.native.full_acc(domain)
        if db.store.acc(domain) != full:
            logger.warning("state commitment %r disagreed with its rows; recomputed", domain)
            db.store.set_acc(domain, full)
            repaired[domain] = True
    logger.info("state commitments reconciled in %.2fs", time.monotonic() - started)
    return repaired


def reset(db: Any, domain: str) -> None:
    """Empty every table of ``domain`` without folding out each row: its accumulator becomes
    the empty set's. (The rows are still marked for the proof tree and journaled.)"""
    for d, _enc, table, _cols in TABLES.values():
        if d == domain:
            db.store[table].clear()
    db.store.set_acc(domain, lthash.ZERO)


async def root(db: Any, domain: str) -> str:
    """The domain's incremental root: one hash of its accumulator."""
    return lthash.root(domain, db.store.acc(domain), ROOT_LENGTH[domain])


def active(height: int) -> bool:
    """Is the incremental root the rule for the block at ``height``?"""
    from . import chain_spec

    return chain_spec.is_active(FEATURE, int(height))
