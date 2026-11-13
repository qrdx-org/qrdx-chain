"""
Phase E (d) inc2 — token ledger DB layer.

Pins the consensus token-balance primitives on DatabaseSQLite: delta application
(credit/debit, clamp-at-0, no commit), the deterministic BLAKE3-512
token_balances root (canonical order, zero rows skipped, empty == zero root), and
the reorg-rebuild clear. These mirror the account_state equivalents.
"""

import os
import tempfile
from decimal import Decimal

import pytest

from qrdx.database_sqlite import DatabaseSQLite

from pq_addrs import pq

ZERO_ROOT = "0" * 128


@pytest.fixture
async def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database = await DatabaseSQLite.create(path)
    yield database
    await database.connection.close()
    for p in (path, path + "-wal", path + "-shm"):
        try:
            os.remove(p)
        except OSError:
            pass


async def test_empty_ledger_is_zero_root(db):
    assert await db.get_token_balances_root() == ZERO_ROOT


async def test_credit_then_balance_and_root_change(db):
    assert await db.apply_token_balance_delta("0xTOK", pq("alice"), Decimal("1000")) is True
    assert await db.get_token_balance("0xTOK", pq("alice")) == Decimal("1000")
    root = await db.get_token_balances_root()
    assert root != ZERO_ROOT


async def test_an_overdraft_is_applied_in_full_and_flagged(db, caplog):
    """It used to clamp at 0 while the paired credit landed in full — minting the difference.
    The exchange refuses operations whose holder cannot cover them, so this is a bug if it
    ever happens: applied in full (supply stays conserved) and logged as critical."""
    await db.apply_token_balance_delta("0xTOK", pq("bob"), Decimal("100"))
    await db.apply_token_balance_delta("0xTOK", pq("bob"), Decimal("-250"))  # over-debit
    assert await db.get_token_balance("0xTOK", pq("bob")) == Decimal("-150")
    assert "TOKEN-OVERDRAFT" in caplog.text


async def test_zero_balance_row_excluded_from_root(db):
    # A holder funded then fully spent nets to 0 → must not affect the root.
    await db.apply_token_balance_delta("0xTOK", pq("carol"), Decimal("500"))
    await db.apply_token_balance_delta("0xTOK", pq("carol"), Decimal("-500"))
    assert await db.get_token_balance("0xTOK", pq("carol")) == Decimal("0")
    assert await db.get_token_balances_root() == ZERO_ROOT


async def test_root_is_order_independent_of_insertion(db):
    # Insert in one order...
    await db.apply_token_balance_delta("0xTOKb", pq("2"), Decimal("7"))
    await db.apply_token_balance_delta("0xTOKa", pq("1"), Decimal("3"))
    root1 = await db.get_token_balances_root()
    await db.clear_token_balances()
    # ...and the reverse order — canonical ORDER BY makes the root identical.
    await db.apply_token_balance_delta("0xTOKa", pq("1"), Decimal("3"))
    await db.apply_token_balance_delta("0xTOKb", pq("2"), Decimal("7"))
    root2 = await db.get_token_balances_root()
    assert root1 == root2 != ZERO_ROOT


async def test_clear_token_balances_resets_root(db):
    await db.apply_token_balance_delta("0xTOK", pq("alice"), Decimal("1000"))
    assert await db.get_token_balances_root() != ZERO_ROOT
    await db.clear_token_balances()
    assert await db.get_token_balances_root() == ZERO_ROOT


async def test_zero_delta_is_noop(db):
    assert await db.apply_token_balance_delta("0xTOK", pq("x"), Decimal("0")) is False
    assert await db.get_token_balances_root() == ZERO_ROOT
