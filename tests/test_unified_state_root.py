"""
Phase D4 (primitive) — unified block state root + account-state root.

The unified state root commits to all state domains (UTXO, account/EVM, exchange,
token) under one BLAKE3-512 hash (Whitepaper §3.6). These tests pin the
primitives: deterministic account-state root, and a unified root that is
sensitive to each domain. (Consensus *enforcement* of the unified root is gated
on the account/EVM domain receiving deterministic import replay — see the
readiness spec.)
"""

import os
import tempfile

import blake3

from qrdx.crypto.hashing import unified_state_root, state_root_hex, TOKEN_ZERO_ROOT
from qrdx.database_sqlite import DatabaseSQLite


def test_unified_root_is_blake3_512_and_order_fixed():
    r = unified_state_root("aa", "bb", "cc", "dd")
    assert len(r) == 128  # BLAKE3-512
    assert r == state_root_hex("aa|bb|cc|dd".encode())
    # Domain order matters (utxo, account, exchange, token are positional).
    assert unified_state_root("aa", "bb", "cc", "dd") != unified_state_root("bb", "aa", "cc", "dd")


def test_token_root_defaults_to_zero_domain():
    # A 3-arg call binds the token domain at its empty (all-zero) root.
    assert unified_state_root("u", "a", "e") == unified_state_root("u", "a", "e", TOKEN_ZERO_ROOT)


def test_unified_root_sensitive_to_each_domain():
    base = unified_state_root("u", "a", "e", "t")
    assert unified_state_root("U", "a", "e", "t") != base, "must depend on UTXO root"
    assert unified_state_root("u", "A", "e", "t") != base, "must depend on account root"
    assert unified_state_root("u", "a", "E", "t") != base, "must depend on exchange root"
    assert unified_state_root("u", "a", "e", "T") != base, "must depend on token root"


def test_unified_root_deterministic():
    assert unified_state_root("u", "a", "e", "t") == unified_state_root("u", "a", "e", "t")


async def _db():
    path = tempfile.mktemp(suffix=".db")
    return await DatabaseSQLite.create(db_path=path), path


async def test_account_state_root_empty_is_zero():
    db, path = await _db()
    try:
        root = await db.get_account_state_root()
        assert root == "0" * 128
    finally:
        await db.close()
        os.remove(path)


async def test_account_state_root_changes_with_state_and_is_deterministic():
    db, path = await _db()
    try:
        now = 1_700_000_000
        await db.connection.execute(
            "INSERT INTO account_state (address, balance, nonce, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            ("0xPQ" + "11" * 32, "1000", 0, now, now),
        )
        await db.connection.commit()
        r1 = await db.get_account_state_root()
        assert r1 != "0" * 128 and len(r1) == 128
        # Deterministic for identical state.
        assert r1 == await db.get_account_state_root()

        # Mutating a balance changes the root.
        await db.connection.execute(
            "UPDATE account_state SET balance = ? WHERE address = ?",
            ("2000", "0xPQ" + "11" * 32),
        )
        await db.connection.commit()
        assert await db.get_account_state_root() != r1
    finally:
        await db.close()
        os.remove(path)


async def test_account_state_root_canonical_ordering():
    """Root is independent of insertion order (canonical by address)."""
    now = 1_700_000_000
    roots = []
    for order in ([("0xPQaa", "5"), ("0xPQbb", "7")], [("0xPQbb", "7"), ("0xPQaa", "5")]):
        db, path = await _db()
        try:
            for addr, bal in order:
                await db.connection.execute(
                    "INSERT INTO account_state (address, balance, nonce, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?)", (addr, bal, 0, now, now),
                )
            await db.connection.commit()
            roots.append(await db.get_account_state_root())
        finally:
            await db.close()
            os.remove(path)
    assert roots[0] == roots[1], "account root must be insertion-order independent"
