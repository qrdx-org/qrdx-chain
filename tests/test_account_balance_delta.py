"""Phase E (b-2): apply_account_balance_delta — QRDX delta -> account_state wei.

account_state is keyed by canonical ACCOUNT ID, so these tests seed and read
rows through ``to_account_id`` while passing the caller-facing 0xPQ display
address to the delta API — which is exactly the unification being pinned: a PQ
holder's debit lands on the 20-byte row the EVM shares.
"""
import os, tempfile
from decimal import Decimal
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.crypto.account_id import to_account_id

from pq_addrs import pq

async def _db():
    return await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))

async def _bal_wei(db, addr):
    r = db.store["account_state"].get(to_account_id(addr))
    return int(r.balance) if r and r.balance is not None else None

async def test_debit_and_credit_existing_account():
    db = await _db(); path = db.db_path
    try:
        addr = pq("abx16")
        db.store["account_state"].put(address=to_account_id(addr), balance=str(100 * 10**18))
        await db.connection.commit()
        await db.apply_account_balance_delta(addr, Decimal("-30"))  # debit 30 QRDX
        assert await _bal_wei(db, addr) == 70 * 10**18
        await db.apply_account_balance_delta(addr, Decimal("5"))    # credit 5
        assert await _bal_wei(db, addr) == 75 * 10**18
    finally:
        await db.close(); os.remove(path)

async def test_debit_clamps_at_zero():
    db = await _db(); path = db.db_path
    try:
        addr = pq("cdx16")
        db.store["account_state"].put(address=to_account_id(addr), balance=str(10 * 10**18))
        await db.connection.commit()
        await db.apply_account_balance_delta(addr, Decimal("-50"))  # over-debit
        assert await _bal_wei(db, addr) == 0
    finally:
        await db.close(); os.remove(path)

async def test_credit_creates_account_debit_noop_on_missing():
    db = await _db(); path = db.db_path
    try:
        a_credit = pq("eex16")
        assert await db.apply_account_balance_delta(a_credit, Decimal("7")) is True
        assert await _bal_wei(db, a_credit) == 7 * 10**18
        a_missing = pq("ffx16")
        assert await db.apply_account_balance_delta(a_missing, Decimal("-3")) is False
        assert await _bal_wei(db, a_missing) is None
    finally:
        await db.close(); os.remove(path)
