"""
Phase E — cross-node determinism of the enforced collateral/flush path.

Two independent nodes (separate DB + ExchangeStateManager) that fund the same
trader and process the SAME open-position must end with IDENTICAL account_state
debits and IDENTICAL exchange roots — the consensus property required before
flipping ENFORCE_EXCHANGE_COLLATERAL. Also pins enforce-mode rejection of an
under-collateralized open (no debit, no position) and that it's deterministic too.
"""
import os, tempfile
from decimal import Decimal
from types import SimpleNamespace

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.exchange.state_manager import ExchangeStateManager
from qrdx.exchange.block_processor import preload_sender_balances, flush_exchange_balance_deltas


async def _node(trader, fund_qrdx):
    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    if fund_qrdx is not None:
        await db.connection.execute(
            "INSERT INTO account_state (address, balance, nonce, created_at, updated_at, is_contract) "
            "VALUES (?, ?, 0, 0, 0, 0)", (trader, str(int(Decimal(fund_qrdx) * 10**18))))
        await db.connection.commit()
    mgr = ExchangeStateManager()
    mgr.perp_engine.create_market("BTC")
    mgr.enforce_collateral = True
    return db, mgr


def _open_tx(trader):
    return SimpleNamespace(sender=trader, params={
        "market_id": "BTC-QRDX-PERP", "side": "long",
        "size": "1", "leverage": "10", "price": "30000"})


async def _run_block(db, mgr, tx):
    mgr.begin_block(1, 0.0)
    await preload_sender_balances(db, [tx], mgr)
    res = mgr._op_open_position(tx)
    mgr.commit_block()
    await flush_exchange_balance_deltas(db, mgr, enforce=True)
    return res


async def _acct_wei(db, addr):
    cur = await db.connection.execute(
        "SELECT balance FROM account_state WHERE LOWER(address)=LOWER(?)", (addr,))
    r = await cur.fetchone()
    return int(r[0]) if r and r[0] is not None else None


async def test_two_nodes_agree_on_debit_and_root():
    trader = "0xPQ" + "ab" * 16
    db1, mgr1 = await _node(trader, "1000000")
    db2, mgr2 = await _node(trader, "1000000")
    try:
        r1 = await _run_block(db1, mgr1, _open_tx(trader))
        r2 = await _run_block(db2, mgr2, _open_tx(trader))
        assert r1.success and r2.success
        # Identical account_state debit (margin moved) on both nodes.
        b1, b2 = await _acct_wei(db1, trader), await _acct_wei(db2, trader)
        assert b1 == b2, f"account_state diverged: {b1} != {b2}"
        assert b1 < 1000000 * 10**18, "margin should have been debited"
        # Identical exchange root.
        assert mgr1.compute_state_root() == mgr2.compute_state_root()
    finally:
        for db in (db1, db2): await db.close(); os.remove(db.db_path)


async def test_enforce_rejects_uncollateralized_deterministically():
    trader = "0xPQ" + "cd" * 16
    db1, mgr1 = await _node(trader, "100")   # margin ~3000 > 100
    db2, mgr2 = await _node(trader, "100")
    try:
        r1 = await _run_block(db1, mgr1, _open_tx(trader))
        r2 = await _run_block(db2, mgr2, _open_tx(trader))
        assert not r1.success and not r2.success
        # No debit, balance unchanged + identical on both.
        assert await _acct_wei(db1, trader) == await _acct_wei(db2, trader) == 100 * 10**18
        assert mgr1.compute_state_root() == mgr2.compute_state_root()
    finally:
        for db in (db1, db2): await db.close(); os.remove(db.db_path)
