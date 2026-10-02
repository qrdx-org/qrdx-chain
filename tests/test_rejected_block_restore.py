"""
A rejected block must leave no trace in derived state.

Every import path applies a block's sections BEFORE its final checks, and they do not all
roll back on their own: `apply_block_evm_section` commits on success (committing the
exchange deltas flushed before it), the in-memory ExchangeStateManager is already mutated,
and withdrawal credits sit in the open transaction for the next commit. So a block rejected
at the EVM root check or at E-D4 used to leave its effects behind — the node held state for
a block its chain does not contain, and built on it.

The fix restores by rebuilding derived state from the (intact) canonical chain — the same
rebuild the reorg path uses. Also covered: that rebuild now resets the mempool's nonce
expectations, whose absence silently lost orphaned EVM transactions on every reorg.
"""
import inspect
import os
import tempfile
from decimal import Decimal

import pytest

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.node import main as node_main

from pq_addrs import pq


# ── Every rejection after state mutation restores ──────────────────────────

def _main_src():
    return inspect.getsource(node_main)


def test_sync_path_restores_on_evm_and_e_d4_rejection():
    src = inspect.getsource(node_main.process_and_create_block)
    evm = src.index('Rejecting PoS block {block_height}: {verr_evm}')
    ed4 = src.index('Rejecting block {block_height}: E-D4')
    assert "_restore_after_rejected_block(" in src[evm:evm + 300]
    assert "_restore_after_rejected_block(" in src[ed4:ed4 + 300]


def test_rest_path_restores_on_evm_and_e_d4_rejection():
    src = _main_src()
    evm = src.index("'invalid_evm_section', severity=6")
    root = src.index("'invalid_state_root', severity=8")
    assert "_restore_after_rejected_block(" in src[evm:evm + 300]
    assert "_restore_after_rejected_block(" in src[root:root + 300]


def test_p2p_path_restores_on_evm_and_e_d4_rejection():
    from qrdx.rpc.modules import p2p
    src = inspect.getsource(p2p)
    evm = src.index("return {'ok': False, 'error': f'Invalid EVM section: {verr_evm}'}")
    root = src.index("return {'ok': False, 'error': f'Invalid state root: {root_err}'}")
    assert "_restore_after_rejection(" in src[evm - 200:evm]
    assert "_restore_after_rejection(" in src[root - 200:root]


def test_the_p2p_hook_is_injected():
    src = _main_src()
    call = src[src.index("set_node_context("):]
    call = call[:call.index("\n    )\n")]   # the call's closing paren, not one in a comment
    assert "restore_after_rejected_block=_restore_after_rejected_block" in call


def test_restore_uses_the_full_derived_state_rebuild():
    src = inspect.getsource(node_main._restore_after_rejected_block)
    assert "_rebuild_derived_state_after_rollback()" in src
    assert "rollback()" in src


# ── Behaviour ─────────────────────────────────────────────────────────────

async def test_restore_undoes_a_rejected_blocks_uncommitted_credit():
    """
    A credit applied during a rejected block's processing (uncommitted, as a withdrawal
    is) must not survive — before, the next commit would have persisted it.
    """
    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    saved_db, saved_sm = node_main.db, node_main.EVM_STATE_MANAGER
    try:
        node_main.db, node_main.EVM_STATE_MANAGER = db, None
        who = pq("rejected-credit")
        await db.apply_account_balance_delta(who, Decimal("100"))   # the rejected block's effect
        await node_main._restore_after_rejected_block(7, "test")
        await db.connection.commit()                                # a later block commits
        assert await db.get_address_balance(who) == 0, (
            "a rejected block's credit survived and was committed by the next block")
    finally:
        node_main.db, node_main.EVM_STATE_MANAGER = saved_db, saved_sm
        path = db.db_path
        await db.close()
        os.remove(path)


async def test_the_rebuild_resets_mempool_nonce_expectations():
    """
    A transaction that executed in an orphaned or rejected block bumped the mempool's
    expected nonce past the account's real nonce. Without a reset the mempool refuses the
    transaction as 'nonce too low' when it is re-queued — so every reorg silently lost its
    orphaned EVM transactions.
    """
    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    saved_db, saved_sm = node_main.db, node_main.EVM_STATE_MANAGER
    saved_pending = dict(node_main.EVM_PENDING_NONCE)
    try:
        node_main.db, node_main.EVM_STATE_MANAGER = db, None
        sender = "0x" + "12" * 20
        await db.connection.execute(
            "INSERT INTO account_state (address, balance, nonce, created_at, updated_at, "
            "is_contract) VALUES (?, '0', 3, 0, 0, 0)", (sender,))
        await db.connection.commit()
        node_main.EVM_PENDING_NONCE.clear()
        node_main.EVM_PENDING_NONCE[sender] = 5       # bumped by an orphaned block's txs

        await node_main._reset_evm_pending_nonces()
        assert node_main.EVM_PENDING_NONCE.get(sender) == 3, (
            "the mempool still expects the orphaned block's nonces — re-queued "
            "transactions would be refused as 'nonce too low'")
    finally:
        node_main.db, node_main.EVM_STATE_MANAGER = saved_db, saved_sm
        node_main.EVM_PENDING_NONCE.clear()
        node_main.EVM_PENDING_NONCE.update(saved_pending)
        path = db.db_path
        await db.close()
        os.remove(path)


def test_the_rollback_rebuild_resets_nonces():
    src = inspect.getsource(node_main._rebuild_derived_state_after_rollback)
    assert "_reset_evm_pending_nonces()" in src
