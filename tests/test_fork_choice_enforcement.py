"""
Block history must converge: parent continuity AND equal-height reconciliation, enforced.

Root cause of the persistent multi-way fork: adjacent-slot proposers produce two VALID
blocks at one height off one parent, and nodes kept appending later blocks onto parents
they did not hold (broken parent links), so each height's block was chosen independently.

Neither fix worked alone (reconciliation A/B: no effect). Together, in an interleaved
three-soak A/B: worst pairwise block divergence 4,4,5 → 0,0,0 and broken parent links
3,3,4 → 0,0,0, all soaks passing, liveness unchanged.

A hidden reason continuity never took effect before: the p2p path — live broadcast, where
most blocks arrive — called the checker WITHOUT `enforce`, so it got a silent False
whatever the flag said. The earlier "6/6 safe" enforce soak only covered sync and REST.
"""
import importlib
import os
import tempfile

import pytest

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.node import main as node_main

from pq_addrs import pq


def _reloaded_defaults():
    saved = {k: os.environ.pop(k, None) for k in
             ("QRDX_ENFORCE_PARENT_CONTINUITY", "QRDX_ENFORCE_FORK_CHOICE_RECONCILE")}
    try:
        mod = importlib.reload(node_main)
        return mod._ENFORCE_PARENT_CONTINUITY, mod._ENFORCE_FORK_CHOICE_RECONCILE
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
        importlib.reload(node_main)


def test_both_gates_are_on_by_default():
    continuity, reconcile = _reloaded_defaults()
    assert continuity is True, "parent continuity must be enforced — alone neither converges"
    assert reconcile is True, "reconciliation must be enforced — alone neither converges"


def test_reconciliation_enforce_path_is_not_a_stub():
    """It was literally 'intentionally not wired yet' — flipping the flag did nothing."""
    import inspect
    src = inspect.getsource(node_main.fork_choice_reconcile_pass)
    assert "intentionally not wired yet" not in src
    assert "handle_reorganization(" in src, "enforce path must roll back to the ancestor"
    assert "get_blocks(" in src, (
        "enforce path must then FETCH the canonical chain — handle_reorganization alone "
        "only rolls back, leaving the node short")
    assert "remote_height <= local_height" not in src, (
        "must not reuse _sync_blockchain's longest-chain gate: equal-height reconciliation "
        "is exactly the case that gate declines")


async def _db_with_block(height, block_hash):
    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    await db.add_block(block_hash=block_hash, block_height=height, block_content="",
                       validator_address=pq("proposer"), timestamp=1_700_000_000)
    await db.connection.commit()
    return db


async def _check(db, **kw):
    saved = node_main.db
    node_main.db = db
    try:
        return await node_main._check_parent_continuity(
            6, str({"parent_hash": "ee" * 32, "slot": 6}), **kw)
    finally:
        node_main.db = saved


async def test_a_caller_that_omits_enforce_honours_the_gate(monkeypatch):
    """
    The p2p hook calls `_check_parent_continuity(block_no, block_content)` with no
    `enforce`. That used to default to False, so p2p never enforced. It must now follow
    the global gate.
    """
    monkeypatch.setattr(node_main, "_ENFORCE_PARENT_CONTINUITY", True)
    db = await _db_with_block(5, "aa" * 32)
    try:
        ok, err = await _check(db)            # no `enforce` — as p2p calls it
        assert ok is False, "a mismatched parent was accepted on the p2p call shape"
        assert err
    finally:
        path = db.db_path; await db.close(); os.remove(path)


async def test_gate_off_keeps_observe_behaviour(monkeypatch):
    monkeypatch.setattr(node_main, "_ENFORCE_PARENT_CONTINUITY", False)
    db = await _db_with_block(5, "aa" * 32)
    try:
        ok, _ = await _check(db)
        assert ok is True
    finally:
        path = db.db_path; await db.close(); os.remove(path)


async def test_a_matching_parent_is_accepted(monkeypatch):
    monkeypatch.setattr(node_main, "_ENFORCE_PARENT_CONTINUITY", True)
    db = await _db_with_block(5, "ee" * 32)
    try:
        ok, err = await _check(db)
        assert ok is True, err
    finally:
        path = db.db_path; await db.close(); os.remove(path)


def test_the_p2p_path_still_calls_the_checker():
    import inspect
    from qrdx.rpc.modules import p2p
    src = inspect.getsource(p2p)
    assert "self._check_parent_continuity(" in src
