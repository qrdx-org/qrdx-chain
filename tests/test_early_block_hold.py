"""
A block that arrives before its parent is held (qrdx/rpc/modules/p2p.py ``_hold_early``): under
load a block often overtakes its parent. Dropped, it was fetched again by fork resolution, and
meanwhile the next slot's proposer built a competing block over it. Held, it is submitted as soon
as its parent is imported, and a proposer waits for it as for a block being imported.
"""

import asyncio

from qrdx.rpc.modules.p2p import P2PModule
from qrdx.rpc.server import rpc_caller
from qrdx.validator import pipeline


def _module(monkeypatch):
    m = P2PModule()
    submitted, forks = [], []

    async def submit(block):
        submitted.append((block["id"], rpc_caller.get()))
        return {"ok": True}

    monkeypatch.setattr(m, "submitBlock", submit)
    monkeypatch.setattr(
        m, "_signal_fork", lambda no, block, why: forks.append((no, rpc_caller.get()))
    )
    return m, submitted, forks


async def test_a_held_block_is_submitted_once_its_parent_is_imported(monkeypatch):
    m, submitted, forks = _module(monkeypatch)
    token = rpc_caller.set("peer-a")
    try:
        assert m._hold_early(12, {"id": 12})
        assert not m._hold_early(12, {"id": 12, "other": True})  # (one a height)
    finally:
        rpc_caller.reset(token)
    assert pipeline.incoming(12)  # (a proposer of the next slot waits for it)
    m._release_early(13)  # (another height: nothing)
    m._release_early(12)
    await asyncio.sleep(0)
    assert submitted == [(12, "peer-a")] and forks == []  # (as its sender sent it)
    assert not pipeline.incoming(12)


async def test_a_held_block_whose_parent_does_not_come_goes_to_fork_resolution(monkeypatch):
    m, submitted, forks = _module(monkeypatch)
    monkeypatch.setattr(P2PModule, "EARLY_FOR", 0.01)
    token = rpc_caller.set("peer-b")
    try:
        assert m._hold_early(20, {"id": 20})
    finally:
        rpc_caller.reset(token)
    await asyncio.sleep(0.05)
    assert forks == [(20, "peer-b")] and submitted == []
    assert not pipeline.incoming(20) and 20 not in m._early
    m._release_early(20)  # (too late: nothing held)
    await asyncio.sleep(0)
    assert submitted == []
