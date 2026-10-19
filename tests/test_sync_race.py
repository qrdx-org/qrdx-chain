"""
A sync batch that overlaps blocks pushed while it was in flight (qrdx/node/main.py
_sync_blockchain).

At 250 ms slots, blocks pushed by peers keep arriving while a sync fetches a batch, so by the
time the batch is applied its first blocks are often already here. The sync used to try to apply
them again, fail on the height, abort as a "FATAL ERROR", and record a severity-8 violation
against the honest peer it was syncing from. Now blocks the node already holds are skipped, and a
different block at a height it holds hands the decision to fork choice.
"""
from qrdx.node import main as node_main

from test_finality_compute import keys  # noqa: F401  (the module fixture)
from test_fork_resolution import PEER, _Peer, copy_blocks, setup  # noqa: F401  (the fixture)


async def _sync(monkeypatch, ours, theirs, pushed):
    violations, forks = [], []

    async def record_violation(peer_id, kind, severity=1):
        violations.append((peer_id, kind))

    async def get_status(self):
        return {"ok": True, "result": {"height": theirs.height, "network": None,
                                        "last_block_hash": theirs.hashes[-1]}}

    async def get_block(self, h):
        return {"ok": True, "result": {"block": {"hash": theirs.hashes[int(h)]}}}

    fetch = _Peer.get_blocks

    async def get_blocks_while_pushes_arrive(self, start, limit):
        resp = await fetch(self, start, limit)
        for b in resp["result"][:pushed]:  # these reach us by push before the batch is applied
            assert await node_main.process_and_create_block(b)
        return resp

    monkeypatch.setattr(node_main.security.reputation_manager, "record_violation",
                        record_violation)
    monkeypatch.setattr(node_main, "schedule_fork_resolution",
                        lambda peer, reason: forks.append(reason))
    monkeypatch.setattr(_Peer, "get_status", get_status, raising=False)
    monkeypatch.setattr(_Peer, "get_block", get_block, raising=False)
    monkeypatch.setattr(_Peer, "get_blocks", get_blocks_while_pushes_arrive)
    await node_main._sync_blockchain(node_id=PEER)
    return violations, forks


async def test_blocks_pushed_during_the_fetch_are_skipped_not_fatal(setup, monkeypatch):
    ours, theirs, _ = setup
    await ours.epochs(1, 1, voters=[0, 1, 2, 3])
    await copy_blocks(ours, theirs)          # one shared history (votes are randomized)
    for i in range(6):
        await theirs.block(100 + i, tag="T")
    violations, forks = await _sync(monkeypatch, ours, theirs, pushed=2)
    tip = await ours.db.get_next_block_id() - 1
    assert tip == theirs.height
    assert (await ours.db.get_block_hashes(tip, tip))[tip] == theirs.hashes[-1]
    assert violations == [] and forks == []


async def test_a_peer_that_reorged_mid_sync_hands_off_to_fork_choice(setup, monkeypatch):
    """The peer agreed with our tip at the integrity check, then reorged: its batch builds on
    another parent. That is a fork, not an invalid block: no violation, fork choice decides."""
    ours, theirs, _ = setup
    await ours.epochs(1, 1, voters=[0, 1, 2, 3])
    await copy_blocks(ours, theirs)
    mine = await ours.block(100, tag="O")
    for i in range(4):
        await theirs.block(100 + i, tag="T")
    ours_tip = ours.height

    async def agreeing_get_block(self, h):
        return {"ok": True, "result": {"block": {"hash": ours.hashes[int(h)]}}}

    async def get_status(self):
        return {"ok": True, "result": {"height": theirs.height, "network": None}}

    violations, forks = [], []

    async def record_violation(peer_id, kind, severity=1):
        violations.append(kind)

    monkeypatch.setattr(node_main.security.reputation_manager, "record_violation",
                        record_violation)
    monkeypatch.setattr(node_main, "schedule_fork_resolution",
                        lambda peer, reason: forks.append(reason))
    monkeypatch.setattr(_Peer, "get_status", get_status, raising=False)
    monkeypatch.setattr(_Peer, "get_block", agreeing_get_block, raising=False)
    await node_main._sync_blockchain(node_id=PEER)
    assert violations == [] and forks == ["sync batch left our chain"]
    assert (await ours.db.get_block_hashes(ours_tip, ours_tip))[ours_tip] == mine
