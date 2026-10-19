"""
Fork choice, resolved at once (qrdx/node/main.py resolve_fork_with_peer; qrdx/validator/ffg.py
prefer).

Forks used to be repaired only by a pass every ~8 s, under two rules that disagreed (sync took
the longer chain; the pass took the lower hash at the first divergent height). At sub-second
slots a node spent dozens of slots on a losing branch, and with finality not bound to a branch
the fork then finalized on both sides. Now a block that does not extend the tip triggers fork
choice with the peer that sent it, under one rule (Casper FFG's, then the longest chain) scored
from the competing branch's own blocks. What must hold:

  * a branch holding a newer justified checkpoint that the other chain does not hold wins even
    when it is shorter, and a merely longer branch never pulls a node off such a checkpoint;
  * a justified checkpoint below the fork is in both chains, whichever branch carries its
    votes: it decides nothing, and the taller branch wins (the 250 ms testnet stalled when one
    validator's branch, carrying one more vote for a shared checkpoint, beat the network's);
  * with equal justification the taller branch wins, and at equal height the lower tip hash —
    the same choice on both nodes, so they converge instead of swapping;
  * nothing is rolled back unless the peer's branch wins, never below the finalized checkpoint;
  * a branch that turns out to hold a block the node refuses is undone, and the node's own
    branch restored;
  * the switch is atomic against every other block writer: a block arriving over p2p mid-switch
    waits for it (it used to land between the rollback and the branch, so the branch no longer
    fit and the node's own could not be restored either), and a chain that moved while the
    branch was scored is left alone.
"""
import asyncio

import pytest

from qrdx.constants import SLOTS_PER_EPOCH as S
from qrdx.node import main as node_main
from qrdx.node.nodes_manager import NodesManager
from qrdx.rpc.modules.p2p import blocks_for_transfer
from qrdx.validator import ffg
from qrdx.validator.finality import update_finality

from test_finality_compute import Chain, keys  # noqa: F401  (keys: the module fixture)

PEER = "qxpeer"


class _Peer:
    """NodeInterface for the peer: its chain is another Chain's database."""

    chain = None

    def __init__(self, url, client=None, db=None):
        pass

    async def get_status(self):
        c = _Peer.chain
        return {"ok": True, "result": {"height": c.height, "last_block_hash": c.hashes[-1]}}

    async def get_block_hashes(self, lo, hi):
        hashes = await _Peer.chain.db.get_block_hashes(lo, hi)
        return {"ok": True, "result": {str(h): bh for h, bh in hashes.items()}}

    async def get_blocks(self, start, limit):
        return {"ok": True, "result": await blocks_for_transfer(_Peer.chain.db, start, limit)}


@pytest.fixture
async def setup(monkeypatch, keys):  # noqa: F811
    ours, theirs = await Chain.create(keys), await Chain.create(keys)
    applied, refuse = [], set()

    async def apply(block_info, is_bulk_sync=False):
        b = block_info["block"]
        if b["block_hash"] in refuse:
            return False
        if b["block_height"] != await ours.db.get_next_block_id():
            return False
        await ours.db.connection.execute(
            "INSERT INTO blocks (block_hash, block_height, content, timestamp) VALUES (?, ?, ?, 0)",
            (b["block_hash"], b["block_height"], b["content"]))
        await ours.db.connection.commit()
        applied.append(b["block_hash"])
        return True

    async def nothing(*a, **k):
        return None

    async def compatible(*a, **k):
        return True

    monkeypatch.setattr(node_main, "db", ours.db)
    monkeypatch.setattr(node_main, "NodeInterface", _Peer)
    monkeypatch.setattr(node_main, "process_and_create_block", apply)
    monkeypatch.setattr(node_main, "_rebuild_derived_state_after_rollback", nothing)
    monkeypatch.setattr(node_main, "_drop_if_incompatible", compatible)
    monkeypatch.setattr(NodesManager, "peers", {PEER: {"node_id": PEER, "url": "http://peer"}})
    monkeypatch.setattr(NodesManager, "sync", staticmethod(lambda: None))
    _Peer.chain = theirs
    yield ours, theirs, refuse
    await ours.close()
    await theirs.close()


async def _tip(chain):
    h = await chain.db.get_next_block_id() - 1
    return (await chain.db.get_block_hashes(h, h))[h]


async def _common(ours, theirs, epochs):
    """The shared history: built once and copied, block for block (a vote is a fresh,
    randomized signature, and a block's hash commits to the votes it carries)."""
    await ours.epochs(1, epochs, voters=[0, 1, 2, 3])
    await copy_blocks(ours, theirs)


async def copy_blocks(src, dst):
    cur = await src.db.connection.execute(
        "SELECT block_hash, block_height, content FROM blocks WHERE block_height > ? "
        "ORDER BY block_height", (dst.height,))
    for bh, height, content in await cur.fetchall():
        await dst.db.connection.execute(
            "INSERT INTO blocks (block_hash, block_height, content, timestamp) VALUES (?, ?, ?, 0)",
            (bh, height, content))
        dst.height = height
        dst.hashes.append(bh)
        dst.slots.append(src.slots[height])
    await dst.db.connection.commit()


async def test_a_newer_justified_checkpoint_wins_over_a_longer_branch(setup):
    ours, theirs, _ = setup
    await _common(ours, theirs, 1)
    # Justifies epochs 2 and 3; epoch 3's checkpoint is a block of their own branch.
    await theirs.epochs(2, 3, voters=[0, 1, 2], tag="T")
    for i in range(8):                                        # ours: longer, no votes
        await ours.block(2 * S + 1 + i, tag="O")
    assert await node_main.resolve_fork_with_peer(PEER)
    assert await _tip(ours) == theirs.hashes[-1]
    assert (await update_finality(ours.db))["justified_epoch"] == 3


async def test_a_longer_branch_does_not_pull_a_node_off_a_newer_justified_checkpoint(setup):
    ours, theirs, _ = setup
    await _common(ours, theirs, 1)
    await ours.epochs(2, 3, voters=[0, 1, 2], tag="O")       # checkpoint 3 is ours alone
    for i in range(8):
        await theirs.block(2 * S + 1 + i, tag="T")
    before = await _tip(ours)
    assert not await node_main.resolve_fork_with_peer(PEER)
    assert await _tip(ours) == before


async def test_votes_for_a_shared_checkpoint_do_not_beat_a_taller_branch(setup):
    """Their branch carries the votes justifying epoch 2, but epoch 2's checkpoint is below the
    fork: ours holds it too. Height decides: ours, the taller, stays."""
    ours, theirs, _ = setup
    await _common(ours, theirs, 1)
    await theirs.epochs(2, 2, voters=[0, 1, 2], tag="T")
    for i in range(6):
        await ours.block(2 * S + 1 + i, tag="O")
    before = await _tip(ours)
    assert not await node_main.resolve_fork_with_peer(PEER)
    assert await _tip(ours) == before


async def test_a_node_carrying_the_votes_still_joins_a_taller_branch(setup):
    """The other side of the same fork: ours carries the votes for the shared checkpoint, theirs
    is taller. Ours moves, so both nodes end on one chain."""
    ours, theirs, _ = setup
    await _common(ours, theirs, 1)
    await ours.epochs(2, 2, voters=[0, 1, 2], tag="O")
    for i in range(6):
        await theirs.block(2 * S + 1 + i, tag="T")
    assert await node_main.resolve_fork_with_peer(PEER)
    assert await _tip(ours) == theirs.hashes[-1]


def test_prefer_reads_the_justified_checkpoints_height_against_the_fork():
    newer, older = ffg.Score(14, 487, "aa", 331), ffg.Score(9, 649, "bb", 209)
    assert not ffg.prefer(newer, older, ancestor=338)   # both hold epoch 14's checkpoint
    assert ffg.prefer(older, newer, ancestor=338)
    assert ffg.prefer(newer, older, ancestor=300)       # it is above the fork: only one holds it
    assert ffg.prefer(newer, older)                     # no fork point given: justification first


async def test_with_equal_justification_the_taller_branch_wins(setup):
    ours, theirs, _ = setup
    await _common(ours, theirs, 1)
    await ours.block(2 * S + 1, tag="O")
    for i in range(3):
        await theirs.block(2 * S + 1 + i, tag="T")
    assert await node_main.resolve_fork_with_peer(PEER)
    assert await _tip(ours) == theirs.hashes[-1]


async def test_at_equal_height_both_nodes_pick_the_lower_tip_hash(setup):
    ours, theirs, _ = setup
    await _common(ours, theirs, 1)
    a = await ours.block(2 * S + 1, tag="O")
    b = await theirs.block(2 * S + 1, tag="T")
    moved = await node_main.resolve_fork_with_peer(PEER)
    assert moved == (b < a)
    assert await _tip(ours) == min(a, b)
    # From the other side the same rule picks the same block.
    assert ffg.prefer((1, 0, min(a, b)), (1, 0, max(a, b)))
    assert not ffg.prefer((1, 0, max(a, b)), (1, 0, min(a, b)))


async def test_a_branch_with_a_refused_block_is_undone_and_ours_restored(setup):
    ours, theirs, refuse = setup
    await _common(ours, theirs, 1)
    mine = [await ours.block(2 * S + 1 + i, tag="O") for i in range(2)]
    theirs_new = [await theirs.block(2 * S + 1 + i, tag="T") for i in range(4)]
    refuse.add(theirs_new[2])
    assert not await node_main.resolve_fork_with_peer(PEER)
    h = await ours.db.get_next_block_id() - 1
    assert [(await ours.db.get_block_hashes(x, x))[x] for x in (h - 1, h)] == mine


async def test_never_below_the_finalized_checkpoint(setup):
    ours, theirs, _ = setup
    await ours.epochs(1, 3, voters=[0, 1, 2, 3])               # finalizes epoch 2
    await update_finality(ours.db)
    for i in range(30):                                        # theirs: a long branch from genesis
        await theirs.block(1 + i, tag="T")
    before = await _tip(ours)
    assert not await node_main.resolve_fork_with_peer(PEER)
    assert await _tip(ours) == before


async def test_a_block_arriving_mid_switch_waits_for_it(setup, monkeypatch):
    ours, theirs, _ = setup
    await _common(ours, theirs, 1)
    mine = await ours.block(2 * S + 1, tag="O")
    for i in range(3):
        await theirs.block(2 * S + 1 + i, tag="T")
    echoed = await blocks_for_transfer(ours.db, ours.height, 1)  # a peer pushes ours back
    pushes = []

    async def push():
        async with node_main.block_processing_lock:
            return await node_main.process_and_create_block(echoed[0])

    async def rebuild_and_receive_a_push():
        if not pushes:
            pushes.append(asyncio.create_task(push()))
            await asyncio.sleep(0)  # the push now waits on the block-processing lock

    monkeypatch.setattr(node_main, "_rebuild_derived_state_after_rollback",
                        rebuild_and_receive_a_push)
    assert await node_main.resolve_fork_with_peer(PEER)
    assert await pushes[0] is False  # it ran after the switch, and no longer fits
    assert await _tip(ours) == theirs.hashes[-1] != mine


async def test_a_chain_that_moved_while_the_branch_was_scored_is_left_alone(setup, monkeypatch):
    ours, theirs, _ = setup
    await _common(ours, theirs, 1)
    await ours.block(2 * S + 1, tag="O")
    for i in range(3):
        await theirs.block(2 * S + 1 + i, tag="T")
    fetch, n = _Peer.get_blocks, len(ours.hashes)

    async def get_blocks_while_ours_grows(self, start, limit):
        if len(ours.hashes) == n:  # our proposer adds blocks meanwhile
            for i in range(3):
                await ours.block(2 * S + 2 + i, tag="O")
        return await fetch(self, start, limit)

    monkeypatch.setattr(_Peer, "get_blocks", get_blocks_while_ours_grows)
    assert not await node_main.resolve_fork_with_peer(PEER)
    assert len(ours.hashes) == n + 3
    assert await _tip(ours) == ours.hashes[-1]
