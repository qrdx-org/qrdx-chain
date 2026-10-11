"""
Fork-choice reconciliation must be able to adopt the canonical chain — and must not undo itself.

Across three fault-injecting soaks, 24 of 41 reconciliation attempts failed, for two reasons:

* **The ancestor search started above the peer's chain.** Reconciliation passed the LOCAL tip
  as the search start, but the peer holding the canonical (lowest-hash) block can be
  shorter. It was asked for a block it did not have and the reorg aborted ("Could not get
  remote block at height N") — 18 of the 24 failures. The search now starts at the
  divergence height; orphan collection still runs to the local tip.
* **The node's own proposer slipped into the adoption.** Rollback and each applied batch hold
  the block-processing lock, but the network fetches between them cannot. The proposer built
  a fresh block on the just-rolled-back tip, so the adopted chain's next block failed
  ("height 130 != expected 131") — the resolver re-created the fork it was resolving. While
  an adoption is in flight the proposer now skips its slot.
"""
import inspect
import os
import tempfile

import pytest

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.node import main as node_main
from qrdx.validator import node_integration as NI

SHARED, FORK = 7, 10          # blocks 0..7 shared; local diverges at 8 and runs to 10


def _hash(h, side):
    return f"{side}{h:063x}"


class _ShorterPeer:
    """Holds the canonical chain 0..8: same as us up to 7, a different block at 8."""

    async def get_block(self, height):
        h = int(height)
        if h > SHARED + 1:
            return {"ok": False}
        return {"ok": True, "result": {"block": {"hash": _hash(h, "a" if h <= SHARED else "b")}}}


@pytest.fixture
async def local_chain(monkeypatch):
    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    for h in range(FORK + 1):
        await db.add_block(block_hash=_hash(h, "a" if h <= SHARED else "c"), block_height=h,
                           block_content="", validator_address="0xPQ" + "00" * 32,
                           timestamp=1_700_000_000 + h)
    await db.connection.commit()
    monkeypatch.setattr(node_main, "db", db)
    monkeypatch.setattr(node_main, "EVM_STATE_MANAGER", None)
    yield db
    path = db.db_path
    await db.close()
    os.remove(path)


async def test_searching_from_the_local_tip_aborts_on_a_shorter_peer(local_chain):
    """The failure the soaks showed (and the default for longest-chain sync, where the peer
    is longer and this cannot happen)."""
    assert await node_main.handle_reorganization(_ShorterPeer(), FORK) is None
    assert (await local_chain.get_next_block_id()) - 1 == FORK, "nothing may roll back"


async def test_searching_from_the_divergence_height_finds_the_ancestor(local_chain):
    common = await node_main.handle_reorganization(_ShorterPeer(), FORK, search_from=SHARED + 1)
    assert common == SHARED
    assert (await local_chain.get_next_block_id()) - 1 == SHARED, "rolled back to the ancestor"


def test_fork_choice_finds_the_ancestor_from_both_chains_hashes():
    """The resolver compares the two chains' hashes over the window in one exchange, so a
    shorter peer holding the winning block is never asked for a block it lacks."""
    src = inspect.getsource(node_main.resolve_fork_with_peer)
    assert "get_block_hashes(lo, hi)" in src and "db.get_block_hashes(lo, hi)" in src
    assert "resolve_fork_with_peer(" in inspect.getsource(node_main.fork_choice_reconcile_pass)


# ── the adoption guard ────────────────────────────────────────────────────

async def test_the_adoption_marker_is_balanced_even_on_error():
    assert not node_main._peer_chain_adoption_in_progress()
    with pytest.raises(RuntimeError):
        async with node_main._adopting_peer_chain():
            assert node_main._peer_chain_adoption_in_progress()
            raise RuntimeError("peer vanished mid-fetch")
    assert not node_main._peer_chain_adoption_in_progress()


@pytest.mark.parametrize("fn, calls", [
    ("resolve_fork_with_peer", ("_rollback_to(", "_apply_branch(")),
    ("_sync_blockchain", ("process_and_create_block(",)),
])
def test_both_adoption_paths_mark_rollback_through_apply(fn, calls):
    src = inspect.getsource(getattr(node_main, fn))
    start = src.index("async with _adopting_peer_chain()")
    depth = len(src[:start].splitlines()[-1]) if src[:start].splitlines() else 0
    body = src[start:]
    if len(calls) == 2:
        assert body.index(calls[0]) < body.index(calls[1])
    # Every call sits inside the marked block (deeper than the `async with` line).
    for call in calls:
        line = next(l for l in body.splitlines() if call in l)
        assert len(line) - len(line.lstrip()) > depth, f"{call} is outside the adoption marker"


def test_the_proposer_skips_its_slot_mid_adoption():
    lines = inspect.getsource(NI.ValidatorNode._block_production_loop).splitlines()
    start = next(i for i, l in enumerate(lines) if "async with self._production_lock():" in l)
    guard = next(i for i, l in enumerate(lines) if "self._proposal_guard()" in l)
    first_section = next(i for i, l in enumerate(lines) if "process_exchange_transactions(" in l)
    assert start < guard < first_section, "the guard must be checked under the lock, before execution"
    assert any("continue" in l for l in lines[guard + 1:guard + 6])


def test_main_wires_the_guard():
    assert "set_proposal_guard(_validator_wait_reason)" in inspect.getsource(node_main.startup)


def test_the_guard_holds_a_validator_until_its_first_sync(monkeypatch):
    """A validator that starts behind the network neither proposes nor votes on its stale tip
    until the post-bootstrap sync check has run, and never for longer than the bound."""
    import time

    monkeypatch.setattr(node_main, "_PEER_CHAIN_ADOPTIONS", 0)
    monkeypatch.setattr(node_main, "_initial_sync_pending", True)
    monkeypatch.setattr(node_main, "_initial_sync_deadline", time.monotonic() + 60)
    assert node_main._validator_wait_reason() == "waiting for the first sync with peers"
    monkeypatch.setattr(node_main, "_initial_sync_deadline", time.monotonic() - 1)
    assert node_main._validator_wait_reason() is None  # an isolated node still produces
    monkeypatch.setattr(node_main, "_initial_sync_deadline", time.monotonic() + 60)
    monkeypatch.setattr(node_main, "_initial_sync_pending", False)
    assert node_main._validator_wait_reason() is None
    monkeypatch.setattr(node_main, "_PEER_CHAIN_ADOPTIONS", 1)
    assert node_main._validator_wait_reason() == "adopting a peer's chain"
    src = inspect.getsource(node_main.periodic_peer_discovery)
    assert src.index("check_peer_and_sync(") < src.index("_catch_up_before_validating()")
    assert src.index("_catch_up_before_validating()") < src.index("_initial_sync_pending = False")


def test_the_voter_waits_too():
    src = inspect.getsource(NI.ValidatorNode._attestation_loop)
    assert src.index("self._proposal_guard()") < src.index("self._cast_vote(")


async def test_a_validator_catches_up_before_it_validates(monkeypatch):
    """A sync ends behind by what the network produced while it ran (at 250 ms a restarted
    validator came out of its first sync six blocks short). The catch-up syncs again until no
    peer is more than a block ahead, and gives up at the deadline."""
    import time
    from types import SimpleNamespace

    chain = {"local": 100, "remote": 160, "syncs": 0}

    class Peer:
        def __init__(self, url, client=None, db=None):
            pass

        async def get_status(self):
            chain["remote"] += 2  # the network keeps producing while we sync
            return {"ok": True, "result": {"height": chain["remote"]}}

    async def sync(peer_info):
        chain["syncs"] += 1
        chain["local"] = chain["remote"] - 1 if chain["syncs"] >= 3 else chain["remote"] - 20

    async def next_block_id():
        return chain["local"] + 1

    monkeypatch.setattr(node_main, "NodeInterface", Peer)
    monkeypatch.setattr(node_main, "check_peer_and_sync", sync)
    monkeypatch.setattr(node_main, "db", SimpleNamespace(get_next_block_id=next_block_id))
    monkeypatch.setattr(node_main.NodesManager, "get_all_peers",
                        staticmethod(lambda: [{"node_id": "p", "url": "http://p"}]))
    monkeypatch.setattr(node_main, "_initial_sync_deadline", time.monotonic() + 30)
    await node_main._catch_up_before_validating()
    assert chain["syncs"] == 3   # synced until within a block, not once

    chain.update(local=0, remote=10_000, syncs=0)
    monkeypatch.setattr(node_main, "_initial_sync_deadline", time.monotonic() - 1)
    await node_main._catch_up_before_validating()
    assert chain["syncs"] == 0   # past the deadline it never blocks
