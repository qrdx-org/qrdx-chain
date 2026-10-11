"""
Push-sync: a node that is ahead pushes the blocks a lagging peer is missing (main._push_sync_to_peer
→ p2p_submitBlocks). Three defects stranded a lagging node at height 0 on a 1-second-slot testnet:

  * the pushed items carried no block hash or proposer, so p2p_submitBlocks handed every PoS block
    to the PoW parser, which failed on it — a push never delivered a block;
  * the pusher counted each refused push as a violation by the receiver, which was banned after
    four, and a banned node's handshake is refused;
  * a node whose only peers were learned from their own requests (no URL) never re-bootstrapped,
    so it had nobody to pull from.
"""
import asyncio
import os
import tempfile
import time
from types import SimpleNamespace

import pytest

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.node import main as node_main
from qrdx.node.nodes_manager import NodeInterface, NodesManager
from qrdx.rpc.modules.p2p import P2PModule

PEER = {"node_id": "qxpushsyncpeer", "url": "http://peer.invalid"}


@pytest.fixture
async def chain():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = await DatabaseSQLite.create(path)
    for h in range(6):
        await db.connection.execute(
            "INSERT INTO blocks (block_hash, block_height, validator_address, timestamp, content) "
            "VALUES (?, ?, ?, ?, ?)",
            (f"{h:064x}", h, f"0xPQproposer{h}", 1_700_000_000 + 2 * h, repr({"slot": h})),
        )
    await db.connection.commit()
    yield db
    await db.connection.close()
    os.remove(path)


@pytest.fixture
def pushed(monkeypatch):
    """Capture what the pusher sends; reply with ``reply[0]``."""
    batches, reply = [], [{"ok": True, "result": "accepted"}]

    async def submit_blocks(self, payload):
        batches.append(payload)
        return reply[0]

    monkeypatch.setattr(NodeInterface, "submit_blocks", submit_blocks)
    monkeypatch.setattr(node_main.asyncio, "sleep", _no_sleep)
    return batches, reply


async def _no_sleep(_s):
    return None


def _receiver(next_height=1):
    """A P2P module whose block processor records what it is handed."""
    state = SimpleNamespace(next=next_height, handed=[])

    class _DB:
        async def get_next_block_id(self):
            return state.next

    async def process(block_info):
        state.handed.append(block_info)
        state.next += 1
        return True

    module = P2PModule()
    module._db = _DB()
    module._security = SimpleNamespace(sync_state_manager=SimpleNamespace(is_syncing=False))
    module._block_processing_lock = asyncio.Lock()
    module._process_and_create_block = process
    return module, state


async def test_pushed_blocks_reach_the_pos_import_path(chain, pushed):
    batches, _ = pushed
    await node_main._push_sync_to_peer(PEER, 1, chain, {"id": 6})
    items = [item for batch in batches for item in batch]
    assert [i["id"] for i in items] == [1, 2, 3, 4, 5]
    for i in items:
        assert i["block_hash"] == f"{i['id']:064x}"
        assert i["validator_address"] == f"0xPQproposer{i['id']}"
        assert i["timestamp"] == 1_700_000_000 + 2 * i["id"]

    module, state = _receiver()
    for batch in batches:
        assert (await module.submitBlocks(batch))["ok"]
    # process_and_create_block takes the PoS path exactly when both of these are set.
    for info in state.handed:
        assert info["block"]["hash"] and info["block"]["address"]


async def test_a_refused_push_does_not_count_against_the_receiver(chain, pushed):
    _, reply = pushed
    reply[0] = {"ok": False, "error": "the receiver refused the block"}
    rep = node_main.security.reputation_manager
    before = await rep.get_score(PEER["node_id"])
    for _ in range(6):  # more than enough refusals to have banned it before
        await node_main._push_sync_to_peer(PEER, 1, chain, {"id": 6})
    assert await rep.get_score(PEER["node_id"]) == before
    assert not await rep.is_banned(PEER["node_id"])


class _Stop(Exception):
    pass


async def test_a_node_with_no_connectable_peer_rebootstraps(monkeypatch, tmp_path):
    monkeypatch.setattr(NodesManager, "db_path", str(tmp_path / "nodes.json"))
    # Known only from their own requests: private, so no URL.
    monkeypatch.setattr(
        NodesManager, "peers", {"qxa": {"url": None, "last_seen": int(time.time())}}
    )
    bootstraps = []

    async def bootstrap():
        bootstraps.append(1)

    sleeps = []

    async def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) > 2:
            raise _Stop

    monkeypatch.setattr(node_main, "bootstrap_from_all_nodes", bootstrap)
    monkeypatch.setattr(node_main.asyncio, "sleep", sleep)
    with pytest.raises(_Stop):
        await node_main.periodic_peer_discovery()
    assert len(bootstraps) == 2  # the startup bootstrap, then a retry in the periodic loop
