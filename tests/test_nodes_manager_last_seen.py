"""
A peer's last_seen is updated in memory on every signed request, but the peer store on disk is
rewritten at most once per LAST_SEEN_PERSIST_INTERVAL (qrdx/node/nodes_manager.py). Rewriting
it on every request was a third of a node's event-loop time.
"""
import json

import pytest

from qrdx.node import nodes_manager as nm
from qrdx.node.nodes_manager import NodesManager


@pytest.fixture
def store(tmp_path, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(nm.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(NodesManager, "db_path", str(tmp_path / "nodes.json"))
    monkeypatch.setattr(NodesManager, "peers", {"peer-a": {"url": "http://a", "last_seen": 0}})
    monkeypatch.setattr(NodesManager, "_last_sync", 0.0)
    writes = []
    real = NodesManager.sync

    def counting():
        writes.append(clock[0])
        real()

    monkeypatch.setattr(NodesManager, "sync", staticmethod(counting))
    return clock, writes, tmp_path / "nodes.json"


def test_last_seen_is_current_in_memory_and_persisted_at_most_once_per_interval(store):
    clock, writes, path = store
    NodesManager.update_peer_last_seen("peer-a")
    assert len(writes) == 1  # the first update is persisted

    for _ in range(50):  # a burst of requests within the interval
        clock[0] += 0.5
        NodesManager.update_peer_last_seen("peer-a")
    assert len(writes) == 1
    assert NodesManager.peers["peer-a"]["last_seen"] > 0  # memory is always current

    clock[0] = writes[0] + nm.LAST_SEEN_PERSIST_INTERVAL
    NodesManager.update_peer_last_seen("peer-a")
    assert len(writes) == 2
    on_disk = json.loads(path.read_text())["peers"]["peer-a"]["last_seen"]
    assert on_disk == NodesManager.peers["peer-a"]["last_seen"]


def test_an_unknown_peer_writes_nothing(store):
    _clock, writes, _path = store
    NodesManager.update_peer_last_seen("nobody")
    assert writes == []
