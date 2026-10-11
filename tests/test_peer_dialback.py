"""
A peer dropped as unreachable gets its URL back when it returns (qrdx/node/main.py
handle_unreachable_peer, _dial_back_if_known).

A node drops a peer it cannot reach. When that peer comes back it connects in, and a peer that
connects in is recorded without a URL (a private node advertises none). This node could then
neither push blocks to it nor resolve a fork with it: after a validator restarted on the 250 ms
testnet, the network stayed split. The dropped peer's URL, verified by the handshake it was
learned in, is remembered and dialled back.
"""
import asyncio

from qrdx.node import main as node_main
from qrdx.node.nodes_manager import NodesManager

PEER, URL = "qxreturning", "http://127.0.0.1:3008"


async def test_a_returning_peer_is_dialled_back_at_its_old_url(monkeypatch):
    peers = {PEER: {"pubkey": "pk", "url": URL, "last_seen": 0, "is_public": False}}
    monkeypatch.setattr(NodesManager, "peers", peers)
    monkeypatch.setattr(NodesManager, "sync", staticmethod(lambda: None))
    monkeypatch.setattr(node_main, "_FORMER_PEER_URLS", {})
    monkeypatch.setattr(node_main, "_dialback_at", {})
    dials = []

    async def handshake(url):
        dials.append(url)
        NodesManager.peers[PEER] = {"pubkey": "pk", "url": url, "last_seen": 0, "is_public": False}

    monkeypatch.setattr(node_main, "do_handshake_with_peer", handshake)

    await node_main.handle_unreachable_peer(PEER, URL, "propagation")
    assert PEER not in NodesManager.peers and node_main._FORMER_PEER_URLS == {PEER: URL}

    # It comes back and connects in: recorded without a URL, then dialled back once.
    NodesManager.peers[PEER] = {"pubkey": "pk", "url": None, "last_seen": 0, "is_public": False}
    node_main._dial_back_if_known(PEER)
    node_main._dial_back_if_known(PEER)  # a second request at once does not dial again
    for _ in range(5):
        await asyncio.sleep(0)
    assert dials == [URL]
    assert NodesManager.peers[PEER]["url"] == URL
    assert PEER not in node_main._FORMER_PEER_URLS


async def test_the_memory_is_bounded(monkeypatch):
    monkeypatch.setattr(NodesManager, "peers", {})
    monkeypatch.setattr(NodesManager, "sync", staticmethod(lambda: None))
    monkeypatch.setattr(node_main, "_FORMER_PEER_URLS", {})
    for i in range(node_main._FORMER_PEER_URLS_MAX + 10):
        await node_main.handle_unreachable_peer(f"qx{i}", f"http://10.0.0.{i % 250}:3007", "x")
    assert len(node_main._FORMER_PEER_URLS) == node_main._FORMER_PEER_URLS_MAX
