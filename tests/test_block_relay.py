"""
Compact block relay (qrdx/node/block_relay.py; docs/PERFORMANCE.md).

A block travels with its exchange operations named by hash, and the receiver rebuilds the
section from its own mempool. What must hold:

* the rebuilt section is byte for byte the one the proposer signed (the block's ``body_root``),
  so every check after it runs on the block exactly as if it had come whole;
* the rebuilt operations are the mempool's own, already checked, and are not checked again;
* only what the receiver lacks is fetched, and a fetched operation the block does not name is
  refused;
* nothing a node keeps beside a block (the decoded operations) goes on the wire.
"""

import json

import pytest

from qrdx.constants import CHAIN_ID
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import ExchangeOpType, ExchangeTransaction
from qrdx.exchange.block_processor import encode_exchange_txs, is_verified
from qrdx.exchange.mempool import ExchangeMempool
from qrdx.node import block_relay
from qrdx.node import main as node_main
from qrdx.validator.block_verification import body_root


def _signed(key, nonce, to="0xPQ" + "b" * 64):
    t = ExchangeTransaction(op_type=ExchangeOpType.TOKEN_TRANSFER, sender=key.public_key.to_address(),
                            nonce=nonce, params={"token_address": "QRDX", "to": to, "amount": "0.5"},
                            gas_limit=40_000, gas_price=10 ** 9, chain_id=CHAIN_ID)
    t.public_key = key.public_key.to_bytes()
    t.signature = key.sign(t.signing_bytes()).to_bytes()
    return t


@pytest.fixture
def txs():
    keys = [PQPrivateKey.generate() for _ in range(3)]
    return [_signed(k, n) for k in keys for n in range(2)]


def _block(txs):
    section = encode_exchange_txs(txs)
    data = {"id": 9, "block_hash": "ab" * 32, "block_content": "{}", "exchange_transactions": section,
            "exchange_state_root": "cd" * 32, "_exchange_objects": list(txs)}
    data["body_root"] = body_root(data)
    return data


@pytest.fixture
def mempool(monkeypatch, txs):
    pool = ExchangeMempool(nonce_provider=lambda a: 0)
    for t in txs:   # (as they arrive by gossip: parsed from their wire form)
        assert pool.admit(ExchangeTransaction.from_dict(t.to_dict()))[0]
    monkeypatch.setattr(node_main, "_get_exchange_mempool", lambda: pool)
    return pool


def test_the_compact_form_names_the_section_by_hash(txs):
    data = _block(txs)
    form = block_relay.compact_form(data)
    assert "exchange_transactions" not in form
    assert form["exchange_tx_hashes"] == [t.tx_hash() for t in txs]
    json.dumps(form)                                            # (all of it travels)
    assert not set(block_relay.LOCAL_KEYS) & set(form)
    assert not set(block_relay.LOCAL_KEYS) & set(block_relay.wire_form(data))
    assert len(json.dumps(form)) * 50 < len(json.dumps(block_relay.wire_form(data)))


async def test_a_block_rebuilt_from_the_mempool_is_the_signed_one(txs, mempool):
    data = _block(txs)
    full, why = await block_relay.rebuild(block_relay.compact_form(data), "http://sender")
    assert why == "" and full["exchange_transactions"] == data["exchange_transactions"]
    assert body_root(full) == data["body_root"]
    assert all(is_verified(t) for t in full["_exchange_objects"])   # (checked when admitted)


async def test_only_what_is_missing_is_fetched(txs, mempool, monkeypatch):
    data = _block(txs)
    block_relay.remember(data["block_hash"], data["exchange_transactions"])
    mempool.remove([txs[1].tx_hash(), txs[4].tx_hash()])
    asked = []

    async def fetch(url, block_hash, indexes):
        asked.append(indexes)
        return block_relay.body_txs(block_hash, indexes)

    monkeypatch.setattr(block_relay, "_fetch", fetch)
    full, why = await block_relay.rebuild(block_relay.compact_form(data), "http://sender")
    assert why == "" and asked == [[1, 4]]
    assert body_root(full) == data["body_root"]


async def test_a_fetched_operation_the_block_does_not_name_is_refused(txs, mempool, monkeypatch):
    data = _block(txs)
    mempool.remove([txs[0].tx_hash()])

    async def fetch(url, block_hash, indexes):
        return [txs[1].to_dict()]           # (a real operation, at the wrong position)

    monkeypatch.setattr(block_relay, "_fetch", fetch)
    full, why = await block_relay.rebuild(block_relay.compact_form(data), "http://sender")
    assert full is None and "does not name" in why


async def test_without_the_sender_a_missing_operation_fails_the_rebuild(txs, mempool):
    data = _block(txs)
    mempool.remove([txs[2].tx_hash()])
    full, why = await block_relay.rebuild(block_relay.compact_form(data), None)
    assert full is None and "unavailable" in why


def test_a_node_serves_only_positions_of_blocks_it_relayed(txs):
    data = _block(txs)
    block_relay.remember(data["block_hash"], data["exchange_transactions"])
    assert block_relay.body_txs(data["block_hash"], [0, 5]) == [data["exchange_transactions"][0],
                                                                data["exchange_transactions"][5]]
    assert block_relay.body_txs(data["block_hash"], [6]) is None
    assert block_relay.body_txs(data["block_hash"], [True]) is None
    assert block_relay.body_txs("ef" * 32, [0]) is None


def test_the_wire_form_of_an_operation_survives_a_round_trip(txs):
    """What makes rebuilding exact: an operation parsed from its wire form gives that form back."""
    for t in txs:
        d = t.to_dict()
        assert ExchangeTransaction.from_dict(d).to_dict() == d


class _Transport:
    """The peer transport's pool, as ``netd.SERVICE.lookup`` reads it."""

    def __init__(self, held):
        self.held = held  # hash -> raw bytes

    def lookup(self, hashes):
        return [self.held.get(h) for h in hashes]


async def test_what_the_mempool_lacks_is_read_from_the_transport(txs, mempool, monkeypatch):
    """Operations that reached the node but are not admitted yet (admission waits while a block
    is processed) are in the transport's pool: read from there, not fetched from the sender.
    They are not marked verified: the block's import checks them."""
    from qrdx.node import netd

    data = _block(txs)
    mempool.remove([txs[1].tx_hash(), txs[4].tx_hash()])
    held = {t.tx_hash(): json.dumps(t.to_dict()).encode() for t in (txs[1], txs[4])}
    monkeypatch.setattr(netd, "SERVICE", _Transport(held))

    async def fetch(url, block_hash, indexes):
        raise AssertionError(f"fetched {indexes}")

    monkeypatch.setattr(block_relay, "_fetch", fetch)
    full, why = await block_relay.rebuild(block_relay.compact_form(data), "http://sender")
    assert why == "" and body_root(full) == data["body_root"]
    objects = full["_exchange_objects"]
    assert not is_verified(objects[1]) and not is_verified(objects[4]) and is_verified(objects[0])


async def test_a_transport_entry_the_block_does_not_name_is_fetched_instead(txs, mempool,
                                                                            monkeypatch):
    from qrdx.node import netd

    data = _block(txs)
    block_relay.remember(data["block_hash"], data["exchange_transactions"])
    mempool.remove([txs[2].tx_hash()])
    wrong = json.dumps(txs[3].to_dict()).encode()       # (another operation under its hash)
    monkeypatch.setattr(netd, "SERVICE", _Transport({txs[2].tx_hash(): wrong}))
    asked = []

    async def fetch(url, block_hash, indexes):
        asked.append(indexes)
        return block_relay.body_txs(block_hash, indexes)

    monkeypatch.setattr(block_relay, "_fetch", fetch)
    full, why = await block_relay.rebuild(block_relay.compact_form(data), "http://sender")
    assert why == "" and asked == [[2]] and body_root(full) == data["body_root"]


# ── over the peer transport (qrdx/node/netd.py) ──────────────────────────────────────────


async def test_what_the_node_lacks_is_asked_of_the_sender_over_the_transport(txs, mempool,
                                                                               monkeypatch):
    """A block that came over the transport: what neither the mempool nor the transport's pool
    holds is asked of the peer that sent it, by hash, before HTTP. What it answers wrongly (an
    operation the block does not name) or not at all is fetched over HTTP."""
    from qrdx.node import netd

    data = _block(txs)
    block_relay.remember(data["block_hash"], data["exchange_transactions"])
    mempool.remove([txs[i].tx_hash() for i in (1, 3, 5)])
    monkeypatch.setattr(netd, "SERVICE", _Transport({}))
    asked_peer, asked_http = [], []

    async def ask(peer, hashes):
        asked_peer.append((peer, hashes))
        answers = {txs[1].tx_hash(): json.dumps(txs[1].to_dict()).encode(),
                   txs[3].tx_hash(): json.dumps(txs[0].to_dict()).encode()}   # (wrong)
        return [answers.get(h) for h in hashes]

    async def fetch(url, block_hash, indexes):
        asked_http.append(indexes)
        return block_relay.body_txs(block_hash, indexes)

    monkeypatch.setattr(netd, "ask_block_txs", ask)
    monkeypatch.setattr(block_relay, "_fetch", fetch)
    full, why = await block_relay.rebuild(block_relay.compact_form(data), "http://sender",
                                          sender_node="qxsender")
    assert why == "" and body_root(full) == data["body_root"]
    assert asked_peer == [("qxsender", [txs[i].tx_hash() for i in (1, 3, 5)])]
    assert asked_http == [[3, 5]]


class _Sent:
    """The transport as ``peers.propagate`` uses it: what was sent, to whom."""

    def __init__(self, connected):
        self.connected = connected
        self.blocks, self.votes, self.held = [], [], []

    def send_block(self, raw, except_node=None):
        self.blocks.append(raw)
        return [n for n in self.connected if n != except_node]

    def send_votes(self, raws, except_node=None):
        self.votes.extend(raws)
        return [n for n in self.connected if n != except_node]

    def missing(self, hashes):
        return list(hashes)

    def hold(self, items):
        self.held.extend(items)


async def test_blocks_and_votes_go_over_the_transport_and_http_carries_the_rest(txs, monkeypatch):
    from qrdx.node import netd, peers
    from qrdx.node.nodes_manager import NodeInterface, NodesManager

    sent = _Sent(["qxa", "qxb"])
    monkeypatch.setattr(netd, "SERVICE", sent)
    all_peers = [{"node_id": n, "url": f"http://{n}"} for n in ("qxa", "qxb", "qxc")]
    monkeypatch.setattr(NodesManager, "get_propagate_peers", staticmethod(lambda: all_peers))

    class _Security:
        class reputation_manager:
            @staticmethod
            async def is_banned(_):
                return False

            @staticmethod
            async def record_good_behavior(_):
                return None

        import asyncio as _a
        propagation_semaphore = _a.Semaphore(4)

    monkeypatch.setattr(node_main, "security", _Security, raising=False)
    monkeypatch.setattr(peers, "get_node_id", lambda: "qxself")
    over_http = []

    async def post_prepared(self, prepared):
        over_http.append(self.url if hasattr(self, "url") else self)
        return {"ok": True}

    async def prepare(method, params):
        return (method, params)

    async def push_attestation(self, att):
        over_http.append(("vote", self.url if hasattr(self, "url") else self))
        return {"ok": True}

    monkeypatch.setattr(NodeInterface, "post_prepared", post_prepared)
    monkeypatch.setattr(NodeInterface, "prepare_rpc", staticmethod(prepare))
    monkeypatch.setattr(NodeInterface, "push_attestation", push_attestation)
    data = _block(txs)
    await peers.propagate("submit_block", data, ignore_node_id=None, db=None)
    form = json.loads(sent.blocks[0])
    assert form["exchange_tx_hashes"] == [t.tx_hash() for t in txs]
    assert "exchange_transactions" not in form and "_exchange_objects" not in form
    assert [h for h, _ in sent.held] == [t.tx_hash() for t in txs]    # (to be asked for)
    assert len(over_http) == 1 and "qxc" in str(over_http[0])          # (only the rest)
    await peers.propagate("push_attestation", {"attestation": {"slot": 3}}, db=None)
    assert [json.loads(v) for v in sent.votes] == [{"slot": 3}]
    assert len(over_http) == 2 and "qxc" in str(over_http[1])


async def test_a_block_from_the_transport_is_taken_as_one_from_http(monkeypatch):
    """The same handler, with the peer the transport authenticated as the verified sender —
    whatever the block names as its sender."""
    from qrdx.node import netd
    from qrdx.rpc.server import rpc_caller

    seen = []

    class _Module:
        async def submitCompactBlock(self, block):
            seen.append(("compact", rpc_caller.get(), block))
            return {"ok": True}

        async def submitBlock(self, block):
            seen.append(("whole", rpc_caller.get(), block))
            return {"ok": False, "error": "sync_required"}

    monkeypatch.setattr(node_main, "p2p_rpc_module", _Module())
    await netd._receive_block("qxpeer", json.dumps(
        {"id": 3, "exchange_tx_hashes": [], "_sender_node_id": "qxliar"}).encode())
    await netd._receive_block("qxpeer", json.dumps({"id": 4}).encode())
    await netd._receive_block("qxpeer", b"not json")
    await netd._receive_block("qxpeer", b"[1, 2]")
    assert seen == [("compact", "qxpeer", {"id": 3, "exchange_tx_hashes": []}),
                    ("whole", "qxpeer", {"id": 4})]
    assert rpc_caller.get() is None
