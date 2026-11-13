"""
Who becomes a peer, and who keeps the place (docs/KNOWN_ISSUES.md, "Anyone could fill a node's
peer table").

Any signed request that named this chain's genesis made its caller a peer, up to the limit.
Once the table was full, nobody else got in, so whoever filled it first held it, with keys
anyone can make. Now:

* a caller becomes a peer only by completing the handshake;
* at most a few peers come from one network group;
* a full table makes room for a newcomer by displacing an inbound peer from the most crowded
  group, and never a validator, a peer this node dialed or one of the longest-connected;
* a peer that proves, with its validator key, that it runs a validator is exempt.
"""

import json

import pytest
from test_peer_rpc_authentication import _call, _signed, me, peers, whoami  # noqa: F401

from qrdx.node import identity
from qrdx.node import main as node_main
from qrdx.node import peers as node_peers
from qrdx.node import nodes_manager as nm
from qrdx.node.nodes_manager import NodesManager, network_group


def _admit(n, ip, **kw):
    return NodesManager.admit_peer(f"qx{n:040x}", "ab" * 8, f"http://{ip}:3007", True,
                                   source_ip=ip, **kw)


def test_network_groups():
    assert network_group("203.0.113.7") == network_group("203.0.113.200") == "203.0.113.0/24"
    assert network_group("203.0.114.7") != network_group("203.0.113.7")
    assert network_group("2001:db8:1:2::5") == "2001:db8:1::/48"
    assert network_group("127.0.0.1") is None and network_group(None) is None  # (exempt)


def test_one_group_holds_at_most_a_few_places(peers, monkeypatch):
    monkeypatch.setattr(nm, "PEERS_PER_GROUP", 4)
    assert all(_admit(i, f"198.51.100.{i}") for i in range(4))
    assert not _admit(4, "198.51.100.99")              # a fifth from that /24
    assert _admit(5, "198.51.101.1")                   # another /24 is welcome
    assert _admit(6, "198.51.100.98", validator="0xPQ" + "aa" * 32)   # a validator is exempt


def test_a_full_table_displaces_an_inbound_peer_of_the_most_crowded_group(peers, monkeypatch):
    monkeypatch.setattr(nm, "PEERS_PER_GROUP", 4)
    monkeypatch.setattr(nm, "MAX_PEERS_COUNT", 12)
    monkeypatch.setattr(nm, "PROTECTED_LONGEST", 2)
    clock = iter(range(1_000_000, 2_000_000))
    monkeypatch.setattr(nm.time, "time", lambda: next(clock))
    _admit(0, "192.0.2.1")                                       # the two longest-connected:
    _admit(1, "192.0.2.2")                                       # protected
    _admit(2, "192.0.3.1", outbound=True)                         # dialed by us: protected
    _admit(3, "192.0.4.1", validator="0xPQ" + "bb" * 32)          # a validator: protected
    for i in range(4, 8):
        _admit(i, f"192.0.5.{i}")                                 # a crowded group
    for i in range(8, 12):
        _admit(i, f"192.0.{i}.1")                                 # one each
    assert len(NodesManager.peers) == 12
    assert _admit(99, "192.0.99.1")                               # room is made for it
    assert f"qx{99:040x}" in NodesManager.peers
    assert f"qx{7:040x}" not in NodesManager.peers                # the crowd's latest arrival
    for kept in (0, 1, 2, 3):
        assert f"qx{kept:040x}" in NodesManager.peers


def test_a_table_of_protected_peers_admits_no_one(peers, monkeypatch):
    monkeypatch.setattr(nm, "MAX_PEERS_COUNT", 3)
    for i in range(3):
        _admit(i, f"192.0.2.{i}", outbound=True)
    assert not _admit(9, "192.0.9.9")


async def test_a_signed_request_does_not_make_its_caller_a_peer(me, peers, whoami, monkeypatch):
    """It used to: any signed call naming this chain's genesis was admitted, up to the limit."""
    monkeypatch.setattr(node_main, "GENESIS_BLOCK_HASH", "aa" * 32)
    dialed = []
    monkeypatch.setattr(node_peers, "_dial_back_unknown", dialed.append)
    body, headers = await _signed("authtest_whoami")
    headers["x-denaro-genesis"] = "aa" * 32
    headers["x-peer-url"] = "http://203.0.113.9:3007"
    # (the genesis header is signed: sign again with it)
    from qrdx.node.nodes_manager import NodeInterface

    headers = await NodeInterface._identity_headers(body.decode(), {"genesis": "aa" * 32})
    headers["x-peer-url"] = "http://203.0.113.9:3007"
    reply = await _call(body, headers)
    assert reply["result"] == identity.get_node_id()
    assert NodesManager.peers == {}                                # not admitted…
    assert dialed == ["http://203.0.113.9:3007"]                   # …but dialed back


async def test_the_old_signature_form_is_still_accepted(me, peers, whoami):
    """Signing the body itself, as nodes before the hash form do."""
    import time as _time

    body = json.dumps({"jsonrpc": "2.0", "method": "authtest_whoami", "id": 1},
                      separators=(",", ":"))
    now, nonce = int(_time.time()), "ab" * 16
    signature = identity.sign_message(
        identity.get_canonical_json_bytes({"body": body, "timestamp": now, "nonce": nonce}))
    headers = {"x-node-id": identity.get_node_id(), "x-public-key": identity.get_public_key_hex(),
               "x-signature": signature, "x-timestamp": str(now), "x-nonce": nonce}
    assert (await _call(body.encode(), headers))["result"] == identity.get_node_id()


async def test_a_validator_proof_is_bound_to_the_node_and_the_validator(monkeypatch):
    from qrdx import chain_index
    from qrdx.crypto.pq.dilithium import PQPrivateKey, sign
    from qrdx.rpc.modules.p2p import validator_peer_message
    from qrdx.validator import epoch_state, ffg

    key = PQPrivateKey.generate()
    address = key.public_key.to_address()

    async def _key(db, a, h):
        return key.public_key.to_bytes() if a == address else None

    async def _slot(db, h):
        return 80

    async def _members(db, epoch, tip):
        return [address]

    class _DB:
        async def get_next_block_id(self):
            return 100

    monkeypatch.setattr(node_main, "db", _DB())
    monkeypatch.setattr(ffg, "validator_key", _key)
    monkeypatch.setattr(chain_index, "slot_at", _slot)
    monkeypatch.setattr(epoch_state, "state_at", _members)
    proof = {"address": address,
             "signature": sign(key, validator_peer_message("qx" + "11" * 20)).to_bytes().hex()}
    assert await node_peers._peer_validator("qx" + "11" * 20, proof) == address
    assert await node_peers._peer_validator("qx" + "22" * 20, proof) is None   # another node
    stranger = PQPrivateKey.generate()
    forged = {"address": address,
              "signature": sign(stranger, validator_peer_message("qx" + "11" * 20)).to_bytes().hex()}
    assert await node_peers._peer_validator("qx" + "11" * 20, forged) is None  # not its key

    async def _nobody(db, epoch, tip):
        return []

    monkeypatch.setattr(epoch_state, "state_at", _nobody)
    assert await node_peers._peer_validator("qx" + "11" * 20, proof) is None   # not a validator
