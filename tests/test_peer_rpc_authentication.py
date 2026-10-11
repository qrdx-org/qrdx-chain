"""
Peer RPC authentication (docs/KNOWN_ISSUES.md: "The peer RPC transport was unauthenticated").

What must hold:
  * a node signs every JSON-RPC call it makes to a peer, over the exact bytes it sends;
  * a node id is believed only when it is the presented key's (BLAKE3 of it) — a valid
    signature proves the key, not a claimed id;
  * the calls that hand a node data to act on, or establish who a peer is, are refused
    unsigned; a forged, tampered or replayed signature is refused on any call; reads stay open;
  * the verified caller reaches the RPC method (rpc_caller); a sender a payload merely names
    does not;
  * the handshake is mutual: a challenge is answerable only by the node it was issued to, and
    the answering node proves its identity by signing the caller's nonce with every claim it
    makes, on this network only.
"""
import json

import httpx
import oqs
import pytest
from starlette.requests import Request

from qrdx import chain_spec
from qrdx.node import identity
from qrdx.node import main as node_main
from qrdx.node.nodes_manager import NodeInterface, NodesManager
from qrdx.rpc.modules.p2p import handshake_proof_message, verify_handshake_proof
from qrdx.rpc.server import RPCModule, rpc_caller, rpc_method


def _keypair():
    signer = oqs.Signature(identity.PQ_ALGORITHM)
    public = signer.generate_keypair()
    return public, signer.export_secret_key()


@pytest.fixture
def me(monkeypatch):
    """This process as a node with a fresh identity."""
    public, secret = _keypair()
    monkeypatch.setattr(identity, "_public_key", public)
    monkeypatch.setattr(identity, "_secret_key", secret)
    monkeypatch.setattr(identity, "_node_id", identity._derive_node_id(public))
    return identity._derive_node_id(public)


@pytest.fixture
def peers(monkeypatch, tmp_path):
    monkeypatch.setattr(NodesManager, "peers", {})
    monkeypatch.setattr(NodesManager, "db_path", str(tmp_path / "nodes.json"))
    monkeypatch.setattr(NodeInterface, "network_identity_provider", None)


class _WhoAmI(RPCModule):
    namespace = "authtest"

    @rpc_method
    async def whoami(self):
        return rpc_caller.get()


@pytest.fixture
def whoami():
    node_main.rpc_server.register_module(_WhoAmI())
    yield
    node_main.rpc_server.unregister_module("authtest")


def _request(body: bytes, headers: dict) -> Request:
    scope = {"type": "http", "method": "POST", "path": "/rpc", "query_string": b"",
             "headers": [(k.lower().encode(), str(v).encode()) for k, v in headers.items()],
             "client": ("127.0.0.1", 40000), "server": ("test", 80), "scheme": "http",
             "root_path": ""}

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


async def _signed(method, params=None):
    """(body, headers) exactly as NodeInterface._rpc_call sends them."""
    payload = {"jsonrpc": "2.0", "method": method, "id": 1}
    if params is not None:
        payload["params"] = params
    body = json.dumps(payload, separators=(",", ":"))
    headers = await NodeInterface("http://peer.invalid", client=None, db=None)._identity_headers(body)
    return body.encode(), headers


async def _call(body: bytes, headers: dict) -> dict:
    resp = await node_main.rpc_endpoint(_request(body, headers))
    return json.loads(resp.body)


def _is_auth_refusal(reply: dict) -> bool:
    return (reply.get("error") or {}).get("code") == -32099


# ── the endpoint ────────────────────────────────────────────────────────────────────────

async def test_a_signed_call_reaches_the_method_as_the_verified_node(me, peers, whoami):
    reply = await _call(*await _signed("authtest_whoami"))
    assert reply["result"] == me


async def test_an_unsigned_read_is_served_anonymously(peers, whoami):
    body = json.dumps({"jsonrpc": "2.0", "method": "authtest_whoami", "id": 1}).encode()
    reply = await _call(body, {"content-type": "application/json"})
    assert "error" not in reply and reply["result"] is None


PEER_ONLY = ["p2p_handshakeChallenge", "p2p_handshakeResponse", "p2p_pushAttestation",
             "p2p_pushTx", "p2p_submitBlock", "p2p_submitBlocks"]


def test_the_peer_only_methods_are_exactly_these():
    assert node_main.rpc_server.peer_only_methods() == PEER_ONLY


@pytest.mark.parametrize("method", PEER_ONLY)
async def test_peer_only_methods_are_refused_unsigned(peers, method):
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": [], "id": 7}).encode()
    reply = await _call(body, {})
    assert _is_auth_refusal(reply) and reply["id"] == 7


async def test_the_rpc_server_itself_refuses_peer_only_methods_without_a_caller():
    """Whatever transport hands it a request — not only the HTTP endpoint."""
    reply = json.loads(await node_main.rpc_server.handle_request(
        {"jsonrpc": "2.0", "method": "p2p_submitBlock", "params": [{}], "id": 3}))
    assert _is_auth_refusal(reply)


async def test_a_tampered_body_is_refused(me, peers, whoami):
    body, headers = await _signed("authtest_whoami")
    reply = await _call(body.replace(b'"id":1', b'"id":2'), headers)
    assert _is_auth_refusal(reply)


async def test_a_replayed_request_is_refused(me, peers, whoami):
    body, headers = await _signed("authtest_whoami")
    assert (await _call(body, headers))["result"] == me
    assert _is_auth_refusal(await _call(body, headers))


async def test_a_claimed_node_id_that_is_not_the_keys_is_refused(me, peers, whoami):
    """Signing with your own key while claiming another node's id was accepted before."""
    body, headers = await _signed("authtest_whoami")
    other_public, _ = _keypair()
    headers["x-node-id"] = identity._derive_node_id(other_public)
    assert _is_auth_refusal(await _call(body, headers))


async def test_a_peer_only_call_with_a_valid_signature_gets_past_authentication(me, peers):
    # The P2P module is not wired in this unit test, so the call fails later — but not on auth.
    reply = await _call(*await _signed("p2p_pushAttestation", [{}]))
    assert not _is_auth_refusal(reply)


# ── the client side ─────────────────────────────────────────────────────────────────────

async def test_the_client_signs_the_exact_bytes_it_sends(me, peers):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"], seen["headers"] = request.content, dict(request.headers)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await NodeInterface("http://peer.invalid", client=client, db=None)._rpc_call("p2p_getStatus")
    h = seen["headers"]
    assert h["x-node-id"] == me and identity.node_id_for_public_key(h["x-public-key"]) == me
    signed = identity.get_canonical_json_bytes(
        {"body": seen["body"].decode(), "timestamp": int(h["x-timestamp"]), "nonce": h["x-nonce"]})
    assert identity.verify_signature(h["x-public-key"], h["x-signature"], signed)


# ── the handshake ───────────────────────────────────────────────────────────────────────

async def test_a_challenge_is_answerable_only_by_the_node_it_was_issued_to():
    mgr = node_main.HandshakeChallengeManager()
    challenge = await mgr.create_challenge(issued_to="qxalice")
    assert not await mgr.verify_and_consume_challenge(challenge, "qxmallory")
    assert not await mgr.verify_and_consume_challenge(challenge, None)
    assert await mgr.verify_and_consume_challenge(challenge, "qxalice")
    assert not await mgr.verify_and_consume_challenge(challenge, "qxalice")   # consumed


def _answer(me_id, client_nonce, **overrides):
    result = {"challenge": "c" * 64, "node_id": me_id, "pubkey": identity.get_public_key_hex(),
              "url": "http://node.example:3007", "network": {"chain_id": 7620}}
    result["proof"] = identity.sign_message(handshake_proof_message(client_nonce, result))
    result.update(overrides)
    return result


def test_a_genuine_identity_proof_verifies(me):
    nonce = "ab" * 32
    assert verify_handshake_proof(nonce, _answer(me, nonce)) is None


@pytest.mark.parametrize("claim", ["challenge", "node_id", "url", "network"])
def test_altering_any_claim_breaks_the_proof(me, claim):
    nonce = "ab" * 32
    forged = {"challenge": "d" * 64, "node_id": "qx" + "0" * 40,
              "url": "http://evil.example:3007", "network": {"chain_id": 762}}[claim]
    assert verify_handshake_proof(nonce, _answer(me, nonce, **{claim: forged})) is not None


def test_a_proof_is_bound_to_the_callers_nonce(me):
    assert verify_handshake_proof("cd" * 32, _answer(me, "ab" * 32)) == "identity proof does not verify"


def test_another_nodes_key_cannot_stand_behind_a_claimed_id(me):
    nonce = "ab" * 32
    other_public, _ = _keypair()
    answer = _answer(me, nonce, pubkey=other_public.hex())
    assert verify_handshake_proof(nonce, answer) == "node id is not the presented key's"


def test_a_proof_made_on_another_network_is_worthless_here(me, monkeypatch):
    nonce = "ab" * 32
    answer = _answer(me, nonce)
    mainnet = chain_spec.build_spec("qrdx-mainnet", 762, {})
    monkeypatch.setattr(chain_spec, "active", lambda: mainnet)
    assert verify_handshake_proof(nonce, answer) == "identity proof does not verify"
