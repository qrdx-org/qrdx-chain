"""
A flood cannot take the node's peers' share of its RPC budget (docs/KNOWN_ISSUES.md, "A flood from
one address throttled a node's peers").

The limiter took a request's global token before its client's: one IP far past its own limit
still drained the global budget, and the node's peers (blocks, votes, transactions) were refused
with everyone else. Found by the flood of integration_tests/adversarial.py, in which blocks fell
from 2.9 to 1.8 a second.
"""

from qrdx.rpc.server import RPCRateLimiter


async def test_a_client_past_its_limit_takes_nothing_from_the_others():
    rl = RPCRateLimiter(per_client_rps=5, global_rps=20, burst_multiplier=1.0)
    allowed = sum([await rl.check("10.0.0.1") for _ in range(1000)])
    assert allowed == 5                                   # its own limit
    assert all([await rl.check(f"10.0.1.{i}") for i in range(15)])  # the rest of the budget


async def test_public_traffic_cannot_spend_the_peers_pool():
    rl = RPCRateLimiter(per_client_rps=5, global_rps=20, burst_multiplier=1.0)
    for i in range(100):                                  # many addresses, the public pool spent
        for _ in range(5):
            await rl.check(f"10.0.{i}.1")
    assert not await rl.check("10.9.9.9")
    assert await rl.check("qx-peer-a", peer=True)         # a peer still gets through
    assert await rl.check("qx-peer-b", peer=True)


def test_a_signed_caller_that_is_not_a_peer_is_limited_by_its_address():
    """A fresh key per request would otherwise be a fresh limit."""
    import inspect

    from qrdx.node import main

    src = inspect.getsource(main.rpc_endpoint)
    assert "client_id=peer_id or ip" in src
    assert "NodesManager.get_peer(caller)" in src


async def test_a_batch_costs_a_call_each_and_is_capped():
    """A batch used to cost one request whatever it held, and could hold any number of calls,
    all run at once: one request past every limit."""
    import json

    from qrdx.rpc.server import MAX_BATCH_SIZE, RPCServer

    server = RPCServer(per_client_rps=10, global_rps=1000)
    calls = lambda n: json.dumps(  # noqa: E731
        [{"jsonrpc": "2.0", "id": i, "method": "rpc_modules", "params": []} for i in range(n)])
    too_big = json.loads(await server.handle_request(calls(MAX_BATCH_SIZE + 1), client_id="a"))
    assert "at most" in too_big["error"]["message"]
    first = json.loads(await server.handle_request(calls(15), client_id="b"))
    assert isinstance(first, list) and len(first) == 15        # 15 of its 20-token burst
    second = json.loads(await server.handle_request(calls(15), client_id="b"))
    assert second["error"]["message"] == "Rate limit exceeded"  # 15 more do not fit


async def test_gossip_goes_to_each_peer_in_one_batch():
    """One request a transaction a peer kept a loaded node's event loop busy enough that its
    blocks reached peers late (integration_tests/load.py)."""
    import asyncio
    from decimal import Decimal

    from test_exchange_inclusion import Op, _Key

    from qrdx.exchange import ExchangeStateManager
    from qrdx.exchange.mempool import ExchangeMempool
    from qrdx.exchange.submission import ExchangeSubmitter

    ExchangeStateManager.reset_instance()
    try:
        keys = [_Key() for _ in range(5)]
        sent = []

        async def balance(address):
            return Decimal(1)

        async def forward(url, tx_dict):
            raise AssertionError("gossiped one at a time")

        async def forward_batch(url, txs):
            sent.append((url, len(txs)))

        pool = ExchangeMempool(nonce_provider=lambda lane: 0)
        sub = ExchangeSubmitter(lambda: pool, lambda: ["http://a", "http://b"], forward,
                                get_balance=balance, forward_batch=forward_batch,
                                gossip_interval=0.01)
        for k in keys:
            ok, err, _ = await sub.submit(k.signed(Op.CANCEL_ALL, {}))
            assert ok, err
        await asyncio.sleep(0.1)
        assert sorted(sent) == [("http://a", 5), ("http://b", 5)]
    finally:
        ExchangeStateManager.reset_instance()


async def test_a_peer_has_a_peers_limit_not_the_publics():
    """A peer was held to the public per-address limit (50 a second): peers gossip every
    transaction to each other, so from about 50 transactions a second its gossip was refused,
    and with it its blocks and votes. Found by integration_tests/load.py (docs/PERFORMANCE.md)."""
    rl = RPCRateLimiter(per_client_rps=5, global_rps=20, burst_multiplier=1.0, peer_rps=1000,
                        per_peer_rps=200)
    assert sum([await rl.check("qx-peer-a", peer=True) for _ in range(300)]) == 200
    assert sum([await rl.check("10.0.0.1") for _ in range(300)]) == 5        # the public's limit
    assert sum([await rl.check("qx-peer-b", peer=True, cost=50) for _ in range(10)]) == 4


def test_the_node_sizes_the_peers_limits_for_gossip():
    from qrdx.node import main

    rl = main.rpc_server._rate_limiter
    assert rl.per_peer_rps >= 4000 and rl.peer_rps >= 4 * rl.per_peer_rps
    assert rl.per_client_rps < rl.per_peer_rps


def test_json_rpc_skips_the_http_middleware_and_keeps_what_it_did():
    """POST /rpc goes straight to the handler (main._FastRPC, the outermost layer): the two
    request middlewares cost a loaded node more than a gossip batch's own admission."""
    from fastapi.testclient import TestClient

    from qrdx.node import main

    assert main.app.user_middleware[0].cls is main._FastRPC
    client = TestClient(main.app)
    r = client.post("/rpc", json={"jsonrpc": "2.0", "id": 1, "method": "nope_nothing", "params": []},
                    headers={"Origin": "https://wallet.example"})
    assert r.status_code == 200 and r.json()["error"]["code"] == -32601
    assert r.headers["access-control-allow-origin"] == "*"
    r = client.post("/rpc", content=b"{not json")
    assert r.json()["error"]["code"] == -32700


def test_a_proposer_sizes_its_blocks_to_its_share_of_the_slot():
    from qrdx.validator import node_integration as NI

    node = NI.ValidatorNode.__new__(NI.ValidatorNode)
    node._exchange_limit = 500
    budget = NI.SLOT_DURATION_SECONDS * NI.EXCHANGE_BUILD_SHARE
    node._measure_exchange(500, budget / 2)                 # full and fast: grow
    assert node._exchange_limit == 626
    node._measure_exchange(100, budget / 2)                 # not full: no evidence to grow
    assert node._exchange_limit == 626
    node._measure_exchange(626, budget * 4)                 # far over: at most halved
    assert node._exchange_limit == 313
    for _ in range(20):
        node._measure_exchange(node._exchange_limit, budget * 10)
    assert node._exchange_limit == NI.EXCHANGE_BUILD_MIN
