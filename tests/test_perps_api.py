"""
Perps for wallets: the REST / JSON-RPC / streaming surfaces and the CLI.

* the journal — receipts for executed exchange transactions and a feed of fills, liquidations
  and funding — recorded at block commit only, rebuilt with the manager;
* the shared views every surface reports through (incl. the estimated liquidation price,
  checked against the liquidation engine itself);
* the write path: parse, the exact signing payload for foreign wallets, admission + gossip
  (a flood that terminates), stale-copy pruning in the mempool;
* exchange_* / perp_* JSON-RPC; the event hub's channels; the perps stream poller; the CLI.
"""
import asyncio
import json
from decimal import Decimal
from types import SimpleNamespace

import pytest

from qrdx import constants
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import ExchangeMempool, ExchangeOpType, ExchangeStateManager, ExchangeTransaction
from qrdx.exchange import block_processor as BP
from qrdx.exchange import views
from qrdx.exchange.submission import ExchangeSubmitter, parse_exchange_tx, signing_payload

D = Decimal
BTC = "BTC-QRDX-PERP"            # the test session quotes perps in QRDX (tests/conftest.py)
T0 = 1_700_000_000 // 3600 * 3600


class Key:
    def __init__(self):
        self.key = PQPrivateKey.generate()
        self.addr = self.key.public_key.to_address()
        self.nonce = 0

    def tx(self, op, params, nonce=None):
        t = ExchangeTransaction(op_type=op, sender=self.addr,
                                nonce=self.nonce if nonce is None else nonce, params=params,
                                gas_limit=2_000_000, gas_price=10**9)
        t.public_key = self.key.public_key.to_bytes()
        t.signature = self.key.sign(t.signing_bytes()).to_bytes()
        if nonce is None:
            self.nonce += 1
        return t


@pytest.fixture
def ex(monkeypatch):
    rep = Key()
    monkeypatch.setattr(constants, "ORACLE_REPORTERS", (rep.addr,))
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    yield mgr, rep
    ExchangeStateManager.reset_instance()


def _block(mgr, height, txs, ts=None):
    ok, err, _ = BP.process_exchange_transactions(height, float(ts or T0 + 2 * height), txs, mgr)
    assert ok, err
    mgr.commit_block()
    return list(mgr._block_results)


def _market(mgr, rep, *traders, price="30000", deposit="100000"):
    _block(mgr, 1, [rep.tx(ExchangeOpType.CREATE_MARKET, {"base_token": "BTC"}),
                    rep.tx(ExchangeOpType.UPDATE_ORACLE, {"pair": "BTC:QRDX", "price": price})]
           + [t.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": deposit}) for t in traders])


def _order(who, side, size, price, nonce=None, **extra):
    return who.tx(ExchangeOpType.PERP_ORDER, {"market_id": BTC, "side": side, "size": str(size),
                                               "price": str(price), **extra}, nonce=nonce)


# ── the journal ────────────────────────────────────────────────────────────

def test_receipts_and_fills_are_journaled_at_commit(ex):
    mgr, rep = ex
    alice, bob = Key(), Key()
    _market(mgr, rep, alice, bob, deposit="10000")
    sell, buy = _order(bob, "sell", 1, 30000), _order(alice, "buy", 1, 30000)
    too_big = _order(alice, "buy", 100, 30000)
    _block(mgr, 2, [sell, buy, too_big])

    r = views.receipt(mgr, buy.tx_hash())
    assert r["success"] and r["block_height"] == 2 and r["op"] == "PERP_ORDER"
    assert r["data"]["fills"][0]["price"] == "30000"
    assert views.receipt(mgr, "0x" + buy.tx_hash()) == r
    bad = views.receipt(mgr, too_big.tx_hash())
    assert not bad["success"] and "margin" in bad["error"]

    fills = views.trades(mgr, BTC)
    assert [(f["buyer"], f["seller"], f["amount"], f["taker"], f["maker"], f["liquidation"])
            for f in fills] == [(alice.addr, bob.addr, "1", alice.addr, bob.addr, False)]
    assert views.events(mgr, address=bob.addr)["events"] == fills
    assert views.events(mgr, since=fills[-1]["seq"])["events"] == []


def test_a_reverted_block_leaves_nothing_and_a_double_commit_records_once(ex):
    mgr, rep = ex
    alice, bob = Key(), Key()
    _market(mgr, rep, alice, bob)
    seq = mgr.journal.seq
    tx = _order(bob, "sell", 1, 30000)
    mgr.take_snapshot()
    mgr.begin_block(2, float(T0 + 4))
    assert mgr.process_transaction(tx).success
    mgr.revert_block()
    assert views.receipt(mgr, tx.tx_hash()) is None and mgr.journal.seq == seq

    _block(mgr, 2, [_order(bob, "sell", 1, 30000, nonce=1), _order(alice, "buy", 1, 30000)])
    mgr.commit_block()                                    # again, for the same block
    assert len(views.trades(mgr, BTC)) == 1


def test_liquidations_and_funding_are_journaled(ex, monkeypatch):
    mgr, rep = ex
    monkeypatch.setattr(constants, "PERP_FUNDING_INTERVAL_SECONDS", 60)
    alice, bob, carol = Key(), Key(), Key()
    _market(mgr, rep, bob, carol, deposit="1000000")
    _block(mgr, 2, [alice.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "3500"}),
                    _order(bob, "sell", 1, 30000), _order(alice, "buy", 1, 30000),
                    _order(carol, "buy", 1, 26900)])
    _block(mgr, 3, [rep.tx(ExchangeOpType.UPDATE_ORACLE, {"pair": "BTC:QRDX", "price": "27000"})],
           ts=T0 + 120)
    kinds = [(e["type"], e.get("liquidation")) for e in views.events(mgr)["events"]]
    assert ("liquidation", None) in kinds and ("fill", True) in kinds and ("funding", None) in kinds
    liq = views.events(mgr, types=["liquidation"])["events"][0]
    assert liq["owner"] == alice.addr and liq["market"] == BTC and liq["stage"] == "book"
    assert views.events(mgr, address=alice.addr, types=["fill"])["events"][-1]["seller"] == alice.addr


# ── views ──────────────────────────────────────────────────────────────────

def test_views_describe_markets_books_orders_and_the_vault(ex):
    mgr, rep = ex
    alice, bob = Key(), Key()
    _market(mgr, rep, alice, bob)
    _block(mgr, 2, [_order(alice, "buy", 2, 29900), _order(bob, "sell", 1, 30100)])
    (summary,) = views.markets(mgr)
    assert summary["market_id"] == BTC and summary["best_bid"] == "29900"
    assert summary["best_ask"] == "30100" and views.market(mgr, "nope") is None
    book = views.order_book(mgr, BTC, depth=5)
    assert book["bids"] == [["29900", "2"]] and book["asks"] == [["30100", "1"]]
    (order,) = views.open_orders(mgr, alice.addr.lower())          # any casing
    assert order["side"] == "buy" and order["remaining"] == "2" and not order["reduce_only"]
    acct = views.account(mgr, alice.addr)
    assert acct["orders"] == [order] and D(acct["open_order_margin"]) > 0
    assert D(views.vault(mgr)["nav"]) == 0 and views.vault(mgr)["share_value"] is None


def _liq(mgr, addr):
    return D(views.account(mgr, addr)["positions"][BTC]["liquidation_price"])


def test_the_estimated_liquidation_price_is_where_liquidation_starts(ex):
    mgr, rep = ex
    alice, bob, carol = Key(), Key(), Key()
    _market(mgr, rep, bob, carol, deposit="1000000")
    _block(mgr, 2, [alice.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "3500"}),
                    _order(bob, "sell", 1, 30000), _order(alice, "buy", 1, 30000),
                    _order(carol, "buy", 1, 27000)])            # a bid to close into
    liq = _liq(mgr, alice.addr)
    assert abs(liq - D(26515) / D("0.975")) < D("0.01")        # (30000 − 3485) / (1 − 2.5 %)
    above = (liq + 1).quantize(D(1))
    _block(mgr, 3, [rep.tx(ExchangeOpType.UPDATE_ORACLE, {"pair": "BTC:QRDX", "price": str(above)})])
    assert BTC in views.account(mgr, alice.addr)["positions"], "liquidated above the estimate"
    below = (liq - 1).quantize(D(1))
    _block(mgr, 4, [rep.tx(ExchangeOpType.UPDATE_ORACLE, {"pair": "BTC:QRDX", "price": str(below)})])
    assert BTC not in views.account(mgr, alice.addr)["positions"], "not liquidated below it"


def test_an_isolated_positions_liquidation_price(ex):
    mgr, rep = ex
    alice, bob = Key(), Key()
    _market(mgr, rep, alice, bob, deposit="10000")
    _block(mgr, 2, [alice.tx(ExchangeOpType.PERP_SET_LEVERAGE,
                             {"market_id": BTC, "leverage": "10", "mode": "isolated"}),
                    _order(bob, "sell", 1, 30000), _order(alice, "buy", 1, 30000)])
    assert abs(_liq(mgr, alice.addr) - D(27000) / D("0.975")) < D("0.01")


# ── the write path ─────────────────────────────────────────────────────────

async def test_a_foreign_wallet_signs_the_served_payload_and_submits_json():
    key = Key()
    payload = signing_payload({"op_type": "PERP_DEPOSIT", "sender": key.addr, "nonce": 0,
                               "params": {"amount": "5"}})
    signature = key.key.sign(bytes.fromhex(payload["signing_bytes"])).to_bytes().hex()
    tx = dict(payload["tx"], signature="0x" + signature,
              public_key=key.key.public_key.to_bytes().hex())
    parsed = parse_exchange_tx(tx)
    assert parsed.verify() and parsed.tx_hash() == payload["tx_hash"]

    forwarded = []

    async def forward(url, tx_dict):
        forwarded.append(url)

    pool = ExchangeMempool(nonce_provider=lambda a: 0)
    sub = ExchangeSubmitter(lambda: pool, lambda: ["http://peer-a", "http://peer-b"], forward)
    ok, err, tx_hash = await sub.submit(json.dumps(tx))
    await asyncio.sleep(0.01)
    assert ok and tx_hash == payload["tx_hash"] and forwarded == ["http://peer-a", "http://peer-b"]
    again = await sub.submit(tx)                          # idempotent, not gossiped again
    await asyncio.sleep(0.01)
    assert again == (True, "", tx_hash) and len(forwarded) == 2
    tampered = await sub.submit(dict(tx, nonce=1))
    assert not tampered[0] and tampered[2] is None


async def test_gossip_floods_a_mesh_once_and_stops():
    nodes = {}

    async def forward_from(origin):
        async def forward(url, tx_dict):
            await nodes[url].submit(tx_dict, propagated=True)
        return forward

    pools = {n: ExchangeMempool(nonce_provider=lambda a: 0) for n in "abc"}
    for n in "abc":
        nodes[n] = ExchangeSubmitter(lambda n=n: pools[n],
                                     lambda n=n: [m for m in "abc" if m != n],
                                     await forward_from(n))
    tx = Key().tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "1"})
    assert (await nodes["a"].submit(tx))[0]
    for _ in range(20):
        await asyncio.sleep(0.01)
    assert all(pools[n].contains(tx.tx_hash()) and pools[n].size() == 1 for n in "abc")


def test_the_mempool_drops_copies_whose_nonce_was_consumed():
    nonces = {}
    a, b = Key(), Key()
    pool = ExchangeMempool(nonce_provider=lambda s: nonces.get(s, 0), max_size=3, max_per_sender=2)
    assert pool.admit(a.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "1"}))[0]
    assert pool.admit(a.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "1"}))[0]
    nonces[a.addr] = 2                                    # another validator included both
    assert pool.admit(a.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "1"}))[0], "sender locked out"
    assert pool.size() == 1
    for _ in range(2):
        assert pool.admit(b.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "1"}))[0]
    nonces[b.addr] = 2
    c = Key()
    assert pool.admit(c.tx(ExchangeOpType.PERP_DEPOSIT, {"amount": "1"}))[0], "pool locked out"


# ── JSON-RPC ───────────────────────────────────────────────────────────────

async def test_exchange_and_perp_rpc(ex):
    from qrdx.rpc.modules.exchange import ExchangeModule, PerpModule
    from qrdx.rpc.server import RPCServer
    mgr, rep = ex
    alice, bob = Key(), Key()
    _market(mgr, rep, alice, bob)
    _block(mgr, 2, [_order(bob, "sell", 1, 30000), _order(alice, "buy", 1, 30000)])

    class Submitter:
        async def submit(self, tx, propagated=False):
            return (False, "nonce too low", None) if tx == "stale" else (True, "", "abc")

    ctx = SimpleNamespace(db=None, submitter=Submitter())
    server = RPCServer(rate_limit=False)
    server.register_module(ExchangeModule(ctx))
    server.register_module(PerpModule(ctx))

    async def call(method, *params):
        return json.loads(await server.handle_request(
            json.dumps({"jsonrpc": "2.0", "method": method, "params": list(params), "id": 1})))

    assert (await call("perp_getMarkets"))["result"][0]["market_id"] == BTC
    assert (await call("perp_getMarket", "nope"))["error"]["code"] == -32001
    assert (await call("perp_getAccount", alice.addr))["result"]["positions"][BTC]["size"] == "1"
    assert (await call("perp_getTrades", BTC, 10))["result"][0]["buyer"] == alice.addr
    assert (await call("exchange_getNonce", alice.addr))["result"] == 2
    assert (await call("exchange_sendTransaction", {"x": 1}))["result"] == "abc"
    assert (await call("exchange_sendTransaction", "stale"))["error"]["code"] == -32003
    payload = (await call("exchange_getSigningPayload", {"op_type": 18, "sender": alice.addr,
                                                          "nonce": 2, "params": {"amount": "1"}}))
    assert len(payload["result"]["tx_hash"]) == 64


# ── streams ────────────────────────────────────────────────────────────────

def test_hub_channels_and_client_frames():
    from qrdx.node.observability import (
        EventHub, event_matches, handle_client_frame, parse_channels,
    )
    hub = EventHub()
    legacy = hub.subscribe()
    trader = hub.subscribe({"perp_markets", "perp_account:0xPQabc"})
    for event in ({"type": "block", "channel": "blocks", "height": 1},
                  {"type": "perp_market", "channel": "perp_markets", "key": BTC},
                  {"type": "perp_account", "channel": "perp_account", "key": "0xPQabc"},
                  {"type": "perp_account", "channel": "perp_account", "key": "0xPQother"}):
        hub.publish_nowait(event)
    assert legacy.get_nowait()["type"] == "block" and legacy.empty()
    got = [trader.get_nowait() for _ in range(2)]
    assert [e["type"] for e in got] == ["perp_market", "perp_account"] and trader.empty()

    reply = handle_client_frame(hub, legacy, {"op": "subscribe", "channels": [f"perp_book:{BTC}"]})
    assert reply == {"type": "subscribed", "channels": ["blocks", f"perp_book:{BTC}"]}
    for bad in (["evil"], ["perp_book"], ["perp_account"], ["perp_book:<script>"]):
        assert handle_client_frame(hub, legacy, {"op": "subscribe", "channels": bad})["type"] == "error"
    assert handle_client_frame(hub, legacy, {"op": "unsubscribe", "channels": ["blocks"]})[
        "channels"] == [f"perp_book:{BTC}"]
    assert hub.keys("perp_account") == {"0xPQabc"}
    assert hub.wants("perp_book", BTC) and not hub.wants("perp_book", "ETH-QRDX-PERP")
    assert event_matches({"perp_events:B"}, {"channel": "perp_events", "key": "A,B"})
    assert parse_channels("blocks, perp_markets, bogus") == {"blocks", "perp_markets"}
    assert parse_channels("") is None


async def test_the_perps_poller_publishes_changes_to_subscribers(ex):
    from qrdx.exchange.stream import PerpStreamPublisher, initial_snapshots, perp_stream_poller
    from qrdx.node.observability import EventHub
    mgr, rep = ex
    alice, bob = Key(), Key()
    _market(mgr, rep, alice, bob)
    _block(mgr, 2, [_order(alice, "buy", 1, 29900)])
    hub = EventHub()
    markets_q = hub.subscribe({"perp_markets"})
    book_q = hub.subscribe({f"perp_book:{BTC}"})
    account_q = hub.subscribe({f"perp_account:{alice.addr}"})
    events_q = hub.subscribe({f"perp_events:{BTC}"})

    publisher = PerpStreamPublisher(hub)

    async def poll():
        publisher.step(ExchangeStateManager.get_instance())

    def drain(q):
        out = []
        while not q.empty():
            out.append(q.get_nowait())
        return out

    await poll()
    assert [e["key"] for e in drain(markets_q)] == [BTC]
    assert drain(book_q)[0]["book"]["bids"] == [["29900", "1"]]
    assert drain(account_q)[0]["account"]["orders"][0]["price"] == "29900"
    assert drain(events_q) == []                          # history is not replayed
    await poll()
    assert not any(drain(q) for q in (markets_q, book_q, account_q, events_q)), "no change, no event"

    _block(mgr, 3, [_order(bob, "sell", 1, 29900)])        # a fill
    await poll()
    (fill,) = drain(events_q)
    assert fill["event"]["type"] == "fill" and fill["event"]["price"] == "29900"
    assert drain(account_q)[0]["account"]["positions"][BTC]["size"] == "1"
    assert drain(book_q)[0]["book"]["bids"] == []
    assert drain(markets_q)[0]["market"]["last_trade_price"] == "29900"

    ExchangeStateManager.reset_instance()                 # a rebuild: a new journal
    rebuilt = ExchangeStateManager.get_instance()
    rebuilt.journal.seq = 99
    await poll()
    assert drain(events_q) == []

    await perp_stream_poller(hub, get_manager=lambda: mgr, interval=0, _max_iterations=2)
    assert [e["key"] for e in drain(markets_q)] == [BTC], "the loop publishes once per change"

    snaps = initial_snapshots(mgr, {"perp_markets", f"perp_book:{BTC}", f"perp_account:{alice.addr}"})
    assert {s["type"] for s in snaps} == {"perp_market", "perp_book", "perp_account"}
    assert all(s["snapshot"] for s in snaps)


# ── the CLI wallet ─────────────────────────────────────────────────────────

def test_the_cli_signs_and_submits_an_order(monkeypatch, tmp_path):
    from click.testing import CliRunner
    from qrdx.cli import perp as P
    from qrdx.wallet_v2 import PQWallet
    wallet = PQWallet(private_key=PQPrivateKey.generate())
    calls = []

    def fake_rpc(node, method, params=None, timeout=20.0):

        if method == "p2p_getStatus":      # the CLI signs for the node's network

            from qrdx.constants import CHAIN_ID

            return {"network": {"chain_id": CHAIN_ID}}
        calls.append((method, params))
        if method == "exchange_getNonce":
            return 7
        if method == "exchange_sendTransaction":
            return parse_exchange_tx(params[0]).tx_hash()
        if method == "perp_getAccount":
            return {"withdrawable": "123.5"}
        raise AssertionError(method)

    monkeypatch.setattr(P, "rpc", fake_rpc)
    monkeypatch.setattr(P, "_signer", lambda wallet_file: wallet)
    wallet_file = tmp_path / "w.json"
    wallet_file.write_text("{}")
    result = CliRunner().invoke(P.perp, ["order", str(wallet_file), "BTC-USD-PERP", "buy", "0.5",
                                         "65000", "--ioc", "--yes"])
    assert result.exit_code == 0, result.output
    sent = parse_exchange_tx(calls[-1][1][0])
    assert sent.verify() and sent.sender == wallet.address and sent.nonce == 7
    assert sent.op_type == ExchangeOpType.PERP_ORDER
    assert sent.params == {"market_id": "BTC-USD-PERP", "side": "buy", "size": "0.5",
                           "price": "65000", "tif": "ioc"}

    result = CliRunner().invoke(P.perp, ["withdraw", str(wallet_file), "all", "--yes"])
    assert result.exit_code == 0, result.output
    sent = parse_exchange_tx(calls[-1][1][0])
    assert sent.op_type == ExchangeOpType.PERP_WITHDRAW and sent.params == {"amount": "123.5"}


def test_the_node_serves_all_of_it():
    """Every surface is wired in the node: REST routes, always-on RPC modules, the stream."""
    import inspect
    from qrdx.node import main
    paths = {getattr(r, "path", None) for r in main.app.routes}
    for path in ("/submit_exchange_tx", "/exchange_signing_payload", "/get_exchange_receipt",
                 "/get_exchange_nonce", "/get_perp_account", "/get_perp_orders",
                 "/get_perp_markets", "/get_perp_market", "/get_perp_orderbook",
                 "/get_perp_vault", "/get_perp_trades", "/get_perp_events", "/ws", "/stream"):
        assert path in paths, path
    methods = main.rpc_server.get_methods()
    for name in ("exchange_sendTransaction", "exchange_getTransactionReceipt",
                 "exchange_getSigningPayload", "perp_getMarkets", "perp_getAccount",
                 "perp_getOrderBook", "perp_getEvents"):
        assert name in methods, name
    assert "handle_client_frame(EVENT_HUB, q, frame)" in inspect.getsource(main.ws_stream)
