"""
Spot for wallets: the read views every surface reports through — AMM pools, liquidity
positions, swap quotes, spot order books — and their REST routes and exchange_* JSON-RPC.

The views are exact, not estimates: a position's value is what removing it pays and a quote is
what the swap gets, to the last unit, and reading either changes nothing.
"""
import json
from decimal import Decimal
from types import SimpleNamespace

import pytest

from qrdx.exchange import ExchangeOpType, ExchangeStateManager, ExchangeTransaction, views

D = Decimal
ALICE, BOB, CAROL = ("0xPQ" + c * 64 for c in "abc")
T0, T1 = "0x" + "11" * 20, "0x" + "22" * 20       # T0 < T1: token0, and the book's base

_nonces = {}


def _tx(sender, op, params):
    n = _nonces.get(sender, 0)
    _nonces[sender] = n + 1
    return ExchangeTransaction(op_type=op, sender=sender, nonce=n, params=params,
                               gas_limit=10_000_000, gas_price=10**9)


@pytest.fixture
def mgr():
    _nonces.clear()
    ExchangeStateManager.reset_instance()
    m = ExchangeStateManager.get_instance()
    m.enforce_spot_settlement = True
    m.enforce_orderbook_settlement = True
    for who in (ALICE, BOB, CAROL):
        m.set_available_balance(who, D(10_000_000))
        for t in (T0, T1):
            m.set_available_token_balance(who, t, D(100_000_000))
    m.begin_block(1, 1_700_000_000.0)
    yield m
    ExchangeStateManager.reset_instance()


def _pool(m, lo=-6000, hi=6000, liquidity="1000000"):
    r = m.process_transaction(_tx(ALICE, ExchangeOpType.CREATE_POOL, {
        "token0": T0, "token1": T1, "fee_tier": 3000, "pool_type": "STANDARD",
        "initial_price": "1", "stake_amount": "10000"}))
    assert r.success, r.error
    pid = r.data["pool_id"]
    for t in (T0, T1):
        m.set_available_token_balance(m.pool_holder_address(pid), t, D(0))
        m.set_available_token_balance(m.orderbook_escrow_address(f"{T0}:{T1}"), t, D(0))
    add = m.process_transaction(_tx(ALICE, ExchangeOpType.ADD_LIQUIDITY, {
        "pool_id": pid, "tick_lower": lo, "tick_upper": hi, "amount": liquidity}))
    assert add.success, add.error
    return pid, add.data["position_id"]


def _swap(m, who, token_in, token_out, amount, **extra):
    return m.process_transaction(_tx(who, ExchangeOpType.SWAP, {
        "token_in": token_in, "token_out": token_out, "amount_in": amount, **extra}))


def test_pools_and_one_pool_with_its_ticks_and_positions(mgr):
    pid, pos = _pool(mgr)
    listed = views.pools(mgr)
    assert [p["pool_id"] for p in listed] == [pid]
    assert [p["pool_id"] for p in views.pools(mgr, T1, T0)] == [pid]      # either order
    assert listed[0]["holder_address"] == mgr.pool_holder_address(pid)
    assert D(listed[0]["price"]) == 1 and listed[0]["tick_spacing"] == 60
    detail = views.pool(mgr, pid)
    assert [(t["tick"], t["liquidity_net"]) for t in detail["ticks"]] == [
        (-6000, "1000000"), (6000, "-1000000")]
    assert [p["position_id"] for p in detail["position_list"]] == [pos]
    assert views.pool(mgr, "nope") is None


@pytest.mark.parametrize("lo,hi", [(-1200, 1200), (600, 3000), (-3000, -600)])  # in / above / below
def test_a_liquidity_quote_is_the_most_the_amounts_buy_and_what_the_deposit_costs(mgr, lo, hi):
    pid, _ = _pool(mgr)
    q = views.liquidity_quote(mgr, pid, lo, hi, amount0="1234.5", amount1="987.65")
    L, cost = D(q["liquidity"]), (D(q["amount0"]), D(q["amount1"]))
    assert L > 0 and cost[0] <= D("1234.5") and cost[1] <= D("987.65")
    pool = mgr.pool_manager.get_pool(pid)
    more = pool.amounts_for_liquidity(lo, hi, L * (1 + D("1e-12")), round_up=True)
    assert more[0] > D("1234.5") or more[1] > D("987.65")         # the most they buy
    assert views.liquidity_quote(mgr, pid, lo, hi, liquidity=q["liquidity"])["amount0"] == q["amount0"]
    before = {t: mgr.available_token_balance(BOB, t) for t in (T0, T1)}
    r = mgr.process_transaction(_tx(BOB, ExchangeOpType.ADD_LIQUIDITY, {
        "pool_id": pid, "tick_lower": lo, "tick_upper": hi, "amount": q["liquidity"]}))
    assert r.success, r.error
    assert (before[T0] - mgr.available_token_balance(BOB, T0),
            before[T1] - mgr.available_token_balance(BOB, T1)) == cost
    with pytest.raises(ValueError):
        views.liquidity_quote(mgr, pid, lo, hi + 1, liquidity="1")    # off the tick spacing
    with pytest.raises(ValueError):
        views.liquidity_quote(mgr, pid, lo, hi)


def test_a_positions_value_is_exactly_what_removing_it_pays(mgr):
    pid, pos = _pool(mgr)
    for i in range(4):
        a, b = (T0, T1) if i % 2 == 0 else (T1, T0)
        assert _swap(mgr, BOB, a, b, "500").success
    [view] = views.positions(mgr, ALICE.lower())              # any casing
    assert view["position_id"] == pos and view["in_range"]
    assert D(view["fees0"]) > 0 and D(view["fees1"]) > 0
    r = mgr.process_transaction(_tx(ALICE, ExchangeOpType.REMOVE_LIQUIDITY,
                                    {"pool_id": pid, "position_id": pos}))
    assert r.success, r.error
    assert D(r.data["amount0"]) == D(view["amount0"]) + D(view["fees0"])
    assert D(r.data["amount1"]) == D(view["amount1"]) + D(view["fees1"])
    assert views.positions(mgr, ALICE) == []


def test_a_quote_is_exactly_what_the_swap_gets_and_changes_nothing(mgr):
    pid, _ = _pool(mgr)
    pool = mgr.pool_manager.get_pool(pid)
    digest = pool.state_digest()
    q = views.quote(mgr, T0, T1, "250", BOB)
    assert pool.state_digest() == digest
    assert q["source"] == "amm" and q["pool_id"] == pid and D(q["unfilled_in"]) == 0
    assert D(q["price_after"]) < D(q["price_before"])        # selling token0 lowers its price
    assert D(q["price_impact"]) > 0
    r = _swap(mgr, BOB, T0, T1, "250", min_amount_out=q["amount_out"])
    assert r.success, r.error
    assert r.data["amount_out"] == q["amount_out"] and r.data["fee_total"] == q["fee"]
    with pytest.raises(ValueError):
        views.quote(mgr, T0, T1, "0")
    assert views.quote(mgr, T0, "0x" + "33" * 20, "1") is None


def test_the_spot_book_open_orders_and_a_book_quote(mgr):
    _pool(mgr, lo=-60000, hi=60000, liquidity="1000")         # a thin pool
    o = mgr.process_transaction(_tx(CAROL, ExchangeOpType.PLACE_ORDER, {
        "pair": f"{T0}:{T1}", "side": "buy", "order_type": "limit", "price": "0.99",
        "amount": "50"}))
    assert o.success, o.error
    book = views.spot_order_book(mgr, f"{T1}:{T0}")           # either order
    assert book["pair"] == f"{T0}:{T1}" and book["base"] == T0
    assert [[D(p), D(a)] for p, a in book["bids"]] == [[D("0.99"), D(50)]] and book["asks"] == []
    assert book["escrow_address"] == mgr.orderbook_escrow_address(f"{T0}:{T1}")
    [mine] = views.spot_open_orders(mgr, CAROL)
    assert mine["side"] == "buy" and D(mine["remaining"]) == 50
    assert views.spot_open_orders(mgr, BOB) == []
    q = views.quote(mgr, T0, T1, "10", BOB)
    assert q["source"] == "clob" and D(q["amount_out"]) == D("9.9")
    # Carol's own bid would stop her at once (self-trade prevention), so her quote is the pool's.
    assert views.quote(mgr, T0, T1, "10", CAROL)["source"] == "amm"
    assert views.spot_order_book(mgr, f"{T0}:0x" + "44" * 20) is None


async def test_spot_rpc(mgr):
    from qrdx.rpc.modules.exchange import ExchangeModule
    from qrdx.rpc.server import RPCServer
    pid, pos = _pool(mgr)
    server = RPCServer(rate_limit=False)
    server.register_module(ExchangeModule(SimpleNamespace(db=None, submitter=None)))

    async def call(method, *params):
        return json.loads(await server.handle_request(
            json.dumps({"jsonrpc": "2.0", "method": method, "params": list(params), "id": 1})))

    assert (await call("exchange_getPools"))["result"][0]["pool_id"] == pid
    assert (await call("exchange_getPool", pid))["result"]["position_list"][0]["position_id"] == pos
    assert (await call("exchange_getPool", "nope"))["error"]["code"] == -32001
    assert (await call("exchange_getPositions", ALICE))["result"][0]["pool_id"] == pid
    lq = (await call("exchange_quoteLiquidity", pid, -600, 600, None, "10", "10"))["result"]
    assert D(lq["liquidity"]) > 0 and D(lq["amount0"]) <= 10
    assert (await call("exchange_quoteLiquidity", pid, -600, 601, "1"))["error"]["code"] == -32602
    quote = (await call("exchange_quoteSwap", T1, T0, "100", BOB))["result"]
    assert quote["source"] == "amm" and D(quote["amount_out"]) > 0
    assert (await call("exchange_quoteSwap", T1, T0, "-1"))["error"]["code"] == -32602
    assert (await call("exchange_quoteSwap", T1, "0x" + "33" * 20, "1"))["error"]["code"] == -32001
    assert (await call("exchange_getOrderBook", f"{T0}:{T1}"))["result"]["bids"] == []
    assert (await call("exchange_getOpenOrders", CAROL))["result"] == []


def test_the_node_serves_the_spot_views():
    from qrdx.node import main
    paths = {getattr(r, "path", None) for r in main.app.routes}
    for path in ("/get_pools", "/get_pool", "/get_lp_positions", "/get_swap_quote",
                 "/get_liquidity_quote",
                 "/get_spot_orderbook", "/get_spot_orders"):
        assert path in paths, path
    methods = main.rpc_server.get_methods()
    for name in ("exchange_getPools", "exchange_getPool", "exchange_getPositions",
                 "exchange_quoteLiquidity",
                 "exchange_quoteSwap", "exchange_getOrderBook", "exchange_getOpenOrders"):
        assert name in methods, name


# ── streams ────────────────────────────────────────────────────────────────

def test_spot_and_token_channels_publish_changes(mgr):
    from qrdx.exchange.stream import ExchangeStreamPublisher, initial_snapshots
    from qrdx.node.observability import (EventHub, canonical_channel, handle_client_frame,
                                         valid_channel)
    pid, pos = _pool(mgr)
    r = mgr.process_transaction(_tx(ALICE, ExchangeOpType.TOKEN_DEPLOY, {
        "name": "Spot", "symbol": "SPT", "total_supply": "10"}))
    token = r.data["token_address"]
    hub = EventHub()
    pools_q = hub.subscribe({"spot_pools"})
    one_pool_q = hub.subscribe({f"spot_pools:{pid}"})
    book_q = hub.subscribe({canonical_channel(f"spot_book:{T1}:{T0}")})   # either order
    acct_q = hub.subscribe({f"spot_account:{ALICE}"})
    tokens_q = hub.subscribe({canonical_channel(f"tokens:{token.upper().replace('0X', '0x')}")})
    publisher = ExchangeStreamPublisher(hub)

    def drain(q):
        out = []
        while not q.empty():
            out.append(q.get_nowait())
        return out

    publisher.step(mgr)
    assert [e["key"] for e in drain(pools_q)] == [pid] and len(drain(one_pool_q)) == 1
    assert drain(book_q)[0]["book"]["pair"] == f"{T0}:{T1}"
    assert drain(acct_q)[0]["account"]["positions"][0]["position_id"] == pos
    assert drain(tokens_q)[0]["token"]["symbol"] == "SPT"
    publisher.step(mgr)
    assert not any(drain(q) for q in (pools_q, one_pool_q, book_q, acct_q, tokens_q))

    assert mgr.process_transaction(_tx(BOB, ExchangeOpType.SWAP, {
        "token_in": T0, "token_out": T1, "amount_in": "100"})).success
    assert mgr.process_transaction(_tx(CAROL, ExchangeOpType.PLACE_ORDER, {
        "pair": f"{T0}:{T1}", "side": "buy", "order_type": "limit", "price": "0.5",
        "amount": "10"})).success
    publisher.step(mgr)
    assert D(drain(pools_q)[0]["pool"]["volume"][0]) == 100            # the swap moved the pool
    assert drain(book_q)[0]["book"]["bids"] == [["0.5", "10"]]
    assert D(drain(acct_q)[0]["account"]["positions"][0]["fees0"]) > 0  # Alice's LP fees grew
    assert drain(tokens_q) == []                                        # token unchanged

    assert not valid_channel("spot_book") and not valid_channel("spot_account")
    q = hub.subscribe()
    reply = handle_client_frame(hub, q, {"op": "subscribe", "channels": [f"spot_book:{T1}:{T0}"]})
    assert f"spot_book:{T0}:{T1}" in reply["channels"]
    snaps = initial_snapshots(mgr, {"spot_pools", f"spot_book:{T0}:{T1}",
                                    f"spot_account:{ALICE}", "tokens"})
    assert {s["type"] for s in snaps} == {"spot_pool", "spot_book", "spot_account", "token"}
    assert all(s["snapshot"] for s in snaps)


# ── the CLI ────────────────────────────────────────────────────────────────

def test_the_spot_cli_swaps_with_a_quoted_minimum_and_adds_quoted_liquidity(monkeypatch, tmp_path):
    from click.testing import CliRunner
    from qrdx.cli import perp as P
    from qrdx.cli import spot as S
    from qrdx.crypto.pq.dilithium import PQPrivateKey
    from qrdx.exchange.submission import parse_exchange_tx
    from qrdx.wallet_v2 import PQWallet
    wallet = PQWallet(private_key=PQPrivateKey.generate())
    calls = []

    def fake_rpc(node, method, params=None, timeout=20.0):

        if method == "p2p_getStatus":      # the CLI signs for the node's network

            from qrdx.constants import CHAIN_ID

            return {"network": {"chain_id": CHAIN_ID}}
        calls.append((method, params))
        if method == "exchange_getNonce":
            return 4
        if method == "exchange_sendTransaction":
            return parse_exchange_tx(params[0]).tx_hash()
        if method == "exchange_quoteSwap":
            assert params[3] == wallet.address                  # quoted as the signer
            return {"amount_out": "200", "source": "amm"}
        if method == "exchange_quoteLiquidity":
            return {"liquidity": "123.45", "amount0": "1", "amount1": "2",
                    "token0": T0, "token1": T1}
        raise AssertionError(method)

    for module in (P, S):
        monkeypatch.setattr(module, "rpc", fake_rpc)
    monkeypatch.setattr(P, "_signer", lambda wallet_file: wallet)
    wallet_file = tmp_path / "w.json"
    wallet_file.write_text("{}")

    r = CliRunner().invoke(S.spot, ["swap", str(wallet_file), T0, T1, "100", "--slippage", "1",
                                    "--yes"])
    assert r.exit_code == 0, r.output
    sent = parse_exchange_tx(calls[-1][1][0])
    assert sent.verify() and sent.nonce == 4
    assert sent.params == {"token_in": T0, "token_out": T1, "amount_in": "100",
                           "min_amount_out": "198.000000000000000000", "venue": "auto"}

    r = CliRunner().invoke(S.spot, ["add-liquidity", str(wallet_file), "pool1", "-600", "600",
                                    "--amount0", "1", "--yes"])
    assert r.exit_code == 0, r.output
    sent = parse_exchange_tx(calls[-1][1][0])
    assert sent.op_type == ExchangeOpType.ADD_LIQUIDITY
    assert sent.params == {"pool_id": "pool1", "tick_lower": -600, "tick_upper": 600,
                           "amount": "123.45"}
    r = CliRunner().invoke(S.spot, ["add-liquidity", str(wallet_file), "pool1", "-600", "600"])
    assert r.exit_code != 0 and "amount0" in r.output
