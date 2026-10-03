"""
S13 — Perps on the clearinghouse order book, settled in a USD stablecoin, cross-node
(docs/PERPS_CLEARINGHOUSE.md).

The issuer deploys the testnet stablecoin (qUSD — the bridged stablecoin's stand-in) and pays two
PQ traders. They deposit it into the perps clearinghouse; one rests a sell, the other lifts it,
so their positions are equal and opposite. The validators' price feed moves the market (each
validator votes what it reads; the oracle is their stake-weighted median), both close on the
book, and both withdraw. Every node must agree on the positions and the balances, and the
stablecoin must be conserved: what one trader gained the other lost, and the clearinghouse holder
keeps exactly the trading fees. (Perps used to trade against nobody, which minted QRDX on every
win and burned it on every loss.)
"""

import asyncio
import json
import os
from decimal import Decimal

from integration_tests.scenarios.base import Scenario
from integration_tests.rpc_client import NodeRPCClient

MARKET = "qBTC-USD-PERP"


def stablecoin_address(wallets) -> str:
    """The configured perps collateral: the issuer's first TOKEN_DEPLOY (nonce 0)."""
    from qrdx.exchange.state_manager import ExchangeStateManager
    from integration_tests.config import STABLECOIN_SYMBOL
    issuer = (wallets.get("Stablecoin Issuer") or {}).get("address", "")
    return ExchangeStateManager.derive_token_address(issuer, 0, STABLECOIN_SYMBOL)


class S13PerpCollateral(Scenario):
    name = "s13_perp_collateral"
    description = "Perps trade on the order book in a USD stablecoin, priced by validator votes; conserved cross-node"
    depends_on = ["s12_exchange_consensus"]

    async def _get(self, url, path, params=None):
        try:
            async with NodeRPCClient(url) as c:
                r = await c._get(path, params=params)
                return r["result"] if r and r.get("ok") else None
        except Exception:
            return None

    async def _account(self, url, address):
        return await self._get(url, "/get_perp_account", {"address": address})

    async def _usd(self, url, address):
        """The address's qUSD balance in the token ledger, or None if unreadable."""
        r = await self._get(url, "/get_token_balance",
                            {"token_address": stablecoin_address(self.ctx.wallets),
                             "address": address})
        return Decimal(r["balance"]) if r else None

    async def _set_price(self, node_urls, base, price, label):
        """Move the market by moving the validators' feed: every validator reads this file and
        votes what it says; wait until a quorum of nodes report the voted oracle price."""
        from integration_tests.config import ORACLE_FEED_FILE
        try:
            data = json.loads(ORACLE_FEED_FILE.read_text())
        except (OSError, ValueError):
            data = {}
        data[base] = str(price)
        tmp = ORACLE_FEED_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        os.replace(tmp, ORACLE_FEED_FILE)

        async def oracle(url):
            r = await self._get(url, "/get_perp_market",
                                {"market_id": f"{base}-{MARKET.split('-')[1]}-PERP"})
            if r and Decimal(r["oracle_price"]) == Decimal(str(price)):
                return r["oracle_price"]
            return None
        return await self._converged(node_urls, oracle,
                                     f"{label}: the oracle follows the validators' votes") is not None

    async def _submit(self, target, wallet, key, op, params, label):
        """Sign with the sender's current exchange nonce, submit to ``target`` (as a JSON
        object), and wait until that nonce is consumed (the exchange root is no signal: it
        commits to the height, so it moves every block). Returns the tx hash, or None."""
        from qrdx.exchange import ExchangeTransaction
        acct = await self._account(target, wallet["address"])
        nonce = acct["exchange_nonce"] if acct else 0
        tx = ExchangeTransaction(op_type=op, sender=wallet["address"], nonce=nonce, params=params,
                                 gas_limit=2_000_000, gas_price=10**9)
        tx.public_key = key.public_key.to_bytes()
        tx.signature = key.sign(tx.signing_bytes()).to_bytes()
        async with NodeRPCClient(target) as c:
            r = await c._post("/submit_exchange_tx", json_data={"tx": tx.to_dict()})
        if not self.check(bool(r and r.get("ok")), f"{label}: admitted"):
            self._log.error("%s rejected at admission: %s", label, r)
            return None
        for _ in range(60):                        # ~120s, reorg-tolerant
            await asyncio.sleep(2)
            after = await self._account(target, wallet["address"])
            if after and after["exchange_nonce"] > nonce:
                return tx.tx_hash()
        self.check(False, f"{label}: included")
        return None

    async def _rpc(self, url, method, *params):
        try:
            async with NodeRPCClient(url) as c:
                r = await c._post("/rpc", json_data={"jsonrpc": "2.0", "method": method,
                                                     "params": list(params), "id": 1})
            return r.get("result") if isinstance(r, dict) else None
        except Exception:
            return None

    async def _listen(self, url, channels, sink, stop):
        """Collect a WebSocket subscriber's frames until ``stop`` is set."""
        import websockets
        ws_url = url.replace("http://", "ws://").replace("https://", "wss://") + "/ws"
        try:
            async with websockets.connect(ws_url) as ws:
                await ws.send(json.dumps({"op": "set", "channels": channels}))
                while not stop.is_set():
                    try:
                        sink.append(json.loads(await asyncio.wait_for(ws.recv(), timeout=1.0)))
                    except asyncio.TimeoutError:
                        continue
        except Exception as e:
            sink.append({"type": "listener-error", "error": str(e)})

    async def _converged(self, node_urls, probe, label):
        """Poll until a quorum of nodes report the same value for ``probe(url)``."""
        values = {}
        for _ in range(60):
            values = {url: await probe(url) for url in node_urls}
            counts = {}
            for v in values.values():
                if v is not None:
                    counts[repr(v)] = counts.get(repr(v), 0) + 1
            if counts and max(counts.values()) >= max(2, len(node_urls) - 1):
                break
            await asyncio.sleep(2)
        modal = max(((repr(v), v) for v in values.values() if v is not None),
                    key=lambda kv: sum(1 for x in values.values() if repr(x) == kv[0]),
                    default=(None, None))[1]
        agree = sum(1 for v in values.values() if repr(v) == repr(modal))
        self.check(agree >= max(2, len(node_urls) - 1),
                   f"{label}: nodes agree ({agree}/{len(node_urls)})")
        return modal

    async def execute(self) -> None:
        from qrdx.crypto.pq.dilithium import PQPrivateKey
        from qrdx.exchange import ExchangeOpType

        node_urls = self.ctx.node_urls
        target = node_urls[0]
        wallets = self.ctx.wallets
        alice, bob, rep, issuer = (wallets.get("Test User 0"), wallets.get("Perp Trader"),
                                   wallets.get("Oracle Reporter"), wallets.get("Stablecoin Issuer"))
        for label, w in (("trader Test User 0", alice), ("trader Perp Trader", bob),
                         ("oracle reporter", rep), ("stablecoin issuer", issuer)):
            if not w or not w.get("private_key") or "PQ" not in str(w.get("address", "")):
                self.check(False, f"{label} wallet available")
                return
        keys = {w["address"]: PQPrivateKey.from_hex(w["private_key"], w["public_key"])
                for w in (alice, bob, rep, issuer)}

        # Bob trades through the node that never proposes (the testnet's non-validator): his
        # transactions reach a block only because nodes gossip exchange transactions.
        observer = node_urls[-1] if len(node_urls) > 3 else target

        async def submit(w, op, params, label):
            via = observer if w is bob else target
            return await self._submit(via, w, keys[w["address"]], op, params, label)

        # The stablecoin perps settle in: deployed by the issuer's first transaction, at the
        # address every node was configured with.
        from integration_tests.config import STABLECOIN_SUPPLY, STABLECOIN_SYMBOL
        usd = stablecoin_address(wallets)
        if not await submit(issuer, ExchangeOpType.TOKEN_DEPLOY,
                            {"name": "Testnet USD", "symbol": STABLECOIN_SYMBOL, "decimals": 18,
                             "total_supply": str(STABLECOIN_SUPPLY)}, "Deploy qUSD"):
            return
        for w, label in ((alice, "Alice"), (bob, "Bob")):
            if not await submit(issuer, ExchangeOpType.TOKEN_TRANSFER,
                                {"token_address": usd, "to": w["address"], "amount": "100000"},
                                f"Pay {label} 100,000 qUSD"):
                return

        holder = (await self._account(target, alice["address"]) or {}).get("holder_address")
        self.check_not_none(holder, "Clearinghouse holder address readable")
        start = {a: await self._usd(target, a) for a in (alice["address"], bob["address"], holder)}
        if not self.check(all(v is not None for v in start.values()) and
                          start[alice["address"]] >= 100000,
                          f"Starting qUSD balances readable (incl. the holder): {start}"):
            return

        if not await submit(alice, ExchangeOpType.CREATE_MARKET, {"base_token": "qBTC"},
                            "CREATE_MARKET"):
            return
        if not await self._set_price(node_urls, "qBTC", 30000, "Validators price qBTC at 30,000"):
            return
        steps = [
            (alice, ExchangeOpType.PERP_DEPOSIT, {"amount": "20000"}, "Alice PERP_DEPOSIT"),
            (bob, ExchangeOpType.PERP_DEPOSIT, {"amount": "20000"}, "Bob PERP_DEPOSIT (gossiped)"),
            (bob, ExchangeOpType.PERP_ORDER, {"market_id": MARKET, "side": "sell", "size": "1",
                                              "price": "30000"}, "Bob rests a sell (gossiped)"),
        ]
        for w, op, params, label in steps:
            if not await submit(w, op, params, label):
                return

        async def bobs_orders(url):
            orders = await self._get(url, "/get_perp_orders", {"address": bob["address"]})
            return None if orders is None else [(o["side"], o["price"], o["remaining"])
                                                for o in orders]
        resting = await self._converged(node_urls, bobs_orders, "Bob's open orders")
        self.check(resting == [("sell", "30000", "1")], f"Bob's sell rests on every node: {resting}")

        # A wallet watching the stream: the fill and Alice's new position arrive live.
        frames, stop = [], asyncio.Event()
        listener = asyncio.create_task(self._listen(
            target, [f"perp_events:{MARKET}", f"perp_account:{alice['address']}"], frames, stop))
        await asyncio.sleep(1)
        lift = await submit(alice, ExchangeOpType.PERP_ORDER, {"market_id": MARKET, "side": "buy",
                                                               "size": "1", "price": "30000"},
                            "Alice lifts it")
        if not lift:
            stop.set()
            return

        async def receipt(url):
            r = await self._get(url, "/get_exchange_receipt", {"tx_hash": lift})
            return None if not r else (r["success"], r["block_height"],
                                       [(f["price"], f["amount"]) for f in r["data"].get("fills", [])])
        got = await self._converged(node_urls, receipt, "Alice's order receipt")
        self.check(got is not None and got[0] and got[2] == [("30000", "1")],
                   f"The receipt shows the fill on every node: {got}")
        via_rpc = await self._rpc(node_urls[1], "exchange_getTransactionReceipt", lift)
        self.check(bool(via_rpc) and via_rpc.get("success") and via_rpc["data"]["fills"],
                   "exchange_getTransactionReceipt (JSON-RPC) reports it too")
        market = await self._rpc(node_urls[2], "perp_getMarket", MARKET)
        self.check(bool(market) and market.get("last_trade_price") == "30000",
                   f"perp_getMarket (JSON-RPC) shows the trade: {market and market.get('last_trade_price')}")
        for _ in range(15):
            if any(f.get("type") == "perp_event" for f in frames) and any(
                    f.get("type") == "perp_account" and MARKET in f["account"]["positions"]
                    for f in frames):
                break
            await asyncio.sleep(1)
        stop.set()
        await listener
        fills = [f["event"] for f in frames if f.get("type") == "perp_event"
                 and f["event"]["type"] == "fill"]
        self.check(any(f["buyer"] == alice["address"] for f in fills),
                   f"The WebSocket stream delivered the fill ({len(fills)} fill event(s))")
        self.check(any(f.get("type") == "perp_account" and
                       f["account"]["positions"].get(MARKET, {}).get("size") == "1"
                       for f in frames),
                   "The WebSocket stream delivered Alice's new position")

        async def sizes(url):
            a, b = await self._account(url, alice["address"]), await self._account(url, bob["address"])
            if not a or not b:
                return None
            return (a["positions"].get(MARKET, {}).get("size"),
                    b["positions"].get(MARKET, {}).get("size"))
        opened = await self._converged(node_urls, sizes, "Open positions")
        self.check(opened is not None and Decimal(opened[0]) == 1 and Decimal(opened[1]) == -1,
                   f"Equal and opposite positions (Alice long 1, Bob short 1): {opened}")

        if not await self._set_price(node_urls, "qBTC", 33000, "Validators price qBTC at 33,000"):
            return
        for w, op, params, label in [
            (bob, ExchangeOpType.PERP_ORDER, {"market_id": MARKET, "side": "buy", "size": "1",
                                              "price": "33000", "reduce_only": True},
             "Bob rests a closing buy"),
            (alice, ExchangeOpType.PERP_ORDER, {"market_id": MARKET, "side": "sell", "size": "1",
                                                "price": "33000", "reduce_only": True},
             "Alice closes into it"),
        ]:
            if not await submit(w, op, params, label):
                return
        for w, label in ((alice, "Alice"), (bob, "Bob")):
            acct = await self._account(target, w["address"])
            amount = acct["withdrawable"] if acct else "0"
            if not await submit(w, ExchangeOpType.PERP_WITHDRAW, {"amount": amount},
                                f"{label} PERP_WITHDRAW {amount}"):
                return

        async def balances(url):
            vals = [await self._usd(url, a) for a in (alice["address"], bob["address"], holder)]
            return None if any(v is None for v in vals) else tuple(str(v) for v in vals)
        final = await self._converged(node_urls, balances, "Final balances")
        if final is None:
            return
        d_alice, d_bob, d_holder = (Decimal(f) - Decimal(str(start[a]))
                                    for f, a in zip(final, (alice["address"], bob["address"], holder)))
        self._log.info("Alice %+.6f, Bob %+.6f, holder (fees) %+.6f", d_alice, d_bob, d_holder)
        self.check(d_alice > Decimal("2900"), f"Alice won ~3,000 minus fees ({d_alice})")
        self.check(d_bob < Decimal("-3000"), f"Bob lost 3,000 plus fees ({d_bob})")
        self.check(d_alice + d_bob + d_holder == 0,
                   f"qUSD conserved: winner + loser + holder = {d_alice + d_bob + d_holder}")
