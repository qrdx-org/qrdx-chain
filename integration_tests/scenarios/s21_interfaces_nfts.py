"""
S21 — What interfaces read, on the live chain: a QRDX market, market data, wallet history,
token extensions and NFTs.

A maker deploys a token and pools it against native QRDX (no wrapping), rests an ask on the
pair's book; a taker lifts part of it and swaps through the pool. Every node then serves the
same market data (/get_trades, /get_orderbook at levels 2 and 3, /get_ticker, /get_candles,
/get_markets) and the same wallet history (/get_address_history — the maker sees the fill as
its maker — and /get_indexed_transaction). The maker deploys a transfer-fee token: a transfer
withholds the fee at the token's address, the withdraw authority collects it, and the token
cannot be pooled. An artist creates an NFT collection and mints to a 0x wallet, which moves
its NFT with an ERC-721 transferFrom from the EVM; every node reports the new owner natively
and through eth_call's ownerOf.
"""

import asyncio
import math
from collections import Counter
from decimal import Decimal

from integration_tests.rpc_client import NodeRPCClient
from integration_tests.scenarios.s20_native_tokens import S20NativeTokens


class S21InterfacesNfts(S20NativeTokens):
    name = "s21_interfaces_nfts"
    description = "QRDX market, market data, history, token extensions, NFTs — cross-node"
    depends_on = ["s14_token_consensus"]

    async def _agree(self, nodes, read, want=None, label="", tries=40):
        """Poll every node until they all read the same (and ``want``, if given)."""
        seen = {}
        for _ in range(tries):
            seen = {}
            for url in nodes:
                try:
                    v = await read(url)
                except Exception as e:
                    v = f"error: {str(e)[:80]}"
                if v is not None:
                    seen[url] = v
            values = list(seen.values())
            if len(seen) == len(nodes) and all(v == values[0] for v in values) \
                    and (want is None or values[0] == want):
                break
            await asyncio.sleep(2)
        modal, n = (Counter(repr(v) for v in seen.values()).most_common(1)[0]
                    if seen else (None, 0))
        self.check(n >= max(2, len(nodes) - 1) and (want is None or repr(want) == modal),
                   f"{label} ({n}/{len(nodes)}: {str(seen.get(nodes[0]))[:200]})")
        return seen.get(nodes[0])

    async def execute(self) -> None:
        from qrdx.exchange import ExchangeOpType as Op
        from qrdx.exchange.state_manager import ExchangeStateManager

        w = self.ctx.wallets
        maker, taker, artist, collector = (w.get(n) for n in (
            "Market Maker", "Market Taker", "NFT Artist", "NFT Collector"))
        if not all(x and x.get("private_key") for x in (maker, taker, artist, collector)):
            self.check(False, "Market Maker / Taker and NFT Artist / Collector wallets available")
            return
        nodes = self.ctx.node_urls
        target = nodes[0]

        # ── a QRDX market: pool + book ─────────────────────────────────────
        start = await self._get(target, "/get_exchange_nonce", address=maker["address"])
        n0 = int((start or {}).get("nonce", 0))
        tok = ExchangeStateManager.derive_token_address(maker["address"], n0, "qMKT")
        await self._ok(target, maker, Op.TOKEN_DEPLOY, {
            "name": "Market Token", "symbol": "qMKT", "decimals": 6,
            "total_supply": "1000000", "uri": "ipfs://qmkt"}, "Deploy qMKT (with metadata)")
        await self._ok(target, maker, Op.CREATE_POOL, {
            "token0": "QRDX", "token1": tok, "fee_tier": 3000, "pool_type": "STANDARD",
            "initial_price": "2", "stake_amount": "10000"}, "Pool qMKT against native QRDX")
        centre = int(math.log(2) / math.log(1.0001)) // 60 * 60
        await self._ok(target, maker, Op.ADD_LIQUIDITY, {
            "token0": tok, "token1": "QRDX", "tick_lower": centre - 600,
            "tick_upper": centre + 600, "amount": "100000"}, "Add liquidity (QRDX + qMKT)")
        market = f"{tok}:QRDX"
        ask = await self._ok(target, maker, Op.PLACE_ORDER, {
            "pair": f"QRDX:{tok}", "side": "sell", "order_type": "limit", "price": "2.5",
            "amount": "10"}, "The maker rests an ask: 10 qMKT at 2.5 QRDX")
        lift = await self._ok(target, taker, Op.PLACE_ORDER, {
            "pair": market, "side": "buy", "order_type": "limit", "price": "2.5",
            "amount": "4"}, "The taker lifts 4 of it")
        self.check(bool(lift) and lift["data"].get("trades") == 1, "The taker's order filled")
        await self._ok(target, taker, Op.SWAP, {
            "token_in": "QRDX", "token_out": tok, "amount_in": "5", "venue": "amm"},
            "The taker swaps 5 QRDX through the pool")

        # ── market data, identical on every node ──────────────────────────
        async def trades(url):
            t = await self._get(url, "/get_trades", market=f"QRDX/{tok}")
            return None if t is None else [(x["venue"], x["side"], x["price"], x["amount"],
                                             x["tx_hash"]) for x in t["trades"]]
        got = await self._agree(nodes, trades, label="Nodes serve the same trades")
        self.check(bool(got) and len(got) == 2 and got[0][:4] == ("clob", "buy", "2.5", "4")
                   and got[1][0] == "amm", f"A book fill then a pool swap ({got})")

        async def book(url):
            b = await self._get(url, "/get_orderbook", market=market, level=3)
            return None if b is None else (
                [(r["price"], r["amount"], r["total"]) for r in b["asks"]],
                [o["owner"] for r in b["asks"] for o in r["orders"]], len(b["amm"]))
        await self._agree(nodes, book, want=([("2.5", "6", "6")], [maker["address"]], 1),
                          label="Nodes serve the L3 book: 6 left at 2.5, the maker's")

        async def ticker(url):
            t = await self._get(url, "/get_ticker", market=market)
            return None if t is None else (t["best_ask"], t["trades_24h"], t["pools"])
        await self._agree(nodes, ticker, want=("2.5", 2, 1), label="Nodes serve the ticker")
        candles = await self._get(target, "/get_candles", market=market, interval="1m")
        self.check(bool(candles and candles["candles"]), "Candles are served")
        markets = await self._get(target, "/get_markets", kind="spot")
        self.check(any(m["market"] == market for m in markets or []),
                   "The QRDX pair is listed in /get_markets")

        # ── wallet history, identical on every node ───────────────────────
        async def maker_history(url):
            h = await self._get(url, "/get_address_history", address=maker["address"], limit=10)
            return None if h is None else [(t["op"], t["roles"]) for t in h["transactions"][:2]]
        await self._agree(nodes, maker_history,
                          want=[("PLACE_ORDER", ["maker"]), ("PLACE_ORDER", ["sender"])],
                          label="The maker's history shows the fill of its ask")
        lift_tx = (lift or {}).get("tx_hash", "")

        async def lookup(url):
            t = await self._get(url, "/get_indexed_transaction", tx_hash=lift_tx)
            return None if t is None else (t["op"], t["status"], sorted(t["accounts"].values()))
        await self._agree(nodes, lookup, want=("PLACE_ORDER", "success", [["maker"], ["sender"]]),
                          label="The taker's order is indexed with both parties")
        latest = await self._get(target, "/get_latest_transactions", limit=5)
        self.check(bool(latest and latest["transactions"]), "Latest transactions are served")

        # ── a transfer-fee token ──────────────────────────────────────────
        start = await self._get(target, "/get_exchange_nonce", address=maker["address"])
        fee_tok = ExchangeStateManager.derive_token_address(
            maker["address"], int((start or {}).get("nonce", 0)), "qFEE")
        await self._ok(target, maker, Op.TOKEN_DEPLOY, {
            "name": "Fee Token", "symbol": "qFEE", "total_supply": "1000",
            "transfer_fee_bps": 100}, "Deploy a 1% transfer-fee token")
        rec = await self._ok(target, maker, Op.TOKEN_TRANSFER, {
            "token_address": fee_tok, "to": taker["address"], "amount": "100"},
            "Send 100 of it")
        self.check(bool(rec) and rec["data"].get("fee") == "1", "1 is withheld")
        await self._refused(target, maker, Op.CREATE_POOL, {
            "token0": fee_tok, "token1": "QRDX", "fee_tier": 3000, "pool_type": "STANDARD",
            "initial_price": "1", "stake_amount": "10000"}, "Pooling a fee token",
            "cannot be pooled")
        await self._ok(target, maker, Op.TOKEN_WITHDRAW_FEES, {"token_address": fee_tok},
                       "The withdraw authority collects the fee")

        async def fee_balances(url):
            vals = []
            for who in (taker["address"], fee_tok, maker["address"]):
                b = await self._get(url, "/get_token_balance", token_address=fee_tok,
                                    address=who)
                if b is None:
                    return None
                vals.append(Decimal(b["balance"]))
            return vals
        await self._agree(nodes, fee_balances, want=[Decimal(99), Decimal(0), Decimal(901)],
                          label="Nodes agree: 99 received, nothing withheld, 901 back home")

        # ── NFTs, natively and as an ERC-721 ──────────────────────────────
        await self._nfts(nodes, target, artist, collector)

    async def _nfts(self, nodes, target, artist, collector):
        from eth_account import Account
        from eth_utils import to_checksum_address
        from qrdx.exchange import ExchangeOpType as Op
        from qrdx.exchange.state_manager import ExchangeStateManager
        from integration_tests.tx_sender import _private_key_to_bytes

        user = self.ctx.wallets.get("Token EVM User")
        if not user or not user.get("private_key"):
            self.check(False, "Token EVM User wallet available")
            return
        key = _private_key_to_bytes(user["private_key"])
        user_addr = Account.from_key(key).address
        start = await self._get(target, "/get_exchange_nonce", address=artist["address"])
        coll = ExchangeStateManager.derive_collection_address(
            artist["address"], int((start or {}).get("nonce", 0)), "QART")
        await self._ok(target, artist, Op.NFT_CREATE_COLLECTION, {
            "name": "Quantum Art", "symbol": "QART", "uri": "ipfs://qart",
            "royalty_bps": 500}, "Create an NFT collection")
        await self._ok(target, artist, Op.NFT_MINT, {
            "collection": coll, "to": user_addr, "uri": "ipfs://qart/1"}, "Mint #1 to a 0x wallet")
        await self._ok(target, artist, Op.NFT_MINT, {
            "collection": coll, "to": collector["address"], "uri": "ipfs://qart/2"},
            "Mint #2 to a PQ wallet")
        await self._refused(target, artist, Op.NFT_TRANSFER, {
            "collection": coll, "token_id": 2, "to": artist["address"],
            "from": collector["address"]}, "Taking someone else's NFT", "not approved")
        await self._ok(target, collector, Op.NFT_TRANSFER, {
            "collection": coll, "token_id": 2, "to": artist["address"]},
            "The collector sends #2 back")

        recipient = "0x" + "e8" * 20
        async with NodeRPCClient(target) as c:
            nonce = int(await c.json_rpc("eth_getTransactionCount", [user_addr, "pending"]), 16)
            chain_id = int(await c.json_rpc("eth_chainId", []), 16)
            data = (bytes.fromhex("23b872dd") + bytes(12) + bytes.fromhex(user_addr[2:])
                    + bytes(12) + bytes.fromhex(recipient[2:]) + (1).to_bytes(32, "big"))
            signed = Account.sign_transaction({
                "nonce": nonce, "gasPrice": 10 ** 9, "gas": 150_000,
                "to": to_checksum_address(coll), "value": 0, "chainId": chain_id,
                "data": data}, key)
            raw = "0x" + bytes(getattr(signed, "raw_transaction", None)
                               or signed.rawTransaction).hex()
            tx_hash = await c.json_rpc("eth_sendRawTransaction", [raw])
            receipt = None
            for _ in range(60):
                receipt = await c.json_rpc("eth_getTransactionReceipt", [tx_hash])
                if receipt:
                    break
                await asyncio.sleep(2)
        self.check(bool(receipt) and int(str(receipt.get("status", "0x0")), 16) == 1,
                   f"The ERC-721 transferFrom executed ({receipt and receipt.get('status')})")

        async def owners(url):
            one = await self._get(url, "/get_nft", collection=coll, token_id="1")
            two = await self._get(url, "/get_nft", collection=coll, token_id="2")
            async with NodeRPCClient(url) as c:
                out = await c.json_rpc("eth_call", [{
                    "to": coll, "data": "0x6352211e" + (1).to_bytes(32, "big").hex()}, "latest"])
            if not (one and two):
                return None
            return (one["owner"].lower(), two["owner"], "0x" + out[-40:])
        await self._agree(nodes, owners, want=(recipient, artist["address"], recipient),
                          label="Nodes agree on the owners, natively and via ownerOf")
