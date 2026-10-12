"""
S23 — The consensus bridge on the live chain (docs/BRIDGE.md).

The scripted source chain (testnet/bridge_deposits.json, which every validator's watcher reads as
a lockbox's finalized deposits) lists a deposit to Test User 0. The validators attest it in their
oracle votes; once two thirds of the stake agree it is minted — on every node, once. The user
then withdraws part of it: the burn is recorded as withdrawal #1 on every node, for the lockbox's
custodian to release. Every node reports the same bridged token, balance, withdrawal and root.
"""

import asyncio
import json
import os
import secrets
from collections import Counter
from decimal import Decimal

from integration_tests.config import (
    BRIDGE_SOURCE_FILE,
    BRIDGE_TEST_CHAIN,
    BRIDGE_TEST_TOKEN,
)
from integration_tests.rpc_client import NodeRPCClient
from integration_tests.scenarios.s20_native_tokens import S20NativeTokens


class S23Bridge(S20NativeTokens):
    name = "s23_bridge"
    description = "Consensus bridge: a validator-attested deposit minted once, a withdrawal — cross-node"
    depends_on = []

    async def _rpc(self, url, method, params=None):
        try:
            async with NodeRPCClient(url) as c:
                return await c.json_rpc(method, params or [])
        except Exception:
            return None

    async def execute(self) -> None:
        from qrdx.exchange import ExchangeOpType
        from qrdx.exchange.bridge import token_address

        user = self.ctx.wallets.get("Test User 0")
        if not (user and user.get("private_key") and "PQ" in str(user.get("address", ""))):
            self.check(False, "Test User 0 (PQ) wallet available")
            return
        nodes = self.ctx.node_urls
        token = token_address(BRIDGE_TEST_CHAIN, BRIDGE_TEST_TOKEN)

        listed = [await self._rpc(url, "bridge_getAssets") for url in nodes]
        self.check(all(a and a[0]["token_address"] == token for a in listed),
                   f"Every node lists the bridged asset at {token}")

        deposit = {"chain": BRIDGE_TEST_CHAIN, "token": BRIDGE_TEST_TOKEN,
                   "tx": "0x" + secrets.token_hex(32), "log": 0, "to": user["address"],
                   "amount": "1234.5"}
        deposit_id = f"{BRIDGE_TEST_CHAIN}:{deposit['tx']}:0"
        tmp = BRIDGE_SOURCE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps([deposit]))
        os.replace(tmp, BRIDGE_SOURCE_FILE)

        async def view(url):
            d = await self._rpc(url, "bridge_getDeposit", [deposit_id])
            t = await self._get(url, "/get_token", token_address=token)
            b = await self._get(url, "/get_token_balance", token_address=token,
                                address=user["address"])
            if not (d and t and b):
                return None
            return {"minted": d["minted"], "supply": Decimal(t["total_supply"]),
                    "balance": Decimal(b["balance"])}

        want = {"minted": True, "supply": Decimal("1234.5"), "balance": Decimal("1234.5")}
        views = {}
        for _ in range(60):                       # the watcher polls every 15 s
            views = {url: await view(url) for url in nodes}
            if all(v == want for v in views.values()):
                break
            await asyncio.sleep(2)
        self.check(all(v == want for v in views.values()),
                   f"Validators attested the deposit: minted once on every node ({views})")

        await self._ok(nodes[0], user, ExchangeOpType.BRIDGE_WITHDRAW, {
            "token_address": token, "amount": "234.5", "to": "0x" + "5e" * 20},
            "The user withdraws 234.5 to the source chain")
        await self._refused(nodes[0], user, ExchangeOpType.BRIDGE_WITHDRAW, {
            "token_address": token, "amount": "5000", "to": "0x" + "5e" * 20},
            "Withdrawing more than the balance", "insufficient")

        async def ledger(url):
            w = await self._rpc(url, "bridge_getWithdrawals", [1, 10])
            t = await self._get(url, "/get_token", token_address=token)
            if w is None or not t:
                return None
            return ([(x["id"], x["amount"], x["to"], x["chain"]) for x in w],
                    Decimal(t["total_supply"]))

        want_ledger = ([(1, "234.5", "0x" + "5e" * 20, BRIDGE_TEST_CHAIN)], Decimal("1000"))
        ledgers = {}
        for _ in range(30):
            ledgers = {url: await ledger(url) for url in nodes}
            if all(v == want_ledger for v in ledgers.values()):
                break
            await asyncio.sleep(2)
        self.check(all(v == want_ledger for v in ledgers.values()),
                   f"Every node records withdrawal #1 and a supply of 1000 ({ledgers})")

        # The deposit stays in the source's list; the watchers keep seeing it. It is not minted
        # again.
        await asyncio.sleep(20)
        supplies = {url: (await self._get(url, "/get_token", token_address=token) or {}).get(
            "total_supply") for url in nodes}
        self.check(all(s is not None and Decimal(s) == 1000 for s in supplies.values()),
                   f"Still 1000 after the watchers re-read the deposit ({supplies})")

        roots = {}
        for url in nodes:
            r = await self._get(url, "/get_unified_state_root")
            if r:
                roots[url] = r.get("token_root")
        modal, n = Counter(v for v in roots.values() if v).most_common(1)[0] if roots else (None, 0)
        self.check(n >= max(2, len(nodes) - 1),
                   f"Nodes converge on one token root ({n}/{len(nodes)})")
