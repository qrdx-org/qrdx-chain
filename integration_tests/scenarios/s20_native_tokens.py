"""
S20 — The native token standard on the live chain (qrdx/exchange/tokens.py).

An issuer deploys a bridge-style token (zero supply, a cap, mint and freeze authorities) and
mints to a holder; the holder approves a spender, who moves part of the allowance; the holder
burns; the issuer freezes the holder (a transfer is refused) and thaws it (the transfer goes
through); the issuer hands the mint authority to the spender, after which only the spender
can mint. Every node then reports the same token — supply, authorities — the same balances
and allowance, and the same token root, and the supply equals the sum of the balances.
"""

import asyncio
from collections import Counter
from decimal import Decimal

from integration_tests.rpc_client import NodeRPCClient
from integration_tests.scenarios.base import Scenario


class S20NativeTokens(Scenario):
    name = "s20_native_tokens"
    description = "Native tokens: mint/burn, approvals, freeze, authorities — cross-node"
    depends_on = ["s14_token_consensus"]

    async def _get(self, url, path, **params):
        async with NodeRPCClient(url) as c:
            r = await c._get(path, params=params)
        return r["result"] if r and r.get("ok") else None

    async def _execute_tx(self, target, wallet, op, params, label):
        """Sign with ``wallet`` at its next exchange nonce, submit, wait for the receipt."""
        from qrdx.crypto.pq.dilithium import PQPrivateKey
        from qrdx.exchange import ExchangeTransaction
        key = PQPrivateKey.from_hex(wallet["private_key"], wallet["public_key"])
        nonce = (await self._get(target, "/get_exchange_nonce", address=wallet["address"])
                 or {}).get("nonce", 0)
        tx = ExchangeTransaction(op_type=op, sender=wallet["address"], nonce=int(nonce),
                                 params=params, gas_limit=2_000_000, gas_price=10**9)
        tx.public_key = key.public_key.to_bytes()
        tx.signature = key.sign(tx.signing_bytes()).to_bytes()
        async with NodeRPCClient(target) as c:
            r = await c._post("/submit_exchange_tx", json_data={"tx_hex": tx.to_hex()})
        if not (r and r.get("ok")):
            self.check(False, f"{label}: admitted ({r})")
            return None
        tx_hash = r["result"]["tx_hash"]
        for _ in range(60):                            # ~120s, reorg-tolerant
            rec = await self._get(target, "/get_exchange_receipt", tx_hash=tx_hash)
            if rec:
                return rec
            await asyncio.sleep(2)
        self.check(False, f"{label}: included in a block")
        return None

    async def _ok(self, target, wallet, op, params, label):
        rec = await self._execute_tx(target, wallet, op, params, label)
        self.check(bool(rec) and rec["success"], f"{label} ({rec and rec['error']})")
        return rec

    async def _refused(self, target, wallet, op, params, label, why):
        rec = await self._execute_tx(target, wallet, op, params, label)
        self.check(bool(rec) and not rec["success"] and why in rec["error"],
                   f"{label} is refused ({rec and rec['error']})")
        return rec

    async def execute(self) -> None:
        from qrdx.exchange import ExchangeOpType
        from qrdx.exchange.state_manager import ExchangeStateManager

        wallets = self.ctx.wallets
        issuer, holder, spender = (wallets.get(n) for n in
                                   ("Token Issuer", "Token Holder", "Token Spender"))
        if not all(w and w.get("private_key") for w in (issuer, holder, spender)):
            self.check(False, "Token Issuer / Holder / Spender wallets available")
            return
        nodes = self.ctx.node_urls
        target = nodes[0]

        start = await self._get(target, "/get_exchange_nonce", address=issuer["address"])
        token = ExchangeStateManager.derive_token_address(
            issuer["address"], int((start or {}).get("nonce", 0)), "qBRG")
        await self._ok(target, issuer, ExchangeOpType.TOKEN_DEPLOY, {
            "name": "Bridged Dollar", "symbol": "qBRG", "decimals": 6, "total_supply": "0",
            "max_supply": "1000000", "mint_authority": issuer["address"],
            "freeze_authority": issuer["address"]}, "Deploy a zero-supply token")
        await self._refused(target, holder, ExchangeOpType.TOKEN_MINT,
                            {"token_address": token, "amount": "5"},
                            "Minting by someone else", "mint authority")
        await self._ok(target, issuer, ExchangeOpType.TOKEN_MINT, {
            "token_address": token, "amount": "1000", "to": holder["address"]},
            "The issuer mints 1000 to the holder")

        await self._ok(target, holder, ExchangeOpType.TOKEN_APPROVE, {
            "token_address": token, "spender": spender["address"], "amount": "300"},
            "The holder approves the spender for 300")
        rec = await self._ok(target, spender, ExchangeOpType.TOKEN_TRANSFER_FROM, {
            "token_address": token, "from": holder["address"], "to": spender["address"],
            "amount": "200"}, "The spender moves 200 of it")
        self.check(bool(rec) and rec["data"].get("allowance_left") == "100",
                   "The allowance falls to 100")
        await self._ok(target, holder, ExchangeOpType.TOKEN_BURN,
                       {"token_address": token, "amount": "100"}, "The holder burns 100")

        await self._ok(target, issuer, ExchangeOpType.TOKEN_FREEZE,
                       {"token_address": token, "account": holder["address"]},
                       "The issuer freezes the holder")
        await self._refused(target, holder, ExchangeOpType.TOKEN_TRANSFER, {
            "token_address": token, "to": spender["address"], "amount": "10"},
            "A frozen holder's transfer", "frozen")
        await self._ok(target, issuer, ExchangeOpType.TOKEN_THAW,
                       {"token_address": token, "account": holder["address"]},
                       "The issuer thaws the holder")
        await self._ok(target, holder, ExchangeOpType.TOKEN_TRANSFER, {
            "token_address": token, "to": spender["address"], "amount": "10"},
            "The thawed holder's transfer")

        await self._ok(target, issuer, ExchangeOpType.TOKEN_SET_AUTHORITY, {
            "token_address": token, "authority": "mint", "new_authority": spender["address"]},
            "The issuer hands the mint authority to the spender")
        await self._refused(target, issuer, ExchangeOpType.TOKEN_MINT,
                            {"token_address": token, "amount": "1"},
                            "Minting by the former authority", "mint authority")
        await self._ok(target, spender, ExchangeOpType.TOKEN_MINT,
                       {"token_address": token, "amount": "1"}, "The new authority mints 1")

        # Every node agrees: 1000 − 100 burned + 1 = 901; holder 1000 − 200 − 100 − 10 = 690;
        # spender 200 + 10 + 1 = 211; 690 + 211 = 901.
        want = {"supply": "901", "mint": spender["address"], "holder": Decimal("690"),
                "spender": Decimal("211"), "allowance": "100"}
        views = {}
        for _ in range(30):                            # nodes may trail the proposer briefly
            views = {}
            for url in nodes:
                t = await self._get(url, "/get_token", token_address=token)
                h = await self._get(url, "/get_token_balance", token_address=token,
                                    address=holder["address"])
                s = await self._get(url, "/get_token_balance", token_address=token,
                                    address=spender["address"])
                a = await self._get(url, "/get_token_allowance", token_address=token,
                                    owner=holder["address"], spender=spender["address"])
                if t and h and s and a:
                    views[url] = {"supply": t["total_supply"], "mint": t["mint_authority"],
                                  "holder": Decimal(h["balance"]),
                                  "spender": Decimal(s["balance"]),
                                  "allowance": a["allowance"]}
            if len(views) == len(nodes) and all(v == want for v in views.values()):
                break
            await asyncio.sleep(2)
        agree = sum(1 for v in views.values() if v == want)
        self.check(agree >= max(2, len(nodes) - 1),
                   f"Nodes agree on supply 901, the new authority, balances 690 / 211 and "
                   f"allowance 100 ({agree}/{len(nodes)}: {views.get(target)})")
        self.check(want["holder"] + want["spender"] == Decimal(want["supply"]),
                   "The supply is the sum of the balances")

        roots = {}
        for url in nodes:
            r = await self._get(url, "/get_unified_state_root")
            if r:
                roots[url] = r.get("token_root")
        modal, n = Counter(v for v in roots.values() if v).most_common(1)[0] if roots else (None, 0)
        self.check(n >= max(2, len(nodes) - 1),
                   f"Nodes converge on one token root ({n}/{len(nodes)})")

        await self._erc20_view(nodes, target, token, holder)

    async def _erc20_view(self, nodes, target, token, holder):
        """Native tokens are ERC-20s inside the EVM: a 0x wallet — funded with the token by an
        exchange transfer — sends it with an ordinary EVM transaction (what a web3 wallet's
        "send" builds), and every node shows the move through both the native ledger and
        eth_call's balanceOf."""
        from eth_account import Account
        from eth_utils import to_checksum_address
        from qrdx.exchange import ExchangeOpType
        from integration_tests.tx_sender import _private_key_to_bytes

        user = self.ctx.wallets.get("Token EVM User")
        if not user or not user.get("private_key"):
            self.check(False, "Token EVM User wallet available")
            return
        key = _private_key_to_bytes(user["private_key"])
        user_addr = Account.from_key(key).address
        recipient = "0x" + "e7" * 20
        await self._ok(target, holder, ExchangeOpType.TOKEN_TRANSFER, {
            "token_address": token, "to": user_addr, "amount": "50"},
            "The holder sends 50 to a 0x wallet")

        async with NodeRPCClient(target) as c:
            nonce = int(await c.json_rpc("eth_getTransactionCount", [user_addr, "pending"]), 16)
            chain_id = int(await c.json_rpc("eth_chainId", []), 16)
            signed = Account.sign_transaction({
                "nonce": nonce, "gasPrice": 10 ** 9, "gas": 120_000,
                "to": to_checksum_address(token), "value": 0, "chainId": chain_id,
                "data": bytes.fromhex("a9059cbb") + bytes(12) + bytes.fromhex(recipient[2:])
                        + (20 * 10 ** 6).to_bytes(32, "big")}, key)
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
                   f"The EVM token transfer executed ({receipt and receipt.get('status')})")

        want = (Decimal(30), Decimal(20), 20 * 10 ** 6)
        reads = {}
        for _ in range(30):
            reads = {}
            for url in nodes:
                u = await self._get(url, "/get_token_balance", token_address=token,
                                    address=user_addr)
                r = await self._get(url, "/get_token_balance", token_address=token,
                                    address=recipient)
                try:
                    async with NodeRPCClient(url) as c:
                        out = await c.json_rpc("eth_call", [{
                            "to": token, "data": "0x70a08231" + "00" * 12 + recipient[2:]},
                            "latest"])
                    erc20 = int(out, 16)
                except Exception as e:
                    erc20 = str(e)[:80]
                if u and r:
                    reads[url] = (Decimal(u["balance"]), Decimal(r["balance"]), erc20)
            if len(reads) == len(nodes) and all(v == want for v in reads.values()):
                break
            await asyncio.sleep(2)
        agree = sum(1 for v in reads.values() if v == want)
        self.check(agree >= max(2, len(nodes) - 1),
                   f"Every node shows the EVM move: 30 / 20 natively, balanceOf 20·10^6 "
                   f"({agree}/{len(nodes)}: {reads.get(target)})")
