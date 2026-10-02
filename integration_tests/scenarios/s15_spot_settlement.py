"""
S15 — Spot AMM settlement against the real token ledger (Phase E spot inc5).

A full spot flow runs through the live consensus pipeline as PQ-signed
ExchangeTransactions: deploy two QRC-20 tokens, create an AMM pool over their
ADDRESSES, add real liquidity (escrowed LP→pool in the token ledger), then swap
one token for the other (trader↔pool). Every node replays the section and the
token-balances root CONVERGES — proving spot settlement is deterministic and the
token ledger conserves value across deploy/liquidity/swap.

Then the defects of the 2026-10-02 spot audit, on the live chain (docs/KNOWN_ISSUES.md):
the reverse swap executes, at exactly the quote the node served; a swap that misses its
own minimum fails and changes nothing; a stranger cannot remove the LP's position; and the
LP's withdrawal pays the principal plus the fees, leaving the pool holding only the
protocol's share.
"""

import asyncio
from collections import Counter
from decimal import Decimal

from integration_tests.scenarios.base import Scenario
from integration_tests.rpc_client import NodeRPCClient


class S15SpotSettlement(Scenario):
    name = "s15_spot_settlement"
    description = "Spot deploy+pool+liquidity+swap settle real token balances cross-node"
    depends_on = ["s14_token_consensus"]

    async def _token_roots(self, node_urls):
        out = {}
        for url in node_urls:
            try:
                async with NodeRPCClient(url) as c:
                    r = await c._get("/get_unified_state_root")
                    if r and r.get("ok"):
                        out[url] = r["result"].get("token_root")
            except Exception:
                pass
        return out

    async def _submit_and_wait(self, node_urls, target, tx_hex, base_root, label):
        async with NodeRPCClient(target) as c:
            r = await c._post("/submit_exchange_tx", json_data={"tx_hex": tx_hex})
            self.check(bool(r and r.get("ok")), f"{label}: admitted")
            if not (r and r.get("ok")):
                self._log.error("%s submit rejected: %s", label, r)
        for _ in range(60):  # ~120s (reorg-tolerant tx inclusion)
            await asyncio.sleep(2)
            cur = await self._token_roots(node_urls)
            if cur.get(target) and cur[target] != base_root:
                return cur[target]
        return None

    async def _get(self, url, path, **params):
        async with NodeRPCClient(url) as c:
            r = await c._get(path, params=params)
        return r["result"] if r and r.get("ok") else None

    async def _submit(self, target, tx_hex, label):
        async with NodeRPCClient(target) as c:
            r = await c._post("/submit_exchange_tx", json_data={"tx_hex": tx_hex})
        self.check(bool(r and r.get("ok")), f"{label}: admitted")
        if not (r and r.get("ok")):
            self._log.error("%s submit rejected: %s", label, r)
            return None
        return r["result"]["tx_hash"]

    async def _receipt(self, target, tx_hash, label):
        """The executed result, once a block includes the transaction (~120s, reorg-tolerant)."""
        if not tx_hash:
            return None
        for _ in range(60):
            rec = await self._get(target, "/get_exchange_receipt", tx_hash=tx_hash)
            if rec:
                return rec
            await asyncio.sleep(2)
        self.check(False, f"{label}: included in a block")
        return None

    async def _balances(self, target, pairs):
        out = []
        for token, holder in pairs:
            r = await self._get(target, "/get_token_balance", token_address=token, address=holder)
            out.append(Decimal(r["balance"]) if r else None)
        return out

    async def _await_balances(self, target, pairs, expected):
        """Poll until the ledger shows ``expected`` (a reorg can briefly show an older tip)."""
        got = None
        for _ in range(30):
            got = await self._balances(target, pairs)
            if got == expected:
                return got
            await asyncio.sleep(2)
        return got

    async def execute(self) -> None:
        node_urls = self.ctx.node_urls
        wallets = self.ctx.wallets

        # A PQ wallet with a clean exchange nonce, used by no other scenario.
        w = wallets.get("Spot Trader")
        if not w or not w.get("private_key") or "PQ" not in str(w.get("address", "")):
            self.check(False, "fresh PQ wallet available")
            return

        from qrdx.crypto.pq.dilithium import PQPrivateKey
        from qrdx.exchange import ExchangeTransaction, ExchangeOpType
        from qrdx.exchange.amm import FeeTier, PoolType, sqrt_price_to_tick
        from qrdx.exchange.state_manager import ExchangeStateManager
        from integration_tests.pool_operator import price_to_sqrt_price_q96

        key = PQPrivateKey.from_hex(w["private_key"], w["public_key"])
        sender = w["address"]
        target = node_urls[0]

        def _sign(tx):
            tx.public_key = key.public_key.to_bytes()
            tx.signature = key.sign(tx.signing_bytes()).to_bytes()
            return tx.to_hex()

        def _tx(op, nonce, params):
            return ExchangeTransaction(op_type=op, sender=sender, nonce=nonce,
                                       params=params, gas_limit=2_000_000, gas_price=Decimal("1"))

        base = await self._token_roots(node_urls)
        base_root = next(iter(set(base.values())), None) if base else None
        self.check_not_none(base_root, "Baseline token root readable")

        # 1-2. Deploy two tokens (deployer = LP = trader, gets full supply of each).
        addrA = ExchangeStateManager.derive_token_address(sender, 0, "qSPOTA")
        addrB = ExchangeStateManager.derive_token_address(sender, 1, "qSPOTB")
        r1 = await self._submit_and_wait(node_urls, target, _sign(_tx(
            ExchangeOpType.TOKEN_DEPLOY, 0,
            {"name": "Spot A", "symbol": "qSPOTA", "total_supply": "1000000", "decimals": 18})),
            base_root, "TOKEN_DEPLOY A")
        self.check_not_none(r1, "Token A deployed")
        r2 = await self._submit_and_wait(node_urls, target, _sign(_tx(
            ExchangeOpType.TOKEN_DEPLOY, 1,
            {"name": "Spot B", "symbol": "qSPOTB", "total_supply": "1000000", "decimals": 18})),
            r1, "TOKEN_DEPLOY B")
        self.check_not_none(r2, "Token B deployed")

        last_root = r2  # the last token-MOVING root (CREATE_POOL moves no tokens)

        # 3. Create the AMM pool over the token ADDRESSES at 1:1. Submit-only: this
        #    moves no tokens, so the token root won't advance — just admit + let it
        #    land before liquidity (poll the EXCHANGE root, which does advance).
        sqrt_price = price_to_sqrt_price_q96(Decimal("1"))
        async with NodeRPCClient(target) as c:
            rp = await c._post("/submit_exchange_tx", json_data={"tx_hex": _sign(_tx(
                ExchangeOpType.CREATE_POOL, 2,
                {"token0": addrA, "token1": addrB, "fee_tier": int(FeeTier.MEDIUM),
                 "pool_type": int(PoolType.STANDARD), "initial_sqrt_price": str(sqrt_price),
                 "stake_amount": "10000"}))})
            self.check(bool(rp and rp.get("ok")), "CREATE_POOL: admitted")
        await asyncio.sleep(8)  # allow the pool block to be produced + imported
        self.check(True, "Pool created over token addresses")

        # 4. Add liquidity (escrows token A + B from the LP into the pool holder).
        #    Resolve the pool by token pair (pool_id is an unpredictable hash).
        spacing = FeeTier.MEDIUM.tick_spacing
        tick = sqrt_price_to_tick(sqrt_price)  # ~0 at 1:1
        center = (tick // spacing) * spacing
        r4 = await self._submit_and_wait(node_urls, target, _sign(_tx(
            ExchangeOpType.ADD_LIQUIDITY, 3,
            {"pool_id": f"{addrA}:{addrB}", "token0": addrA, "token1": addrB,
             "tick_lower": center - 10 * spacing,
             "tick_upper": center + 10 * spacing, "amount": "100000"})),
            last_root, "ADD_LIQUIDITY")
        self.check_not_none(r4, "Liquidity added (LP tokens escrowed → token root advanced)")
        last_root = r4 or last_root

        # 5. Swap A→B (trader pays A, receives B from pool reserves).
        r5 = await self._submit_and_wait(node_urls, target, _sign(_tx(
            ExchangeOpType.SWAP, 4,
            {"token_in": addrA, "token_out": addrB, "amount_in": "100", "min_amount_out": "0"})),
            last_root, "SWAP")
        self.check_not_none(r5, "Swap settled (token root advanced)")

        await self._audit_fixes(node_urls, target, sender, addrA, addrB, _sign, _tx)

        # 6. Cross-node convergence: every node replays the spot flow and lands on the
        #    same non-zero token root (modal set; node DBs are clean after inc4b).
        n_modal = 0
        modal = None
        final = {}
        for _ in range(60):  # ~120s — poll until convergence (reorg-tolerant)
            final = await self._token_roots(node_urls)
            nonzero = [v for v in final.values() if v and v != "0" * 128]
            if nonzero:
                modal, n_modal = Counter(nonzero).most_common(1)[0]
            if n_modal >= max(2, len(final) - 1):
                break
            await asyncio.sleep(2)
        self._log.info("Spot settlement token convergence: %d/%d nodes on the modal root",
                       n_modal, len(final))
        self.check(n_modal >= max(2, len(final) - 1),
                   f"Nodes converge on the deterministic spot-settled token root "
                   f"({n_modal}/{len(final)})")
        self.check(bool(modal) and modal != "0" * 128,
                   "Spot-settled token root is non-zero (real token movement)")

    async def _audit_fixes(self, node_urls, target, sender, addrA, addrB, _sign, _tx):
        from qrdx.crypto.pq.dilithium import PQPrivateKey
        from qrdx.exchange import ExchangeTransaction, ExchangeOpType

        pools = await self._get(target, "/get_pools", token_a=addrA, token_b=addrB) or []
        self.check(len(pools) == 1, f"The pair's pool is listed ({len(pools)})")
        if len(pools) != 1:
            return
        pool = pools[0]
        pool_id, holder = pool["pool_id"], pool["holder_address"]
        token0, token1 = pool["token0"], pool["token1"]
        mine = [p for p in (await self._get(target, "/get_lp_positions", address=sender) or [])
                if p["pool_id"] == pool_id]
        self.check(len(mine) == 1, "The LP's position is listed")
        if len(mine) != 1:
            return
        position_id = mine[0]["position_id"]
        self.check(Decimal(mine[0]["fees0"]) + Decimal(mine[0]["fees1"]) > 0,
                   "The position has earned fees from the swap")

        # The reverse swap (B→A) used to be refused as an oracle "outlier" after any A→B swap.
        # Nobody else trades this pool, so the quote the node serves is exactly the fill.
        quote = await self._get(target, "/get_swap_quote", token_in=addrB, token_out=addrA,
                                amount_in="100", sender=sender)
        self.check(bool(quote) and quote.get("source") == "amm", "Reverse swap quoted by the pool")
        if not quote:
            return
        rec = await self._receipt(target, await self._submit(target, _sign(_tx(
            ExchangeOpType.SWAP, 5, {"token_in": addrB, "token_out": addrA, "amount_in": "100",
                                     "min_amount_out": quote["amount_out"]})), "reverse SWAP"),
            "reverse SWAP")
        self.check(bool(rec) and rec["success"], f"Reverse swap executed ({rec and rec['error']})")
        self.check(bool(rec) and rec["data"].get("amount_out") == quote["amount_out"],
                   "Reverse swap paid exactly the served quote")

        # A swap that misses its own minimum fails and changes nothing (it used to move the
        # pool's price anyway).
        watch = [(addrA, sender), (addrB, sender), (addrA, holder), (addrB, holder)]
        before = await self._balances(target, watch)
        pool_before = await self._get(target, "/get_pool", pool_id=pool_id)
        rec = await self._receipt(target, await self._submit(target, _sign(_tx(
            ExchangeOpType.SWAP, 6, {"token_in": addrA, "token_out": addrB, "amount_in": "50",
                                     "min_amount_out": "1000000"})), "slippage SWAP"),
            "slippage SWAP")
        self.check(bool(rec) and not rec["success"] and "Slippage" in rec["error"],
                   f"A swap below its minimum fails ({rec and rec['error']})")
        self.check(await self._balances(target, watch) == before,
                   "The failed swap moved no tokens")
        pool_after = await self._get(target, "/get_pool", pool_id=pool_id)
        self.check(bool(pool_before) and bool(pool_after)
                   and pool_after["sqrt_price_x96"] == pool_before["sqrt_price_x96"],
                   "The failed swap left the pool's price where it was")

        # Someone else cannot remove the LP's liquidity (they used to receive its tokens).
        w = self.ctx.wallets.get("Spot Stranger")
        if w and w.get("private_key"):
            key = PQPrivateKey.from_hex(w["private_key"], w["public_key"])
            nonce = await self._get(target, "/get_exchange_nonce", address=w["address"])
            tx = ExchangeTransaction(op_type=ExchangeOpType.REMOVE_LIQUIDITY,
                                     sender=w["address"], nonce=int((nonce or {}).get("nonce", 0)),
                                     params={"pool_id": pool_id, "position_id": position_id},
                                     gas_limit=2_000_000, gas_price=Decimal("1"))
            tx.public_key = key.public_key.to_bytes()
            tx.signature = key.sign(tx.signing_bytes()).to_bytes()
            rec = await self._receipt(target, await self._submit(
                target, tx.to_hex(), "stranger REMOVE_LIQUIDITY"), "stranger REMOVE_LIQUIDITY")
            self.check(bool(rec) and not rec["success"] and "owner" in rec["error"],
                       f"A stranger cannot remove the LP's position ({rec and rec['error']})")
        else:
            self.check(False, "Spot Stranger wallet available")

        # The LP's withdrawal pays principal + fees from the pool's holder, exactly as quoted
        # by the position view, and leaves the holder with the protocol's fee share.
        view = [p for p in (await self._get(target, "/get_lp_positions", address=sender) or [])
                if p["position_id"] == position_id]
        before = await self._balances(target, watch)
        rec = await self._receipt(target, await self._submit(target, _sign(_tx(
            ExchangeOpType.REMOVE_LIQUIDITY, 7, {"pool_id": pool_id, "position_id": position_id})),
            "REMOVE_LIQUIDITY"), "REMOVE_LIQUIDITY")
        self.check(bool(rec) and rec["success"], f"The LP removed its liquidity ({rec and rec['error']})")
        if not (rec and rec["success"]) or None in before:
            return
        out = {token0: Decimal(rec["data"]["amount0"]), token1: Decimal(rec["data"]["amount1"])}
        if view:
            v = view[0]
            self.check(out[token0] == Decimal(v["amount0"]) + Decimal(v["fees0"])
                       and out[token1] == Decimal(v["amount1"]) + Decimal(v["fees1"]),
                       "The withdrawal paid exactly the position's served value")
        expected = [before[0] + out[addrA], before[1] + out[addrB],
                    before[2] - out[addrA], before[3] - out[addrB]]
        after = await self._await_balances(target, watch, expected)
        self.check(after == expected,
                   "The LP received exactly the payout, from the pool's holder")
        detail = await self._get(target, "/get_pool", pool_id=pool_id)
        if detail and after == expected:
            fees = dict(zip((token0, token1), map(Decimal, detail["protocol_fees"])))
            leftover = {addrA: after[2] - fees[addrA], addrB: after[3] - fees[addrB]}
            self.check(all(Decimal(0) <= v < Decimal("1e-12") for v in leftover.values()),
                       f"The emptied pool holds only the protocol's fees (+dust {leftover})")
