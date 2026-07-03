"""
S17 — CLOB order-book settlement against the real token ledger (Phase E, ENFORCE_
ORDERBOOK_SETTLEMENT). A PQ trader deploys two QRC-20 tokens, creates the order book
over their addresses (via CREATE_POOL), then places a RESTING limit BUY order — which
ESCROWS quote tokens (amount*price) into the book's deterministic escrow holder — and
finally CANCELS it, refunding the escrow.

Validates the core new CLOB consensus logic cross-node:
  * escrow-on-place moves real token balances (the token root advances + CONVERGES on
    every node, so the escrow is deterministic), and
  * cancel refunds EXACTLY (the token root returns to its pre-place value → conservation).
Match settlement (needs two wallets vs self-trade prevention) is a follow-up.
"""

import asyncio
from collections import Counter
from decimal import Decimal

from integration_tests.scenarios.base import Scenario
from integration_tests.rpc_client import NodeRPCClient


class S17ClobSettlement(Scenario):
    name = "s17_clob_settlement"
    description = "CLOB limit-order escrow-on-place + cancel-refund settle real token balances cross-node"
    depends_on = ["s15_spot_settlement"]

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

    def _modal_root(self, roots):
        nz = [v for v in roots.values() if v and v != "0" * 128]
        return Counter(nz).most_common(1)[0] if nz else (None, 0)

    async def _submit_and_wait(self, node_urls, target, tx_hex, base_root, label):
        async with NodeRPCClient(target) as c:
            r = await c._post("/submit_exchange_tx", json_data={"tx_hex": tx_hex})
            self.check(bool(r and r.get("ok")), f"{label}: admitted")
            if not (r and r.get("ok")):
                self._log.error("%s submit rejected: %s", label, r)
        for _ in range(25):  # ~50s
            await asyncio.sleep(2)
            cur = await self._token_roots(node_urls)
            if cur.get(target) and cur[target] != base_root:
                return cur[target]
        return None

    async def execute(self) -> None:
        node_urls = self.ctx.node_urls
        wallets = self.ctx.wallets

        # A PQ wallet with a CLEAN exchange nonce: validators don't submit exchange txs, so
        # Validator 1's exchange nonce is 0 (Validator 2 is s15's; Pool Creator is s12's).
        w = wallets.get("Validator 1")
        if not w or not w.get("private_key") or "PQ" not in str(w.get("address", "")):
            self.check(False, "funded PQ wallet available")
            return

        from qrdx.crypto.pq.dilithium import PQPrivateKey
        from qrdx.exchange import ExchangeTransaction, ExchangeOpType
        from qrdx.exchange.amm import FeeTier, PoolType
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

        # 1-2. Deploy base + quote tokens (trader holds full supply of each).
        addrA = ExchangeStateManager.derive_token_address(sender, 0, "qCLOBA")  # base (token0)
        addrB = ExchangeStateManager.derive_token_address(sender, 1, "qCLOBB")  # quote (token1)
        r1 = await self._submit_and_wait(node_urls, target, _sign(_tx(
            ExchangeOpType.TOKEN_DEPLOY, 0,
            {"name": "CLOB A", "symbol": "qCLOBA", "total_supply": "1000000", "decimals": 18})),
            base_root, "TOKEN_DEPLOY A")
        self.check_not_none(r1, "Token A (base) deployed")
        r2 = await self._submit_and_wait(node_urls, target, _sign(_tx(
            ExchangeOpType.TOKEN_DEPLOY, 1,
            {"name": "CLOB B", "symbol": "qCLOBB", "total_supply": "1000000", "decimals": 18})),
            r1, "TOKEN_DEPLOY B")
        self.check_not_none(r2, "Token B (quote) deployed")

        # 3. Create the order book over the token addresses (CREATE_POOL makes the matching
        #    OrderBook for the pair "token0:token1"). Moves no tokens.
        pair = f"{addrA}:{addrB}"
        sqrt_price = price_to_sqrt_price_q96(Decimal("1"))
        async with NodeRPCClient(target) as c:
            rp = await c._post("/submit_exchange_tx", json_data={"tx_hex": _sign(_tx(
                ExchangeOpType.CREATE_POOL, 2,
                {"token0": addrA, "token1": addrB, "fee_tier": int(FeeTier.MEDIUM),
                 "pool_type": int(PoolType.STANDARD), "initial_sqrt_price": str(sqrt_price),
                 "stake_amount": "10000"}))})
            self.check(bool(rp and rp.get("ok")), "CREATE_POOL (order book): admitted")
        await asyncio.sleep(8)
        pre_place = self._modal_root(await self._token_roots(node_urls))[0] or r2

        # 4. Place a RESTING limit BUY: buy 100 base @ price 2 → escrows 100*2 = 200 quote
        #    (token B) from the trader into the book escrow holder. No asks exist, so it rests.
        place_tx = _tx(ExchangeOpType.PLACE_ORDER, 3,
                       {"pair": pair, "side": "buy", "order_type": "limit",
                        "price": "2", "amount": "100"})
        order_id = place_tx.tx_hash()[:16]  # the node derives the order id the same way
        r4 = await self._submit_and_wait(node_urls, target, _sign(place_tx), pre_place,
                                         "PLACE_ORDER (resting buy)")
        self.check_not_none(r4, "Limit buy placed → quote escrowed (token root advanced)")

        # 5. Cross-node convergence of the escrow settlement.
        n_modal = 0; modal = None; final = {}
        for _ in range(12):
            final = await self._token_roots(node_urls)
            modal, n_modal = self._modal_root(final)
            if n_modal >= max(2, len(final) - 1):
                break
            await asyncio.sleep(2)
        self.check(n_modal >= max(2, len(final) - 1),
                   f"Nodes converge on the escrow-settled token root ({n_modal}/{len(final)})")
        self.check(bool(modal) and modal != pre_place,
                   "Escrow moved real quote tokens (root advanced from pre-place)")

        # 6. Cancel → refund the escrowed quote. The token root must return to its EXACT
        #    pre-place value (escrow fully refunded ⇒ token ledger conserves).
        r6 = await self._submit_and_wait(node_urls, target, _sign(_tx(
            ExchangeOpType.CANCEL_ORDER, 4, {"order_id": order_id, "pair": pair})),
            modal, "CANCEL_ORDER (refund escrow)")
        self.check_not_none(r6, "Order cancelled (token root moved on refund)")
        self.check(r6 == pre_place,
                   f"Cancel refunded escrow EXACTLY — token root returned to pre-place "
                   f"(conservation): {str(r6)[:12]} == {str(pre_place)[:12]}")
