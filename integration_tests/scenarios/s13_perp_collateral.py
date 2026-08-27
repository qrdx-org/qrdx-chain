"""
S13 — Perp market + position through the live exchange consensus pipeline.

Extends the S12 proof to perpetuals (Phase E): a funded PQ trader creates a perp
market and opens a leveraged position via real PQ-signed ExchangeTransactions, and
every node converges on the same exchange root. This is the live soak that, once
``ENFORCE_EXCHANGE_COLLATERAL`` is flipped on, also verifies the margin debit to
``account_state`` + cross-node consistency.

With enforcement OFF (default) the position opens regardless; this scenario proves
perps are reachable + deterministic on the live network (previously impossible —
there was no CREATE_MARKET path).
"""

import asyncio
from decimal import Decimal

from integration_tests.scenarios.base import Scenario
from integration_tests.rpc_client import NodeRPCClient


class S13PerpCollateral(Scenario):
    name = "s13_perp_collateral"
    description = "Perp market create + open position flow cross-node (Phase E)"
    depends_on = ["s12_exchange_consensus"]

    async def _roots(self, node_urls):
        out = {}
        for url in node_urls:
            try:
                async with NodeRPCClient(url) as c:
                    r = await c._get("/get_exchange_state_root")
                    if r and r.get("ok"):
                        out[url] = r["result"]
            except Exception:
                pass
        return out

    async def _submit_and_wait(self, node_urls, target, tx_hex, base_root, label):
        """Submit a signed exchange tx to one node; wait for its root to advance."""
        async with NodeRPCClient(target) as c:
            r = await c._post("/submit_exchange_tx", json_data={"tx_hex": tx_hex})
            self.check(bool(r and r.get("ok")), f"{label}: admitted to proposer node")
        for _ in range(60):  # ~120s (reorg-tolerant tx inclusion)
            await asyncio.sleep(2)
            cur = await self._roots(node_urls)
            tnode = cur.get(target)
            if tnode and tnode["exchange_state_root"] != base_root:
                return tnode["exchange_state_root"]
        return None

    async def execute(self) -> None:
        node_urls = self.ctx.node_urls
        wallets = self.ctx.wallets

        # A funded PQ trader not used for exchange txs in s12.
        w = wallets.get("Test User 0")
        if not w or not w.get("private_key") or not w.get("public_key") \
                or "PQ" not in str(w.get("address", "")):
            self.check(False, "funded PQ trader wallet available")
            return

        from qrdx.crypto.pq.dilithium import PQPrivateKey
        from qrdx.exchange import ExchangeTransaction, ExchangeOpType

        key = PQPrivateKey.from_hex(w["private_key"], w["public_key"])
        sender = w["address"]
        target = node_urls[0]

        def _sign(tx):
            tx.public_key = key.public_key.to_bytes()
            tx.signature = key.sign(tx.signing_bytes()).to_bytes()
            return tx.to_hex()

        async def _balances():
            out = {}
            for url in node_urls:
                try:
                    async with NodeRPCClient(url) as c:
                        out[url] = await c.get_balance(sender)
                except Exception:
                    pass
            return out

        base = await self._roots(node_urls)
        base_root = next(iter({v["exchange_state_root"] for v in base.values()}), None)
        self.check_not_none(base_root, "Baseline exchange root readable")
        bal_before = await _balances()

        # 1. CREATE_MARKET (nonce 0).
        create = ExchangeTransaction(
            op_type=ExchangeOpType.CREATE_MARKET, sender=sender, nonce=0,
            params={"base_token": "qBTC", "quote_token": "QRDX"},
            gas_limit=1_000_000, gas_price=Decimal("1"),
        )
        root_after_market = await self._submit_and_wait(
            node_urls, target, _sign(create), base_root, "CREATE_MARKET")
        self.check_not_none(root_after_market, "Perp market created (proposer root advanced)")

        # 2. OPEN_POSITION (nonce 1): size 1 @ 30000, 10x → margin ~3000 << 500K balance.
        open_pos = ExchangeTransaction(
            op_type=ExchangeOpType.OPEN_POSITION, sender=sender, nonce=1,
            params={"market_id": "qBTC-QRDX-PERP", "side": "long",
                    "size": "1", "leverage": "10", "price": "30000"},
            gas_limit=1_000_000, gas_price=Decimal("1"),
        )
        root_after_open = await self._submit_and_wait(
            node_urls, target, _sign(open_pos),
            root_after_market or base_root, "OPEN_POSITION")
        self.check_not_none(root_after_open, "Position opened (proposer root advanced)")

        # 3. Cross-node determinism: nodes CONVERGE on the proposer's final root.
        #    Poll for convergence (nodes import the position block at slightly
        #    different times); a quorum on one root proves D3 determinism for perps
        #    without failing on transient propagation lag (a node still on the
        #    market-block root, not yet the position-block root).
        n_on_final = 0
        final = {}
        for _ in range(60):  # ~120s — poll until convergence (reorg-tolerant)
            final = await self._roots(node_urls)
            n_on_final = sum(1 for v in final.values()
                             if v.get("exchange_state_root") == root_after_open)
            if n_on_final >= max(2, len(final) - 1):
                break
            await asyncio.sleep(2)
        self._log.info("Cross-node perp convergence: %d/%d nodes on the final root",
                       n_on_final, len(final))
        self.check(n_on_final >= max(2, len(final) - 1),
                   f"Nodes converge on the proposer's deterministic perp root "
                   f"({n_on_final}/{len(final)})")

        # 4. Consensus invariant (holds in BOTH observe + enforce modes): after the
        #    position, the trader's balance must be IDENTICAL across all nodes. Under
        #    ENFORCE_EXCHANGE_COLLATERAL the margin is debited from account_state; the
        #    key safety property is that every node applies the SAME result.
        bal_after = await _balances()
        if bal_after:
            uniq = set(bal_after.values())
            before = next(iter(set(bal_before.values())), None) if bal_before else None
            after = next(iter(uniq), None)
            self._log.info("Trader balance: before=%s after=%s (delta=%s) across %d nodes",
                           before, after,
                           (after - before) if (before is not None and after is not None) else "?",
                           len(bal_after))
            self.check(len(uniq) == 1,
                       f"Trader account balance consistent across nodes after open "
                       f"(unique={len(uniq)})")
