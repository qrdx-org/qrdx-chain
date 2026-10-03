"""
S12 — Exchange Transaction Consensus (end-to-end)

The live multi-node proof for the exchange consensus pipeline (Phases D1–D3):

  submit  → a real PQ-signed ExchangeTransaction is admitted to node mempools
  include → a validator proposer pulls it, executes it, and writes the exchange
            section + declared exchange_state_root into the block body
  replay  → every node re-executes + verifies the section on import (D3)
  agree   → all nodes converge on the SAME new exchange_state_root

This converts the D3 unit-level guarantees into an observed cross-node property.
"""

import asyncio
from decimal import Decimal

from integration_tests.scenarios.base import Scenario
from integration_tests.rpc_client import NodeRPCClient


class S12ExchangeConsensus(Scenario):
    name = "s12_exchange_consensus"
    description = "Verify an exchange tx flows submit→block→replay→cross-node consistency"
    depends_on = ["s03_block_production"]

    async def _roots(self, node_urls):
        """Read each node's exchange state root + pool count."""
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

    async def execute(self) -> None:
        node_urls = self.ctx.node_urls
        wallets = self.ctx.wallets

        # A PQ wallet to sign the exchange transaction.
        w = wallets.get("Pool Creator") or wallets.get("Token Deployer")
        if not w or not w.get("private_key"):
            self.check(False, "PQ wallet with key available")
            return

        from qrdx.crypto.pq.dilithium import PQPrivateKey
        from qrdx.exchange import ExchangeTransaction, ExchangeOpType
        from qrdx.exchange.amm import FeeTier, PoolType

        key = PQPrivateKey.from_hex(w["private_key"], w["public_key"])
        sender = w["address"]

        # 1. Baseline: every node must agree on the (empty) exchange root.
        initial = await self._roots(node_urls)
        self.check(len(initial) >= 2, f"Exchange root readable on {len(initial)} nodes")
        init_roots = {v["exchange_state_root"] for v in initial.values()}
        self.check(len(init_roots) == 1, "Initial exchange root consistent across nodes")
        base_root = next(iter(init_roots), None)

        # 2. Build + PQ-sign a real exchange transaction (create a trading pair).
        tx = ExchangeTransaction(
            op_type=ExchangeOpType.CREATE_POOL, sender=sender, nonce=0,
            params={"token0": "qBTC", "token1": "qUSD", "fee_tier": int(FeeTier.MEDIUM),
                    "pool_type": int(PoolType.STANDARD), "initial_sqrt_price": "173.205080756",
                    "stake_amount": "10000"},
            gas_limit=1_000_000, gas_price=10**9,
        )
        tx.public_key = key.public_key.to_bytes()
        tx.signature = key.sign(tx.signing_bytes()).to_bytes()
        tx_hex = tx.to_hex()

        # 3. Submit to a SINGLE validator node. Submitting everywhere would let
        #    several validators each include the same tx in different blocks at
        #    different heights — and the state root commits to the height — so the
        #    canonical path is one submission → one inclusion → all nodes import
        #    that one block and converge.
        admitted = False
        async with NodeRPCClient(node_urls[0]) as c:
            r = await c._post("/submit_exchange_tx", json_data={"tx_hex": tx_hex})
            admitted = bool(r and r.get("ok"))
        self.check(admitted, "Exchange tx admitted to proposer node")

        # 4. Poll until the proposer node has included + executed the tx: the pool it
        #    creates exists. (Not "the exchange root changed": the root commits to the
        #    block height and the exchange ticks on every block, so it changes every
        #    block whether or not anything was included.)
        target = node_urls[0]
        included = False
        for attempt in range(60):  # up to ~120s (reorg-tolerant)
            await asyncio.sleep(2)
            cur = await self._roots(node_urls)
            have = sum(1 for v in cur.values() if v.get("pools", 0) >= 1)
            self._log.info("attempt %d: %d/%d node(s) hold the new pool",
                           attempt + 1, have, len(cur))
            if cur.get(target, {}).get("pools", 0) >= 1:
                included = True
                break
        self.check(included, "Exchange tx included + executed (the pool exists on the proposer)")

        # 5. Determinism: nodes at the same height that hold the pool report one root.
        #    Sampled until a quorum sits at one height (they usually do: blocks are 2 s).
        need = max(2, len(node_urls) - 1)
        agreed, seen = False, {}
        for _ in range(30):
            cur = await self._roots(node_urls)
            groups = {}
            for v in cur.values():
                if v.get("pools", 0) >= 1 and "block_height" in v:
                    groups.setdefault(v["block_height"], []).append(v["exchange_state_root"])
            for height, roots in groups.items():
                if len(roots) >= need:
                    seen = {"height": height, "roots": len(set(roots)), "nodes": len(roots)}
                    agreed = len(set(roots)) == 1
            if agreed:
                break
            await asyncio.sleep(1)
        self.check(agreed, f"Nodes at one height share one exchange root ({seen})")
