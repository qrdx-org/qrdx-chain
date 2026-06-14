"""
S14 — QRC-20 token deploy + transfer through the live exchange consensus pipeline.

Phase E (spot) makes token state a CONSENSUS object: a token is deployed and
transferred via real PQ-signed TOKEN_DEPLOY / TOKEN_TRANSFER ExchangeTransactions,
replayed by every node, and the per-node token-balances root (the new domain in
the unified state root) CONVERGES — proving the token ledger is replicated by
consensus replay, not written out-of-band to a single node.

This is the live proof for the consensus-token increment that precedes binding the
real token root into the enforced unified root and spot swap settlement.
"""

import asyncio
from decimal import Decimal

from integration_tests.scenarios.base import Scenario
from integration_tests.rpc_client import NodeRPCClient


class S14TokenConsensus(Scenario):
    name = "s14_token_consensus"
    description = "QRC-20 token deploy + transfer cross-node via consensus (Phase E spot)"
    depends_on = ["s13_perp_collateral"]

    async def _token_roots(self, node_urls):
        """Per-node token-balances root via /get_unified_state_root."""
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
        """Submit a signed exchange tx to one node; wait for its token root to advance."""
        async with NodeRPCClient(target) as c:
            r = await c._post("/submit_exchange_tx", json_data={"tx_hex": tx_hex})
            self.check(bool(r and r.get("ok")), f"{label}: admitted to proposer node")
        for _ in range(25):  # ~50s
            await asyncio.sleep(2)
            cur = await self._token_roots(node_urls)
            if cur.get(target) and cur[target] != base_root:
                return cur[target]
        return None

    async def execute(self) -> None:
        node_urls = self.ctx.node_urls
        wallets = self.ctx.wallets

        # A funded PQ wallet not used for exchange txs elsewhere (fresh exchange nonce).
        w = wallets.get("Token Deployer")
        if not w or not w.get("private_key") or not w.get("public_key") \
                or "PQ" not in str(w.get("address", "")):
            self.check(False, "funded PQ deployer wallet available")
            return

        from qrdx.crypto.pq.dilithium import PQPrivateKey
        from qrdx.exchange import ExchangeTransaction, ExchangeOpType
        from qrdx.exchange.state_manager import ExchangeStateManager

        key = PQPrivateKey.from_hex(w["private_key"], w["public_key"])
        sender = w["address"]
        target = node_urls[0]

        def _sign(tx):
            tx.public_key = key.public_key.to_bytes()
            tx.signature = key.sign(tx.signing_bytes()).to_bytes()
            return tx.to_hex()

        base = await self._token_roots(node_urls)
        base_root = next(iter(set(base.values())), None) if base else None
        self.check_not_none(base_root, "Baseline token root readable")

        # 1. TOKEN_DEPLOY (nonce 0): mint 1,000,000 qSPOT to the deployer.
        symbol = "qSPOT"
        deploy = ExchangeTransaction(
            op_type=ExchangeOpType.TOKEN_DEPLOY, sender=sender, nonce=0,
            params={"name": "Quantum Spot", "symbol": symbol,
                    "total_supply": "1000000", "decimals": 18},
            gas_limit=1_000_000, gas_price=Decimal("1"),
        )
        token_address = ExchangeStateManager.derive_token_address(sender, 0, symbol)
        root_after_deploy = await self._submit_and_wait(
            node_urls, target, _sign(deploy), base_root, "TOKEN_DEPLOY")
        self.check_not_none(root_after_deploy, "Token deployed (token root advanced)")
        self.check(root_after_deploy != base_root, "Deploy changed the token root (state landed)")

        # 2. TOKEN_TRANSFER (nonce 1): move 1,000 qSPOT to another wallet.
        recipient = (wallets.get("Pool Creator") or {}).get("address") or (sender[:-4] + "dead")
        transfer = ExchangeTransaction(
            op_type=ExchangeOpType.TOKEN_TRANSFER, sender=sender, nonce=1,
            params={"token_address": token_address, "to": recipient, "amount": "1000"},
            gas_limit=1_000_000, gas_price=Decimal("1"),
        )
        root_after_transfer = await self._submit_and_wait(
            node_urls, target, _sign(transfer), root_after_deploy, "TOKEN_TRANSFER")
        self.check_not_none(root_after_transfer, "Token transferred (token root advanced)")

        # 3. Cross-node convergence: nodes that received the token PURELY via consensus
        #    replay land on the SAME non-zero token root — the replication proof. We
        #    measure the MODAL root (largest agreeing set), not matches to the proposer:
        #    until the harness deploys s05's tokens through consensus too (inc4b), the
        #    proposer node also carries those out-of-band token rows and so reports a
        #    different (polluted) root, while the importer quorum agrees on the
        #    consensus-only ledger. A quorum on one non-zero root is the determinism proof.
        from collections import Counter
        n_on_modal = 0
        modal_root = None
        final = {}
        for _ in range(12):  # ~24s
            final = await self._token_roots(node_urls)
            nonzero = [v for v in final.values() if v and v != "0" * 128]
            if nonzero:
                modal_root, n_on_modal = Counter(nonzero).most_common(1)[0]
            if n_on_modal >= max(2, len(final) - 1):
                break
            await asyncio.sleep(2)
        self._log.info("Cross-node token convergence: %d/%d nodes on the modal token root",
                       n_on_modal, len(final))
        self.check(n_on_modal >= max(2, len(final) - 1),
                   f"Nodes converge on a deterministic non-zero token root via consensus "
                   f"({n_on_modal}/{len(final)})")
        self.check(bool(modal_root) and modal_root != "0" * 128,
                   "Converged token root is non-zero (token ledger is real consensus state)")
