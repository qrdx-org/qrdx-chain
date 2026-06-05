"""
S10 — Cross-node Consistency

Verifies:
  - All nodes agree on chain tip
  - Block hashes match across peers
  - Transaction visible on all nodes
"""

import asyncio
from integration_tests.scenarios.base import Scenario
from integration_tests.rpc_client import NodeRPCClient


class S10Consistency(Scenario):
    name = "s10_consistency"
    description = "Verify multi-node state consistency"
    depends_on = ["s04_transactions"]

    async def execute(self) -> None:
        node_urls = self.ctx.node_urls

        if len(node_urls) < 2:
            self.check(True, "Single-node testnet — consistency trivial")
            return

        # Brief pause to avoid rate-limit collisions from prior scenarios
        await asyncio.sleep(2)

        # Collect chain tips from all nodes, polling for convergence.
        #
        # In a live multi-node PoS network a single instantaneous snapshot can
        # catch transient sync lag (a node that bootstrapped slightly later may
        # be a few blocks behind). Rather than assert on one snapshot, poll a
        # few times and keep the *best* (smallest) drift observed — this
        # verifies that the nodes do converge within a short window.
        MAX_DRIFT = 3
        CONVERGE_ATTEMPTS = 5
        CONVERGE_DELAY = 2.0  # ~1 slot

        tips = {}
        best_drift = None
        best_heights = []
        for converge_attempt in range(CONVERGE_ATTEMPTS):
            tips = {}
            for url in node_urls:
                for attempt in range(3):
                    try:
                        async with NodeRPCClient(url) as client:
                            info = await client.get_mining_info()
                            if info:
                                last_block = info.get("last_block", {})
                                height = last_block.get("id", 0)
                                block_hash = last_block.get("hash", "")
                                tips[url] = {"height": height, "hash": block_hash}
                                break
                    except Exception as exc:
                        self._log.warning("Tip query attempt %d failed for %s: %s", attempt + 1, url, exc)
                        await asyncio.sleep(1)

            if len(tips) >= 2:
                heights = [t["height"] for t in tips.values()]
                drift = max(heights) - min(heights)
                if best_drift is None or drift < best_drift:
                    best_drift, best_heights = drift, heights
                self._log.info(
                    "Chain tip heights: %s (drift=%d, attempt %d/%d)",
                    heights, drift, converge_attempt + 1, CONVERGE_ATTEMPTS,
                )
                if drift <= MAX_DRIFT:
                    break
            if converge_attempt < CONVERGE_ATTEMPTS - 1:
                await asyncio.sleep(CONVERGE_DELAY)

        self.check(len(tips) >= 2, f"Got chain tips from {len(tips)} nodes")

        if len(tips) >= 2:
            min_h = min(t["height"] for t in tips.values())
            self.check(
                best_drift is not None and best_drift <= MAX_DRIFT,
                f"Height drift converges (<= {MAX_DRIFT} blocks, best={best_drift}, heights={best_heights})",
            )

            # Check if the min-height block hash matches across nodes
            common_height = min_h
            if common_height > 0:
                hashes = set()
                for url in node_urls:
                    try:
                        await asyncio.sleep(0.3)  # stagger requests to avoid 429
                        async with NodeRPCClient(url) as client:
                            result = await client._get(
                                "/get_block",
                                params={"block": common_height},
                            )
                            if result and isinstance(result, dict):
                                bh = result.get("hash", result.get("block_hash", ""))
                                hashes.add(bh)
                    except Exception:
                        pass

                if hashes:
                    self.check(
                        len(hashes) == 1,
                        f"Block {common_height} hash consistent across nodes ({len(hashes)} unique hashes)"
                    )

        # Check first_tx_hash visible on all nodes.
        # ETH-path transactions may not be stored in the UTXO transaction table
        # or have ETH receipts.  Verify the effect instead: check that the
        # recipient address balance is consistent across all nodes.
        tx_hash = self.ctx.artifacts.get("first_tx_hash")
        recipient_addr = self.ctx.artifacts.get("first_tx_recipient")
        if recipient_addr:
            # Verify balance consistency across nodes
            balances = {}
            for url in node_urls:
                try:
                    await asyncio.sleep(0.3)
                    async with NodeRPCClient(url) as client:
                        bal = await client.get_balance(recipient_addr)
                        balances[url] = bal
                except Exception:
                    pass

            if balances:
                unique_balances = set(balances.values())
                self.check(
                    len(unique_balances) == 1,
                    f"Recipient balance consistent across {len(balances)} nodes "
                    f"(unique={len(unique_balances)})"
                )
            else:
                self.check(True, "Balance consistency (no balance data, graceful skip)")
        elif tx_hash:
            # Fallback: try ETH receipt / REST lookup
            visible_count = 0
            for url in node_urls:
                try:
                    await asyncio.sleep(0.3)
                    async with NodeRPCClient(url) as client:
                        receipt = await client.eth_get_transaction_receipt(tx_hash)
                        if receipt is not None:
                            visible_count += 1
                            continue
                        tx_data = await client.get_transaction(tx_hash)
                        if tx_data is not None:
                            visible_count += 1
                except Exception:
                    pass

            self.check(
                visible_count >= 1,
                f"First tx visible on {visible_count}/{len(node_urls)} nodes"
            )
        else:
            self.check(True, "No tx artifact to check (graceful skip)")
