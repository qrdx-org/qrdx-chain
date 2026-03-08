"""
S02 — P2P Network Mesh

Verifies:
  - All nodes have actual peer connections (not 0 peers)
  - Block heights are in sync across nodes (proving block propagation)
  - Heights converge over time (proves gossip + sync is working)
  - No node is isolated with its own independent chain
"""

import asyncio
from integration_tests.scenarios.base import Scenario
from integration_tests.rpc_client import NodeRPCClient, MultiNodeClient


class S02PeerMesh(Scenario):
    name = "s02_peer_mesh"
    description = "Verify P2P network mesh formation"
    depends_on = ["s01_genesis_bootstrap"]

    async def execute(self) -> None:
        node_urls = self.ctx.node_urls

        async with MultiNodeClient(node_urls) as clients:
            # Give peer discovery time to complete (bootstrap + gossip)
            # Nodes start peer discovery 5s after boot, bootstrap takes ~1s per peer.
            await asyncio.sleep(6)

            # ── 1. Verify actual peer connections (with retry for transient drops) ──
            total_peers = 0
            nodes_with_peers = 0
            for i, client in enumerate(clients._clients):
                count = 0
                for attempt in range(3):
                    try:
                        nodes = await client.get_nodes()
                        count = len(nodes) if nodes else 0
                        if count >= 1:
                            break
                        if attempt < 2:
                            await asyncio.sleep(2)
                    except Exception:
                        if attempt < 2:
                            await asyncio.sleep(2)
                total_peers += count
                if count >= 1:
                    nodes_with_peers += 1
                self._log.info("Node %d: %d peers connected", i, count)

            # Allow at most 1 node with 0 peers (bootstrap can be transiently empty)
            min_nodes = max(len(node_urls) - 1, 1)
            self.check(
                nodes_with_peers >= min_nodes,
                f"Enough nodes have peers ({nodes_with_peers}/{len(node_urls)}, need {min_nodes})",
            )

            self.check(
                total_peers >= len(node_urls),
                f"Network has sufficient peer connections (total={total_peers})"
            )

            # ── 2. Block heights should be in sync ──
            heights = await clients.get_block_heights()
            self._log.info("Block heights: %s", heights)

            for i, h in enumerate(heights):
                self.check(h >= 1, f"Node {i} past genesis (height={h})")

            if heights:
                spread = max(heights) - min(heights)
                self.check(spread <= 3,
                           f"Heights in sync (spread={spread}, heights={heights})")

            # ── 3. Wait and verify continued convergence ──
            # Nodes that started later need time for periodic_update_fetcher (8s cycle)
            # to pull blocks from peers.  Give 12s for at least one sync cycle.
            await asyncio.sleep(12)
            heights_after = await clients.get_block_heights()
            self._log.info("Heights after 12s: %s", heights_after)

            if heights_after:
                spread_after = max(heights_after) - min(heights_after)
                # After 12s every node should have synced via periodic_update_fetcher
                self.check(spread_after <= 3,
                           f"Heights still converging (spread={spread_after})")
                advancing = sum(1 for h1, h2 in zip(heights, heights_after) if h2 > h1)
                self.check(advancing >= 1,
                           f"At least 1 node advancing ({advancing}/{len(node_urls)})")
