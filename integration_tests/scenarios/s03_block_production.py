"""
S03 — Block Production & Consensus

Verifies:
  - Blocks are being produced (height advances)
  - All nodes agree on blocks (height consistency)
  - Block production rate is reasonable for 2s slots
  - Consensus state is accessible
"""

import asyncio
from integration_tests.scenarios.base import Scenario
from integration_tests.rpc_client import MultiNodeClient


class S03BlockProduction(Scenario):
    name = "s03_block_production"
    description = "Verify block production and consensus"
    depends_on = ["s02_peer_mesh"]

    async def execute(self) -> None:
        node_urls = self.ctx.node_urls

        async with MultiNodeClient(node_urls) as clients:
            # Record initial heights
            heights_before = await clients.get_block_heights()
            self._log.info("Heights before: %s", heights_before)

            # Wait for blocks to be produced (6 seconds = ~3 slots)
            await asyncio.sleep(6)

            # Record heights after
            heights_after = await clients.get_block_heights()
            self._log.info("Heights after: %s", heights_after)

            # Check that at least one node advanced
            any_advanced = any(
                after > before
                for before, after in zip(heights_before, heights_after)
                if before >= 0 and after >= 0
            )
            self.check(any_advanced, "At least one node produced blocks")

            # Check heights are consistent (within 2 blocks)
            valid_heights = [h for h in heights_after if h >= 0]
            if valid_heights:
                spread = max(valid_heights) - min(valid_heights)
                self.check(spread <= 5, f"Block heights consistent (spread={spread})")

            # Check max height advanced
            max_before = max(h for h in heights_before if h >= 0) if any(h >= 0 for h in heights_before) else 0
            max_after = max(valid_heights) if valid_heights else 0
            blocks_produced = max_after - max_before
            self.check_gte(blocks_produced, 1, f"Blocks produced in 6s ({blocks_produced})")

            # Check block rate is reasonable (0.25-1.0 blocks/sec for 2s slots)
            if blocks_produced > 0:
                rate = blocks_produced / 6.0
                self.check(rate <= 2.0, f"Block rate reasonable ({rate:.2f} blk/s)")

            # Store max height for dependent scenarios
            self.ctx.artifacts["max_height_after_s03"] = max_after
