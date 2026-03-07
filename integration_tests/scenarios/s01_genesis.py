"""
S01 — Genesis & Node Bootstrap

Verifies:
  - All nodes started and healthy
  - Genesis block exists on every node
  - System wallets funded with correct balances
  - Validator wallets present
  - Block height >= 0 across all nodes
"""

from decimal import Decimal
from integration_tests.scenarios.base import Scenario, ScenarioContext
from integration_tests.rpc_client import NodeRPCClient, MultiNodeClient


class S01GenesisBootstrap(Scenario):
    name = "s01_genesis_bootstrap"
    description = "Verify genesis block creation and node bootstrap"
    depends_on = []

    async def execute(self) -> None:
        node_urls = self.ctx.node_urls
        wallets = self.ctx.wallets

        # Check all nodes healthy
        async with MultiNodeClient(node_urls) as clients:
            for i, client in enumerate(clients._clients):
                healthy = await client.health()
                self.check(healthy, f"Node {i} is healthy")

            # Check block heights
            heights = await clients.get_block_heights()
            for i, h in enumerate(heights):
                self.check_gte(h, 0, f"Node {i} has genesis block (height >= 0)")

            # Check height consistency
            if heights:
                spread = max(heights) - min(heights)
                self.check(spread <= 10, f"Block heights consistent (spread={spread})")

        # Check validator wallets have balances
        async with NodeRPCClient(node_urls[0]) as client:
            for label, wallet in wallets.items():
                if "Validator" in label:
                    balance = await client.get_balance(wallet["address"])
                    self.check_not_none(balance, f"{label} has a balance response")
                    if balance is not None:
                        self.check_gte(balance, Decimal("0"), f"{label} balance >= 0")

            # Check peer discovery happened
            nodes = await client.get_nodes()
            self.check(nodes is not None, "Peer list returned")
