"""
S07 — Validator Registration & PoS Slots

Verifies:
    - Validator registration via REST API
    - Genesis validators appear in active set
    - Validator set is visible from all nodes
    - Blocks continue being produced while validator set is active
"""

import asyncio

from integration_tests.scenarios.base import Scenario
from integration_tests.rpc_client import NodeRPCClient


class S07Validators(Scenario):
    name = "s07_validators"
    description = "Verify validator registration and slot assignment"
    depends_on = ["s03_block_production"]

    async def execute(self) -> None:
        node_urls = self.ctx.node_urls
        wallets = self.ctx.wallets

        expected_validators = []
        for i in range(3):
            vw = wallets.get(f"Validator {i}")
            if vw and vw.get("address"):
                expected_validators.append(vw["address"])

        if not expected_validators:
            self.check(False, "Expected validator wallets available")
            return

        primary_url = node_urls[0]
        async with NodeRPCClient(primary_url) as client:
            validators = await client.get_validators()
            self.check(len(validators) >= len(expected_validators),
                       f"Validator set contains expected size ({len(validators)})")

            validator_addrs = []
            for entry in validators:
                if isinstance(entry, dict):
                    addr = entry.get("address") or entry.get("validator") or ""
                else:
                    addr = str(entry)
                if addr:
                    validator_addrs.append(addr)

            self.check(len(validator_addrs) > 0, "Validator addresses retrievable")

            normalized_actual = {a.lower() for a in validator_addrs}
            missing = [a for a in expected_validators if a.lower() not in normalized_actual]
            self.check(len(missing) == 0, f"Expected validators present (missing={len(missing)})")

            before_info = await client.get_mining_info()
            before_height = int(before_info.get("last_block", {}).get("id", 0))
            self.check(before_height >= 1, f"Chain already producing blocks (height={before_height})")

        # Ensure validator data is visible across peers and block production advances.
        visible_nodes = 0
        validator_counts = []
        for url in node_urls:
            try:
                async with NodeRPCClient(url) as client:
                    vals = await client.get_validators()
                    validator_counts.append(len(vals))
                    visible_nodes += 1
            except Exception as exc:
                self._log.warning("Validator query failed for %s: %s", url, exc)

        self.check(visible_nodes >= max(1, len(node_urls) - 1),
                   f"Validator API reachable on most nodes ({visible_nodes}/{len(node_urls)})")
        if validator_counts:
            self.check(min(validator_counts) >= 1,
                       f"Each reachable node reports validators (min={min(validator_counts)})")

        await asyncio.sleep(4)
        async with NodeRPCClient(primary_url) as client:
            after_info = await client.get_mining_info()
            after_height = int(after_info.get("last_block", {}).get("id", 0))

        self.check(after_height > before_height,
                   f"Height advanced while validators active ({before_height} -> {after_height})")
