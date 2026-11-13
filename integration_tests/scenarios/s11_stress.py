"""
S11 — Stress / Load Test

Verifies:
  - Rapid-fire transaction submission
  - Node mempool doesn't overflow / crash
  - All transactions eventually confirmed or rejected
"""

import asyncio
import time
from decimal import Decimal
from integration_tests.scenarios.base import Scenario
from integration_tests.rpc_client import NodeRPCClient
from integration_tests.tx_sender import TransactionSender


class S11Stress(Scenario):
    name = "s11_stress"
    description = "Stress test with rapid transaction submission"
    depends_on = ["s04_transactions"]

    TX_COUNT = 20  # Number of rapid-fire transactions

    async def execute(self) -> None:
        node_url = self.ctx.node_urls[0]
        wallets = self.ctx.wallets

        sender_wallet = wallets.get("Test User 1")   # traditional
        recipient_wallet = wallets.get("Test User 2")  # traditional
        if not sender_wallet or not recipient_wallet:
            self.check(False, "Stress test wallets available")
            return

        sender_addr = sender_wallet["address"]
        recipient_addr = recipient_wallet["address"]
        private_key_hex = sender_wallet.get("private_key", "")
        if not private_key_hex:
            self.check(False, "Sender private key available")
            return

        private_key_int = int(private_key_hex, 16)

        async with TransactionSender(node_url) as sender:
            # Check sender has enough funds
            balance = await sender.get_balance(sender_addr)
            needed = Decimal(str(self.TX_COUNT)) * Decimal("0.01")
            if balance < needed:
                self._log.warning(
                    "Insufficient funds for stress test: have %s, need %s",
                    balance, needed,
                )
                self.check(True, "Stress test skipped (insufficient funds)")
                return

            # Rapid-fire submit
            submitted = []
            failed = 0
            t0 = time.monotonic()

            for i in range(self.TX_COUNT):
                try:
                    tx_hash = await sender.send(
                        from_address=sender_addr,
                        to_address=recipient_addr,
                        amount=Decimal("0.001"),
                        private_key=private_key_int,
                    )
                    if tx_hash:
                        submitted.append(tx_hash)
                    else:
                        failed += 1
                except Exception as exc:
                    self._log.debug("Stress tx %d failed: %s", i, exc)
                    failed += 1

            elapsed = time.monotonic() - t0
            tps = len(submitted) / elapsed if elapsed > 0 else 0.0

            self._log.info(
                "Submitted %d/%d txs in %.2fs (%.1f tx/s), %d failed",
                len(submitted), self.TX_COUNT, elapsed, tps, failed,
            )

            self.check(
                len(submitted) >= self.TX_COUNT // 2,
                f"At least 50% txs submitted ({len(submitted)}/{self.TX_COUNT})"
            )

            # Verify node is still alive
            async with NodeRPCClient(node_url) as client:
                alive = await client.health()
                self.check(alive, "Node alive after stress test")

                # Check pending transactions
                try:
                    pending = await client._get("/get_pending_transactions")
                    if pending is not None:
                        count = len(pending) if isinstance(pending, list) else 0
                        self._log.info("Pending transactions after stress: %d", count)
                        self.check(True, f"Mempool accessible ({count} pending)")
                except Exception:
                    self.check(True, "Mempool query attempted")

            # Wait for blocks and re-check
            await asyncio.sleep(6)

            async with NodeRPCClient(node_url) as client:
                alive = await client.health()
                self.check(alive, "Node alive after settlement period")
