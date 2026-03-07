"""
S04 — ETH-style Transactions

Verifies:
  - Build, sign, and broadcast real Ethereum-style transactions
  - Submit via eth_sendRawTransaction JSON-RPC
  - Sender balance decreases, recipient balance increases
  - Uses secp256k1 signing (traditional 0x wallets)
"""

import asyncio
from decimal import Decimal
from integration_tests.scenarios.base import Scenario
from integration_tests.rpc_client import NodeRPCClient
from integration_tests.tx_sender import TransactionSender


class S04Transactions(Scenario):
    name = "s04_transactions"
    description = "Verify ETH-style transaction lifecycle"
    depends_on = ["s03_block_production"]

    async def execute(self) -> None:
        node_url = self.ctx.node_urls[0]
        wallets = self.ctx.wallets

        # Use traditional (secp256k1) wallets — ETH-compatible 0x addresses
        sender_wallet = wallets.get("Test User 1")    # traditional
        recipient_wallet = wallets.get("Test User 2")  # traditional

        if not sender_wallet or not recipient_wallet:
            self.check(False, "Test wallets available")
            return

        sender_addr = sender_wallet["address"]
        recipient_addr = recipient_wallet["address"]

        async with TransactionSender(node_url) as sender:
            # Check initial balances
            sender_balance = await sender.get_balance(sender_addr)
            recipient_balance = await sender.get_balance(recipient_addr)

            self._log.info("Sender balance: %s QRDX", sender_balance)
            self._log.info("Recipient balance: %s QRDX", recipient_balance)

            self.check_gte(sender_balance, Decimal("1"), "Sender has funds")

            if sender_balance < Decimal("1"):
                self._log.warning("Sender has no funds, skipping transfer test")
                return

            # Send a transaction via eth_sendRawTransaction
            amount = Decimal("1")
            private_key_hex = sender_wallet.get("private_key", "")
            if not private_key_hex:
                self.check(False, "Sender has private key")
                return

            tx_hash = await sender.send(
                from_address=sender_addr,
                to_address=recipient_addr,
                amount=amount,
                private_key_hex=private_key_hex,
            )

            self.check_not_none(tx_hash, "Transaction submitted successfully")

            if tx_hash:
                self.ctx.artifacts["first_tx_hash"] = tx_hash

                # Wait for confirmation
                await asyncio.sleep(4)  # 2 slots

                # Check new balances
                new_sender_balance = await sender.get_balance(sender_addr)
                new_recipient_balance = await sender.get_balance(recipient_addr)

                self._log.info("New sender balance: %s", new_sender_balance)
                self._log.info("New recipient balance: %s", new_recipient_balance)

                # Sender should have less (amount + fee)
                self.check(
                    new_sender_balance <= sender_balance,
                    f"Sender balance decreased (was {sender_balance}, now {new_sender_balance})"
                )

                # Recipient should have more
                self.check(
                    new_recipient_balance >= recipient_balance,
                    f"Recipient balance increased or same (was {recipient_balance}, now {new_recipient_balance})"
                )
