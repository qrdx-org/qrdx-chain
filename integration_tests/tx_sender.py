"""
Transaction Sender — Build and broadcast real UTXO transactions.

Uses the actual QRDX transaction classes:
  - TransactionInput  (qrdx.transactions.transaction_input)
  - TransactionOutput (qrdx.transactions.transaction_output)
  - Transaction       (qrdx.transactions.transaction)

Signing uses fastecdsa P256 (classical wallets) — the same curve
as the node's Transaction.sign() method.

Workflow:
  1. Query node for spendable UTXOs via /get_address_info
  2. Build TransactionInput/Output objects
  3. Serialize to hex via Transaction.hex()
  4. Sign with wallet private key via Transaction.sign()
  5. Submit via /submit_tx  (no signed-request auth needed)
  6. Optionally wait for confirmation

No stubs — every transaction is a real, verifiable QRDX transaction.
"""

import asyncio
import json
import logging
import time
from decimal import Decimal
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from qrdx.constants import SMALLEST, ENDIAN, CURVE
from qrdx.transactions.transaction_input import TransactionInput
from qrdx.transactions.transaction_output import TransactionOutput
from qrdx.transactions.transaction import Transaction
from integration_tests.rpc_client import NodeRPCClient

logger = logging.getLogger(__name__)


class UTXO:
    """Unspent transaction output descriptor."""
    __slots__ = ("tx_hash", "index", "amount")

    def __init__(self, tx_hash: str, index: int, amount: Decimal):
        self.tx_hash = tx_hash
        self.index = index
        self.amount = amount

    def __repr__(self):
        return f"UTXO({self.tx_hash[:16]}..., idx={self.index}, amt={self.amount})"


class TransactionSender:
    """
    Builds and sends real QRDX transactions.

    Usage:
        sender = TransactionSender(node_url="http://127.0.0.1:3007")
        async with sender:
            tx_hash = await sender.send(
                from_address="DKxyz...",
                to_address="DLabc...",
                amount=Decimal("10.5"),
                private_key=12345678...,  # int (fastecdsa P256 key)
            )
    """

    def __init__(self, node_url: str):
        self.node_url = node_url
        self._client: Optional[NodeRPCClient] = None

    async def __aenter__(self):
        self._client = NodeRPCClient(self.node_url)
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc):
        if self._client:
            await self._client.__aexit__(*exc)
            self._client = None

    # ─────────── UTXO Management ───────────

    async def get_utxos(self, address: str) -> List[UTXO]:
        """Fetch spendable UTXOs for an address from the node."""
        result = await self._client._get("/get_address_info", params={"address": address})
        if not result or not result.get("ok"):
            return []

        raw_outputs = result.get("result", {}).get("spendable_outputs", [])
        utxos = []
        for out in raw_outputs:
            utxos.append(UTXO(
                tx_hash=out["tx_hash"],
                index=out["index"],
                amount=Decimal(out["amount"]),
            ))
        return utxos

    async def get_balance(self, address: str) -> Decimal:
        """Get confirmed balance for an address."""
        utxos = await self.get_utxos(address)
        return sum(u.amount for u in utxos)

    def select_utxos(
        self,
        utxos: List[UTXO],
        target: Decimal,
        fee: Decimal = Decimal("0.001"),
    ) -> Tuple[List[UTXO], Decimal]:
        """
        Greedy UTXO selection: largest first until target+fee is met.

        Returns (selected_utxos, change_amount).
        Raises ValueError if insufficient funds.
        """
        total_needed = target + fee
        # Sort by amount descending for fewer inputs
        sorted_utxos = sorted(utxos, key=lambda u: u.amount, reverse=True)

        selected = []
        accumulated = Decimal("0")
        for utxo in sorted_utxos:
            selected.append(utxo)
            accumulated += utxo.amount
            if accumulated >= total_needed:
                break

        if accumulated < total_needed:
            raise ValueError(
                f"Insufficient funds: have {accumulated}, need {total_needed} "
                f"(amount={target} + fee={fee})"
            )

        change = accumulated - total_needed
        return selected, change

    # ─────────── Transaction Building ───────────

    def build_transaction(
        self,
        utxos: List[UTXO],
        to_address: str,
        amount: Decimal,
        change_address: str,
        change_amount: Decimal,
        message: bytes = None,
    ) -> Transaction:
        """
        Build a real Transaction object from UTXOs.

        Creates TransactionInput objects from UTXOs and TransactionOutput
        objects for the recipient (and change if any).
        """
        # Build inputs
        inputs = []
        for utxo in utxos:
            tx_input = TransactionInput(
                input_tx_hash=utxo.tx_hash,
                index=utxo.index,
                amount=utxo.amount,
            )
            inputs.append(tx_input)

        # Build outputs
        outputs = [TransactionOutput(to_address, amount)]
        if change_amount > 0:
            outputs.append(TransactionOutput(change_address, change_amount))

        tx = Transaction(inputs, outputs, message=message)
        return tx

    def sign_transaction(self, tx: Transaction, private_key: int) -> Transaction:
        """
        Sign a transaction with a P256 private key (int).
        Uses the real Transaction.sign() method (fastecdsa ECDSA).
        """
        tx.sign(private_keys=[private_key])
        return tx

    # ─────────── Send Flow ───────────

    async def send(
        self,
        from_address: str,
        to_address: str,
        amount: Decimal,
        private_key: int,
        fee: Decimal = Decimal("0.001"),
        message: bytes = None,
        wait_confirm: bool = False,
        confirm_timeout: float = 30.0,
    ) -> Optional[str]:
        """
        Full send flow: fetch UTXOs → select → build → sign → broadcast.

        Args:
            from_address: Sender's address string (base58 compressed)
            to_address:   Recipient's address string
            amount:       Amount to send in QRDX
            private_key:  Sender's P256 private key (int)
            fee:          Transaction fee in QRDX
            message:      Optional transaction message
            wait_confirm: Whether to wait for block confirmation
            confirm_timeout: Max time to wait for confirmation

        Returns:
            Transaction hash if submitted, None on failure.
        """
        logger.info("Building tx: %s → %s, amount=%s QRDX", from_address[:20], to_address[:20], amount)

        # Step 1: Get UTXOs
        utxos = await self.get_utxos(from_address)
        if not utxos:
            logger.error("No UTXOs for %s", from_address)
            return None

        logger.debug("  Found %d UTXOs, total=%s", len(utxos), sum(u.amount for u in utxos))

        # Step 2: Select UTXOs
        try:
            selected, change = self.select_utxos(utxos, amount, fee)
        except ValueError as e:
            logger.error("  UTXO selection failed: %s", e)
            return None

        logger.debug("  Selected %d UTXOs, change=%s", len(selected), change)

        # Step 3: Build transaction
        tx = self.build_transaction(
            utxos=selected,
            to_address=to_address,
            amount=amount,
            change_address=from_address,
            change_amount=change,
            message=message,
        )

        # Step 4: Sign
        self.sign_transaction(tx, private_key)
        tx_hex = tx.hex()
        tx_hash = tx.hash()

        logger.info("  TX hash: %s, hex_len=%d", tx_hash, len(tx_hex))

        # Step 5: Submit via /submit_tx
        result = await self._client._post("/submit_tx", data={"tx_hex": tx_hex})
        if not result or not result.get("ok"):
            error = result.get("error", "unknown") if result else "no response"
            logger.error("  Submit failed: %s", error)
            return None

        logger.info("  ✓ TX submitted: %s", tx_hash)

        # Step 6: Optionally wait for confirmation
        if wait_confirm:
            confirmed = await self._client.wait_tx_confirmed(tx_hash, timeout=confirm_timeout)
            if confirmed:
                logger.info("  ✓ TX confirmed: %s", tx_hash)
            else:
                logger.warning("  ⚠ TX not confirmed within %ss: %s", confirm_timeout, tx_hash)

        return tx_hash

    async def send_batch(
        self,
        from_address: str,
        private_key: int,
        recipients: List[Tuple[str, Decimal]],
        fee: Decimal = Decimal("0.001"),
        delay: float = 0.5,
    ) -> List[Optional[str]]:
        """
        Send multiple transactions sequentially.

        Args:
            recipients: List of (to_address, amount) tuples.
            delay: Seconds between transactions (avoid mempool flooding).
        """
        results = []
        for to_addr, amount in recipients:
            tx_hash = await self.send(
                from_address=from_address,
                to_address=to_addr,
                amount=amount,
                private_key=private_key,
                fee=fee,
            )
            results.append(tx_hash)
            if delay > 0:
                await asyncio.sleep(delay)
        return results


class MultiSenderCoordinator:
    """
    Coordinates transaction sending across multiple wallets and nodes.

    Useful for stress testing and multi-party scenarios.
    """

    def __init__(self, node_urls: List[str]):
        self.node_urls = node_urls
        self._senders: List[TransactionSender] = []

    async def __aenter__(self):
        for url in self.node_urls:
            sender = TransactionSender(url)
            await sender.__aenter__()
            self._senders.append(sender)
        return self

    async def __aexit__(self, *exc):
        for sender in self._senders:
            await sender.__aexit__(*exc)
        self._senders.clear()

    def _pick_sender(self, index: int = 0) -> TransactionSender:
        """Pick a sender (round-robin or explicit index)."""
        return self._senders[index % len(self._senders)]

    async def spray_transactions(
        self,
        wallets: List[Dict],
        amount_each: Decimal,
        target_address: str,
        delay: float = 0.2,
    ) -> List[Optional[str]]:
        """
        Send transactions from multiple wallets to a single target.
        Distributes across nodes round-robin.
        """
        results = []
        for i, wallet in enumerate(wallets):
            sender = self._pick_sender(i)
            result = await sender.send(
                from_address=wallet["address"],
                to_address=target_address,
                amount=amount_each,
                private_key=wallet["private_key_int"],
            )
            results.append(result)
            if delay > 0:
                await asyncio.sleep(delay)
        return results

    async def chain_transfers(
        self,
        wallets: List[Dict],
        amount: Decimal,
    ) -> List[Optional[str]]:
        """
        Chain transfers: wallet[0]→wallet[1]→wallet[2]→...→wallet[0].
        Tests UTXO propagation through the network.
        """
        hashes = []
        sender = self._pick_sender(0)
        for i in range(len(wallets)):
            src = wallets[i]
            dst = wallets[(i + 1) % len(wallets)]
            tx_hash = await sender.send(
                from_address=src["address"],
                to_address=dst["address"],
                amount=amount,
                private_key=src["private_key_int"],
                wait_confirm=True,
                confirm_timeout=20.0,
            )
            hashes.append(tx_hash)
        return hashes
