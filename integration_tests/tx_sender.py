"""
Transaction Sender — Build and broadcast Ethereum-style transactions.

Uses the eth_sendRawTransaction JSON-RPC endpoint on the QRDX node.
Signing uses eth-account (secp256k1) — the native key system for
traditional QRDX wallets (0x addresses).

Workflow:
  1. Query nonce via eth_getTransactionCount
  2. Build an EIP-155 transaction dict
  3. Sign with eth-account (secp256k1 private key)
  4. Submit RLP-encoded raw tx via POST /rpc → eth_sendRawTransaction
  5. Optionally wait for receipt via eth_getTransactionReceipt

No stubs — every transaction is a real, verifiable QRDX/ETH transaction.
"""

import asyncio
import logging
import time
from decimal import Decimal
from typing import Dict, List, Optional, Tuple

from integration_tests.rpc_client import NodeRPCClient

logger = logging.getLogger(__name__)

# 1 QRDX = 10^6 micro-QRDX in native layer, but 10^18 wei in ETH compat.
# The eth_getBalance converts micro-QRDX → wei via ×10^12.
WEI_PER_QRDX = 10 ** 18
MICRO_QRDX_PER_QRDX = 10 ** 6
WEI_PER_MICRO = 10 ** 12  # conversion factor used by eth module

# Default gas settings (simple value transfer)
DEFAULT_GAS = 21000
DEFAULT_GAS_PRICE = 1_000_000_000  # 1 gwei


class TransactionSender:
    """
    Builds and sends real QRDX transactions via the Ethereum JSON-RPC.

    Usage:
        sender = TransactionSender(node_url="http://127.0.0.1:3007")
        async with sender:
            tx_hash = await sender.send(
                from_address="0x1234...",
                to_address="0xabcd...",
                amount=Decimal("10.5"),
                private_key_hex="aabbcc...",  # secp256k1 hex key
            )
    """

    def __init__(self, node_url: str, chain_id: int = 9999):
        self.node_url = node_url
        self.chain_id = chain_id
        self._client: Optional[NodeRPCClient] = None

    async def __aenter__(self):
        self._client = NodeRPCClient(self.node_url)
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc):
        if self._client:
            await self._client.__aexit__(*exc)
            self._client = None

    # ─────────── Balance Queries ───────────

    async def get_balance(self, address: str) -> Decimal:
        """Get balance in QRDX (converted from wei)."""
        wei = await self._client.eth_get_balance(address)
        return Decimal(wei) / Decimal(WEI_PER_QRDX)

    async def get_balance_wei(self, address: str) -> int:
        """Get balance in wei."""
        return await self._client.eth_get_balance(address)

    async def get_nonce(self, address: str) -> int:
        """Get next nonce for address."""
        return await self._client.eth_get_transaction_count(address)

    # ─────────── Transaction Building & Sending ───────────

    async def send(
        self,
        from_address: str,
        to_address: str,
        amount: Decimal,
        private_key_hex: str,
        gas: int = DEFAULT_GAS,
        gas_price: int = DEFAULT_GAS_PRICE,
        data: bytes = b"",
        wait_confirm: bool = False,
        confirm_timeout: float = 30.0,
    ) -> Optional[str]:
        """
        Full send flow: get nonce → build tx → sign → broadcast.

        Args:
            from_address:    Sender's 0x address
            to_address:      Recipient's 0x address
            amount:          Amount to send in QRDX
            private_key_hex: Sender's secp256k1 private key (hex, no 0x prefix)
            gas:             Gas limit
            gas_price:       Gas price in wei
            data:            Optional calldata
            wait_confirm:    Whether to wait for receipt
            confirm_timeout: Max seconds to wait

        Returns:
            Transaction hash if submitted, None on failure.
        """
        from eth_account import Account

        logger.info(
            "Building ETH tx: %s → %s, amount=%s QRDX",
            from_address[:16], to_address[:16], amount,
        )

        # Ensure private key has 0x prefix for eth-account
        if not private_key_hex.startswith("0x"):
            private_key_hex = "0x" + private_key_hex

        try:
            # Step 1: Get nonce
            nonce = await self.get_nonce(from_address)
            logger.debug("  Nonce: %d", nonce)

            # Step 2: Convert QRDX to wei
            value_wei = int(amount * WEI_PER_QRDX)

            # Step 3: Build transaction dict
            tx = {
                "nonce": nonce,
                "gasPrice": gas_price,
                "gas": gas,
                "to": to_address,
                "value": value_wei,
                "data": data,
                "chainId": self.chain_id,
            }

            # Step 4: Sign
            signed = Account.sign_transaction(tx, private_key_hex)
            raw_hex = "0x" + signed.raw_transaction.hex()
            tx_hash = "0x" + signed.hash.hex()

            logger.info("  TX hash: %s, raw_len=%d", tx_hash, len(raw_hex))

            # Step 5: Submit via JSON-RPC eth_sendRawTransaction
            result = await self._client.eth_send_raw_transaction(raw_hex)
            if result is None:
                logger.error("  Submit failed: no result from eth_sendRawTransaction")
                return None

            logger.info("  ✓ TX submitted: %s", tx_hash)

            # Step 6: Optionally wait for receipt
            if wait_confirm:
                confirmed = await self.wait_for_receipt(tx_hash, timeout=confirm_timeout)
                if confirmed:
                    logger.info("  ✓ TX receipt received: %s", tx_hash)
                else:
                    logger.warning(
                        "  ⚠ TX receipt not available within %ss: %s",
                        confirm_timeout, tx_hash,
                    )

            return tx_hash

        except Exception as e:
            logger.error("  TX failed: %s", e, exc_info=True)
            return None

    async def wait_for_receipt(self, tx_hash: str, timeout: float = 30.0) -> bool:
        """Wait for transaction receipt to be available."""
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            try:
                receipt = await self._client.eth_get_transaction_receipt(tx_hash)
                if receipt is not None:
                    return True
            except Exception:
                pass
            await asyncio.sleep(1.0)
        return False

    async def send_batch(
        self,
        from_address: str,
        private_key_hex: str,
        recipients: List[Tuple[str, Decimal]],
        delay: float = 0.5,
    ) -> List[Optional[str]]:
        """
        Send multiple transactions sequentially.

        Args:
            recipients: List of (to_address, amount_qrdx) tuples.
            delay: Seconds between transactions.
        """
        results = []
        for to_addr, amount in recipients:
            tx_hash = await self.send(
                from_address=from_address,
                to_address=to_addr,
                amount=amount,
                private_key_hex=private_key_hex,
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

    def __init__(self, node_urls: List[str], chain_id: int = 9999):
        self.node_urls = node_urls
        self.chain_id = chain_id
        self._senders: List[TransactionSender] = []

    async def __aenter__(self):
        for url in self.node_urls:
            sender = TransactionSender(url, chain_id=self.chain_id)
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
                private_key_hex=wallet["private_key"],
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
        Tests transaction propagation through the network.
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
                private_key_hex=src["private_key"],
                wait_confirm=True,
                confirm_timeout=20.0,
            )
            hashes.append(tx_hash)
        return hashes
