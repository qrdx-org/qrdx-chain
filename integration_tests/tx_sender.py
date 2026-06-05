"""
Transaction Sender — Build and broadcast ETH-style account-model transactions.

QRDX uses a **dual address system** (see qrdx/crypto/address.py):
  - Traditional (secp256k1): ``0x...`` EIP-55 addresses, signed with ECDSA
  - Post-Quantum (Dilithium): ``0xPQ...`` addresses

Native value transfers between ``0x`` accounts go through the canonical
**account / EVM path**: an EIP-155 signed transaction submitted via
``eth_sendRawTransaction``, recovered + executed by the EVM, and committed to
the ``account_state`` table (balances are tracked in wei, 1 QRDX = 10**18 wei).

The legacy Denaro **UTXO** model (``TransactionOutput`` + secp256k1 *curve
points* encoded in base58) is NOT used for ``0x``/``0xPQ`` transfers — a
``0x`` address is ``keccak256(pubkey)[-20:]`` (a hash), which can never be
reconstructed into a curve point, so that path is incompatible by design.

Workflow:
  1. Resolve nonce (``eth_getTransactionCount``, then tracked locally so
     rapid-fire sends from one account get sequential nonces)
  2. Resolve chain id (``eth_chainId``)
  3. Build a legacy/EIP-155 transaction dict and sign it with the wallet's
     secp256k1 key via ``eth_account``
  4. Submit the raw RLP bytes via ``eth_sendRawTransaction``
  5. Optionally wait for confirmation

No stubs — every transaction is a real, signed, verifiable QRDX transaction.
"""

import asyncio
import logging
from decimal import Decimal
from typing import Dict, List, Optional, Tuple

from eth_account import Account
from eth_utils import to_checksum_address

from integration_tests.rpc_client import NodeRPCClient

logger = logging.getLogger(__name__)

# Unit + gas constants (mirror qrdx/contracts/state_sync.py and eth RPC module)
WEI_PER_QRDX = 10 ** 18          # 1 QRDX = 10^18 wei (Ethereum standard)
DEFAULT_GAS = 21_000             # standard native-transfer gas
DEFAULT_GAS_PRICE_WEI = 10 ** 9  # 1 gwei (node reports 1 gwei min base fee)


def _private_key_to_bytes(private_key) -> bytes:
    """
    Accept a secp256k1 private key as int or hex string, return 32 bytes.

    The wallet roster stores keys as hex; scenarios pass ``int(hex, 16)``.
    """
    if isinstance(private_key, int):
        return private_key.to_bytes(32, "big")
    if isinstance(private_key, str):
        return bytes.fromhex(private_key[2:] if private_key.startswith("0x") else private_key)
    if isinstance(private_key, (bytes, bytearray)):
        return bytes(private_key)
    raise TypeError(f"Unsupported private key type: {type(private_key)}")


class TransactionSender:
    """
    Builds and sends real account-model QRDX transactions for ``0x`` wallets.

    Usage:
        async with TransactionSender("http://127.0.0.1:3007") as sender:
            tx_hash = await sender.send(
                from_address="0x...",
                to_address="0x...",
                amount=Decimal("1"),
                private_key=int(wallet["private_key"], 16),
            )
    """

    def __init__(self, node_url: str):
        self.node_url = node_url
        self._client: Optional[NodeRPCClient] = None
        # Locally tracked next-nonce per account (lowercased address → nonce).
        # Required so rapid-fire sends from one account don't all reuse the
        # same on-chain nonce before the prior txs are reflected.
        self._nonce: Dict[str, int] = {}
        self._chain_id: Optional[int] = None

    async def __aenter__(self):
        self._client = NodeRPCClient(self.node_url)
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc):
        if self._client:
            await self._client.__aexit__(*exc)
            self._client = None

    # ─────────── Balances (account model) ───────────

    async def get_balance(self, address: str) -> Decimal:
        """
        Confirmed balance in QRDX, read via ``eth_getBalance`` (the same
        account-model state that transfers mutate), converted from wei.
        """
        try:
            wei = await self._client.eth_get_balance(address)
            return Decimal(wei) / Decimal(WEI_PER_QRDX)
        except Exception as e:
            logger.debug("get_balance(%s) failed: %s", address, e)
            return Decimal("0")

    # ─────────── Nonce / chain id ───────────

    async def _resolve_chain_id(self) -> int:
        if self._chain_id is None:
            try:
                self._chain_id = await self._client.eth_chain_id()
            except Exception:
                self._chain_id = 0
        return self._chain_id

    async def _next_nonce(self, address: str) -> int:
        """
        Return the next nonce to use, tracked locally for rapid-fire sends.

        Seeds from ``eth_getTransactionCount`` the first time an address is
        seen, then increments locally on each successful submit.
        """
        key = address.lower()
        if key not in self._nonce:
            try:
                self._nonce[key] = await self._client.eth_get_transaction_count(address)
            except Exception:
                self._nonce[key] = 0
        return self._nonce[key]

    # ─────────── Send flow ───────────

    async def send(
        self,
        from_address: str,
        to_address: str,
        amount: Decimal,
        private_key,
        fee: Decimal = None,           # accepted for API compatibility (gas covers fees)
        message: bytes = None,         # accepted for API compatibility (unused on transfers)
        gas_price_wei: int = DEFAULT_GAS_PRICE_WEI,
        gas: int = DEFAULT_GAS,
        wait_confirm: bool = False,
        confirm_timeout: float = 30.0,
    ) -> Optional[str]:
        """
        Build, sign, and broadcast an ETH-style value transfer.

        Returns the transaction hash if accepted, or None on failure.
        """
        key_bytes = _private_key_to_bytes(private_key)
        acct = Account.from_key(key_bytes)

        # Use the address derived from the key for nonce/signing consistency.
        signer_addr = acct.address
        nonce = await self._next_nonce(signer_addr)
        chain_id = await self._resolve_chain_id()
        value_wei = int(Decimal(str(amount)) * WEI_PER_QRDX)

        logger.info(
            "Building tx: %s → %s, amount=%s QRDX (nonce=%d)",
            signer_addr[:20], to_address[:20], amount, nonce,
        )

        tx = {
            "nonce": nonce,
            "gasPrice": gas_price_wei,
            "gas": gas,
            "to": to_checksum_address(to_address),
            "value": value_wei,
            "data": b"",
            "chainId": chain_id,
        }

        try:
            signed = Account.sign_transaction(tx, key_bytes)
        except Exception as e:
            logger.error("  Signing failed: %s", e)
            return None

        raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
        raw_hex = "0x" + bytes(raw).hex()

        try:
            tx_hash = await self._client.eth_send_raw_transaction(raw_hex)
        except Exception as e:
            logger.error("  Submit failed (nonce=%d): %s", nonce, e)
            return None

        if not tx_hash:
            logger.error("  Submit returned empty hash (nonce=%d)", nonce)
            return None

        # Only consume the nonce locally once the node accepted the tx.
        self._nonce[signer_addr.lower()] = nonce + 1
        logger.info("  ✓ TX submitted: %s", tx_hash)

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
        private_key,
        recipients: List[Tuple[str, Decimal]],
        fee: Decimal = None,
        delay: float = 0.5,
    ) -> List[Optional[str]]:
        """Send multiple transfers sequentially (nonces auto-increment)."""
        results = []
        for to_addr, amount in recipients:
            tx_hash = await self.send(
                from_address=from_address,
                to_address=to_addr,
                amount=amount,
                private_key=private_key,
            )
            results.append(tx_hash)
            if delay > 0:
                await asyncio.sleep(delay)
        return results


def _wallet_key(wallet: Dict):
    """Extract a usable private key (int) from a wallet dict."""
    if "private_key_int" in wallet:
        return wallet["private_key_int"]
    return int(wallet["private_key"], 16)


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
        """Send transactions from multiple wallets to a single target."""
        results = []
        for i, wallet in enumerate(wallets):
            sender = self._pick_sender(i)
            result = await sender.send(
                from_address=wallet["address"],
                to_address=target_address,
                amount=amount_each,
                private_key=_wallet_key(wallet),
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
        """Chain transfers: wallet[0]→wallet[1]→...→wallet[0]."""
        hashes = []
        sender = self._pick_sender(0)
        for i in range(len(wallets)):
            src = wallets[i]
            dst = wallets[(i + 1) % len(wallets)]
            tx_hash = await sender.send(
                from_address=src["address"],
                to_address=dst["address"],
                amount=amount,
                private_key=_wallet_key(src),
                wait_confirm=True,
                confirm_timeout=20.0,
            )
            hashes.append(tx_hash)
        return hashes
