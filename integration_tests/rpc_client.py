"""
Async RPC Client — Typed HTTP Client for QRDX Node API

Wraps httpx.AsyncClient with methods for every REST endpoint
used by the testnet scenarios. No stubs — every call hits a real node.

All HTTP calls include automatic retry with exponential backoff for
429 (rate limit) responses, so scenarios don't need individual rate-limit
handling.
"""

import httpx
import asyncio
import logging
from decimal import Decimal
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10.0
MAX_RETRIES = 4          # max retry attempts on 429
RETRY_BASE_DELAY = 1.0   # base delay in seconds (doubles each retry)


class NodeRPCClient:
    """
    Async client for a single QRDX node's REST API.

    All methods perform real HTTP requests — no mocks.
    """

    def __init__(self, base_url: str, timeout: float = DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(self.timeout),
        )
        return self

    async def __aexit__(self, *exc):
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        if not self._client:
            raise RuntimeError("Use 'async with NodeRPCClient(...)' context manager")
        return self._client

    # ─────────── Rate-limit-aware HTTP helpers ───────────

    async def _request_with_retry(self, method: str, path: str, **kwargs) -> httpx.Response:
        """
        Execute an HTTP request with automatic retry on 429 Too Many Requests.

        Uses exponential backoff: 1s → 2s → 4s → 8s.
        All public methods should use this instead of self.client.get/post directly.
        """
        for attempt in range(MAX_RETRIES + 1):
            resp = await self.client.request(method, path, **kwargs)
            if resp.status_code != 429:
                return resp
            delay = RETRY_BASE_DELAY * (2 ** attempt)
            logger.debug("429 on %s %s (attempt %d/%d), retrying in %.1fs",
                         method, path, attempt + 1, MAX_RETRIES + 1, delay)
            await asyncio.sleep(delay)
        # Return the last 429 response so caller can raise_for_status
        return resp

    # ─────────── Low-level helpers ───────────

    async def _get(self, path: str, params: dict = None) -> Optional[dict]:
        """GET request, returns parsed JSON or None on error."""
        try:
            resp = await self._request_with_retry("GET", path, params=params)
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as e:
            logger.debug("GET %s failed: %s", path, e)
            return None

    async def _post(self, path: str, data: dict = None, json_data: dict = None) -> Optional[dict]:
        """POST request, returns parsed JSON or None on error."""
        try:
            if json_data is not None:
                resp = await self._request_with_retry("POST", path, json=json_data)
            else:
                resp = await self._request_with_retry("POST", path, json=data)
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as e:
            logger.debug("POST %s failed: %s", path, e)
            return None

    # ─────────── Health ───────────

    async def health(self) -> bool:
        """
        Check if node is healthy by hitting GET /.

        The QRDX node returns {"node_version": ..., "unspent_outputs_hash": ...}
        at the root endpoint. There is no /health route.
        """
        try:
            resp = await self._request_with_retry("GET", "/")
            if resp.status_code == 200:
                data = resp.json()
                return "node_version" in data
            return False
        except Exception:
            return False

    async def wait_healthy(self, timeout: float = 30.0, interval: float = 1.0) -> bool:
        """Wait for node to become healthy."""
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            if await self.health():
                return True
            await asyncio.sleep(interval)
        return False

    # ─────────── Block Info ───────────

    async def get_mining_info(self) -> dict:
        """Get current mining/block info — unwraps the {ok, result} envelope."""
        resp = await self._request_with_retry("GET", "/get_mining_info")
        resp.raise_for_status()
        data = resp.json()
        # The endpoint returns {"ok": true, "result": {difficulty, last_block, ...}}
        return data.get("result", data)

    async def get_block(self, block_hash: str) -> dict:
        """Get block by hash."""
        resp = await self._request_with_retry("GET", "/get_block", params={"block_hash": block_hash})
        resp.raise_for_status()
        return resp.json()

    async def get_block_by_id(self, block_id: int) -> dict:
        """Get block by height."""
        resp = await self._request_with_retry("GET", "/get_block", params={"block": block_id})
        resp.raise_for_status()
        return resp.json()

    async def get_last_block(self) -> dict:
        """Get the latest block."""
        info = await self.get_mining_info()
        return info.get("last_block", {})

    async def get_block_height(self) -> int:
        """Get current block height."""
        info = await self.get_mining_info()
        return info.get("last_block", {}).get("id", -1)

    # ─────────── Address / Balance ───────────

    async def get_address_info(self, address: str) -> dict:
        """Get address balance and UTXO info — unwraps {ok, result} envelope."""
        resp = await self._request_with_retry("GET", "/get_address_info", params={"address": address})
        resp.raise_for_status()
        data = resp.json()
        return data.get("result", data)

    async def get_balance(self, address: str) -> Decimal:
        """Get address balance as Decimal."""
        try:
            info = await self.get_address_info(address)
            return Decimal(str(info.get("balance", "0")))
        except Exception:
            return Decimal("0")

    # ─────────── Transactions ───────────

    async def push_tx(self, tx_hex: str) -> dict:
        """Submit a raw transaction via GET /push_tx."""
        resp = await self._request_with_retry("GET", "/push_tx", params={"tx_hex": tx_hex})
        resp.raise_for_status()
        return resp.json()

    async def submit_tx(self, tx_hex: str) -> dict:
        """Submit a raw transaction via POST /submit_tx."""
        resp = await self._request_with_retry("POST", "/submit_tx", json={"tx_hex": tx_hex})
        resp.raise_for_status()
        return resp.json()

    async def get_transaction(self, tx_hash: str) -> Optional[dict]:
        """Get transaction by hash."""
        try:
            resp = await self._request_with_retry("GET", "/get_transaction", params={"tx_hash": tx_hash})
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception:
            return None

    async def get_pending_transactions(self) -> List[dict]:
        """Get pending transactions in mempool."""
        resp = await self._request_with_retry("GET", "/get_pending_transactions")
        resp.raise_for_status()
        return resp.json().get("pending_transactions", [])

    # ─────────── Peers ───────────

    async def get_nodes(self) -> List[str]:
        """Get connected peer nodes. Returns list from the /get_nodes endpoint."""
        resp = await self._request_with_retry("GET", "/get_nodes")
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict):
            # Endpoint returns {"ok": true, "result": [...]}
            return data.get("result", data.get("nodes", []))
        return data

    async def add_node(self, node_url: str) -> dict:
        """Add a peer node."""
        resp = await self._request_with_retry("GET", "/add_node", params={"url": node_url})
        resp.raise_for_status()
        return resp.json()

    # ─────────── Validators ───────────

    async def get_validators(self) -> List[dict]:
        """Get registered validators."""
        resp = await self._request_with_retry("GET", "/get_validators")
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict):
            return data.get("validators", [])
        return data

    # ─────────── PQ Info ───────────

    async def get_pq_peer_info(self) -> dict:
        """Get PQ identity information."""
        try:
            resp = await self._request_with_retry("GET", "/pq/peer_info")
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return {}

    # ─────────── System Wallets ───────────

    async def get_system_wallets(self) -> dict:
        """Get system wallet info."""
        try:
            resp = await self._request_with_retry("GET", "/system_wallets")
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return {}

    # ─────────── JSON-RPC ───────────

    async def json_rpc(self, method: str, params: Optional[list] = None) -> Any:
        """Send a JSON-RPC 2.0 request."""
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": 1,
        }
        resp = await self._request_with_retry("POST", "/rpc", json=payload)
        resp.raise_for_status()
        result = resp.json()
        if "error" in result:
            raise RuntimeError(f"RPC error: {result['error']}")
        return result.get("result")

    # ─────────── ETH JSON-RPC Helpers ───────────

    async def eth_get_balance(self, address: str) -> int:
        """Get balance in wei via eth_getBalance."""
        result = await self.json_rpc("eth_getBalance", [address, "latest"])
        if result is None:
            return 0
        return int(result, 16) if isinstance(result, str) else int(result)

    async def eth_get_transaction_count(self, address: str) -> int:
        """Get nonce via eth_getTransactionCount."""
        result = await self.json_rpc("eth_getTransactionCount", [address, "latest"])
        if result is None:
            return 0
        return int(result, 16) if isinstance(result, str) else int(result)

    async def eth_send_raw_transaction(self, raw_tx_hex: str) -> Optional[str]:
        """Submit signed RLP-encoded transaction via eth_sendRawTransaction."""
        result = await self.json_rpc("eth_sendRawTransaction", [raw_tx_hex])
        return result  # returns tx hash hex

    async def eth_get_transaction_receipt(self, tx_hash: str) -> Optional[dict]:
        """Get transaction receipt via eth_getTransactionReceipt."""
        return await self.json_rpc("eth_getTransactionReceipt", [tx_hash])

    async def eth_chain_id(self) -> int:
        """Get chain ID via eth_chainId."""
        result = await self.json_rpc("eth_chainId", [])
        if result is None:
            return 0
        return int(result, 16) if isinstance(result, str) else int(result)

    # ─────────── Block Submission ───────────

    async def push_block(self, block_data: dict) -> dict:
        """Submit a block to the node."""
        resp = await self._request_with_retry("POST", "/push_block", json=block_data)
        resp.raise_for_status()
        return resp.json()

    # ─────────── Convenience: wait for tx ───────────

    async def wait_tx_confirmed(self, tx_hash: str, timeout: float = 30.0) -> bool:
        """Wait for a transaction to be confirmed (appear with a block_hash)."""
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            tx = await self.get_transaction(tx_hash)
            if tx and tx.get("block_hash"):
                return True
            await asyncio.sleep(1.0)
        return False


class MultiNodeClient:
    """
    Client that talks to all testnet nodes.
    Provides cross-node consistency checks.
    """

    def __init__(self, node_urls: List[str], timeout: float = DEFAULT_TIMEOUT):
        self.node_urls = node_urls
        self.timeout = timeout
        self._clients: List[NodeRPCClient] = []

    async def __aenter__(self):
        self._clients = []
        for url in self.node_urls:
            client = NodeRPCClient(url, self.timeout)
            await client.__aenter__()
            self._clients.append(client)
        return self

    async def __aexit__(self, *exc):
        for client in self._clients:
            await client.__aexit__(*exc)

    def __getitem__(self, index: int) -> NodeRPCClient:
        return self._clients[index]

    def __len__(self) -> int:
        return len(self._clients)

    async def all_healthy(self) -> bool:
        """Check all nodes are healthy."""
        results = await asyncio.gather(*[c.health() for c in self._clients])
        return all(results)

    async def wait_all_healthy(self, timeout: float = 60.0) -> bool:
        """Wait for all nodes to be healthy."""
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            if await self.all_healthy():
                return True
            await asyncio.sleep(1.0)
        return False

    async def get_block_heights(self) -> List[int]:
        """Get block height from each node."""
        return list(await asyncio.gather(*[c.get_block_height() for c in self._clients]))

    async def check_balance_consistency(self, address: str) -> bool:
        """Check that all nodes report the same balance for an address."""
        balances = await asyncio.gather(*[c.get_balance(address) for c in self._clients])
        return len(set(balances)) <= 1

    async def get_peer_counts(self) -> List[int]:
        """Get peer count from each node."""
        results = await asyncio.gather(*[c.get_nodes() for c in self._clients])
        return [len(r) for r in results]

    async def broadcast_tx(self, tx_hex: str) -> dict:
        """Submit tx to the first node (it propagates to others)."""
        return await self._clients[0].push_tx(tx_hex)

    async def wait_tx_confirmed(self, tx_hash: str, timeout: float = 30.0) -> bool:
        """Wait for a transaction to be confirmed on all nodes."""
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            results = await asyncio.gather(
                *[c.get_transaction(tx_hash) for c in self._clients],
                return_exceptions=True
            )
            confirmed = [
                r for r in results
                if isinstance(r, dict) and r.get("block_hash")
            ]
            if len(confirmed) == len(self._clients):
                return True
            await asyncio.sleep(1.0)
        return False
