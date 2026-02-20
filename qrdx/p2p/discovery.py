"""
QRDX Kademlia DHT Discovery Protocol

Implements the full Kademlia peer discovery protocol:
- PING/PONG: liveness checks
- FIND_NODE: iterative closest-node lookup with α=3 concurrency
- STORE/FIND_VALUE: key-value storage for peer records
- Iterative lookup algorithm with shortlist convergence
- Bucket refresh via random target generation
- Bootstrap integration: seed from known nodes, then self-sustain
- Periodic refresh loop for long-running nodes

All network calls are async via httpx. The wire protocol uses JSON
over HTTP POST at the /dht/* endpoint namespace.

Reference: Kademlia §2.3 — iterative lookup algorithm.
"""

import asyncio
import os
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

import httpx

from .node import Node, NodeID, Address, derive_node_id, node_id_to_hex, hex_to_node_id
from .routing import (
    RoutingTable,
    KBucketEntry,
    K_BUCKET_SIZE,
    ALPHA,
    MAX_FIND_RESULTS,
    BUCKET_REFRESH_INTERVAL,
)
from ..logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum concurrent FIND_NODE RPCs per lookup
LOOKUP_CONCURRENCY = ALPHA  # 3

# Maximum rounds in iterative lookup before giving up
MAX_LOOKUP_ROUNDS = 10

# Timeout for a single DHT RPC (seconds)
DHT_RPC_TIMEOUT = 5.0

# How often to run the periodic refresh loop (seconds)
REFRESH_LOOP_INTERVAL = 60

# Minimum nodes to consider bootstrap successful
MIN_BOOTSTRAP_PEERS = 3

# Maximum STORE value size (bytes)
MAX_STORE_VALUE_SIZE = 8192

# Store TTL (seconds) — stored values expire after 24 hours
STORE_TTL = 24 * 60 * 60


# ---------------------------------------------------------------------------
# DHT Message Types
# ---------------------------------------------------------------------------

class DHTMessageType(str, Enum):
    """DHT RPC message types."""
    PING = "ping"
    PONG = "pong"
    FIND_NODE = "find_node"
    FIND_NODE_RESPONSE = "find_node_response"
    STORE = "store"
    STORE_RESPONSE = "store_response"
    FIND_VALUE = "find_value"
    FIND_VALUE_RESPONSE = "find_value_response"


# ---------------------------------------------------------------------------
# DHT Messages
# ---------------------------------------------------------------------------

@dataclass
class DHTMessage:
    """A DHT protocol message."""

    type: DHTMessageType
    sender_id: str          # 'qx'-prefixed node ID hex
    sender_host: str        # Sender's host
    sender_port: int        # Sender's port
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            'type': self.type.value,
            'sender_id': self.sender_id,
            'sender_host': self.sender_host,
            'sender_port': self.sender_port,
            'payload': self.payload,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'DHTMessage':
        return cls(
            type=DHTMessageType(d['type']),
            sender_id=d['sender_id'],
            sender_host=d['sender_host'],
            sender_port=d['sender_port'],
            payload=d.get('payload', {}),
        )


# ---------------------------------------------------------------------------
# KademliaProtocol (handles incoming DHT RPCs)
# ---------------------------------------------------------------------------

class KademliaProtocol:
    """
    Handles incoming DHT protocol messages and generates responses.

    This is the server side of the DHT — it processes PING, FIND_NODE,
    STORE, and FIND_VALUE requests.
    """

    def __init__(self, routing_table: RoutingTable, local_node: Node):
        self._rt = routing_table
        self._local_node = local_node
        self._store: Dict[str, Tuple[bytes, float]] = {}  # key → (value, expiry)

    def _make_sender_info(self) -> dict:
        """Build sender identification fields."""
        addr = self._local_node.address
        return {
            'sender_id': self._local_node.node_id_hex,
            'sender_host': addr.ip if addr else '127.0.0.1',
            'sender_port': addr.tcp_port if addr else 30303,
        }

    def _entry_from_message(self, msg: DHTMessage) -> KBucketEntry:
        """Create a routing table entry from an incoming message's sender info."""
        node_id = hex_to_node_id(msg.sender_id)
        return KBucketEntry(
            node_id=node_id,
            node_id_hex=msg.sender_id,
            host=msg.sender_host,
            port=msg.sender_port,
            public_key_hex='',
            at_schema='',
            last_seen=time.monotonic(),
            added_at=time.monotonic(),
            is_inbound=True,
        )

    def handle_message(self, msg: DHTMessage) -> DHTMessage:
        """
        Process an incoming DHT message and return a response.

        Also adds the sender to the routing table (inbound contact).
        """
        # Update routing table with sender
        entry = self._entry_from_message(msg)
        self._rt.add_node(entry, is_inbound=True)

        if msg.type == DHTMessageType.PING:
            return self._handle_ping(msg)
        elif msg.type == DHTMessageType.FIND_NODE:
            return self._handle_find_node(msg)
        elif msg.type == DHTMessageType.STORE:
            return self._handle_store(msg)
        elif msg.type == DHTMessageType.FIND_VALUE:
            return self._handle_find_value(msg)
        else:
            return DHTMessage(
                type=DHTMessageType.PONG,
                **self._make_sender_info(),
                payload={'error': f'Unknown message type: {msg.type}'},
            )

    def _handle_ping(self, msg: DHTMessage) -> DHTMessage:
        """Handle PING → respond with PONG."""
        return DHTMessage(
            type=DHTMessageType.PONG,
            **self._make_sender_info(),
        )

    def _handle_find_node(self, msg: DHTMessage) -> DHTMessage:
        """Handle FIND_NODE → return k closest nodes to target."""
        target_hex = msg.payload.get('target', '')
        try:
            target_id = hex_to_node_id(target_hex)
        except (ValueError, TypeError):
            return DHTMessage(
                type=DHTMessageType.FIND_NODE_RESPONSE,
                **self._make_sender_info(),
                payload={'nodes': [], 'error': 'Invalid target'},
            )

        closest = self._rt.find_closest(
            target_id,
            count=K_BUCKET_SIZE,
            exclude={hex_to_node_id(msg.sender_id)},
        )

        nodes = [
            {
                'node_id': e.node_id_hex,
                'host': e.host,
                'port': e.port,
                'public_key_hex': e.public_key_hex,
            }
            for e in closest
        ]

        return DHTMessage(
            type=DHTMessageType.FIND_NODE_RESPONSE,
            **self._make_sender_info(),
            payload={'nodes': nodes},
        )

    def _handle_store(self, msg: DHTMessage) -> DHTMessage:
        """Handle STORE → store a key-value pair."""
        key = msg.payload.get('key', '')
        value = msg.payload.get('value', '')

        if not key or not value:
            return DHTMessage(
                type=DHTMessageType.STORE_RESPONSE,
                **self._make_sender_info(),
                payload={'stored': False, 'error': 'Missing key or value'},
            )

        if len(value) > MAX_STORE_VALUE_SIZE:
            return DHTMessage(
                type=DHTMessageType.STORE_RESPONSE,
                **self._make_sender_info(),
                payload={'stored': False, 'error': 'Value too large'},
            )

        # Clean expired entries
        self._cleanup_store()

        expiry = time.time() + STORE_TTL
        self._store[key] = (value.encode() if isinstance(value, str) else value, expiry)

        return DHTMessage(
            type=DHTMessageType.STORE_RESPONSE,
            **self._make_sender_info(),
            payload={'stored': True},
        )

    def _handle_find_value(self, msg: DHTMessage) -> DHTMessage:
        """Handle FIND_VALUE → return value if found, else closest nodes."""
        key = msg.payload.get('key', '')

        if key in self._store:
            value, expiry = self._store[key]
            if time.time() < expiry:
                return DHTMessage(
                    type=DHTMessageType.FIND_VALUE_RESPONSE,
                    **self._make_sender_info(),
                    payload={
                        'found': True,
                        'value': value.decode() if isinstance(value, bytes) else value,
                    },
                )
            else:
                del self._store[key]

        # Value not found — return closest nodes (same as FIND_NODE)
        try:
            target_id = hex_to_node_id(key)
        except (ValueError, TypeError):
            target_id = derive_node_id(key.encode())

        closest = self._rt.find_closest(
            target_id,
            count=K_BUCKET_SIZE,
            exclude={hex_to_node_id(msg.sender_id)},
        )

        nodes = [
            {
                'node_id': e.node_id_hex,
                'host': e.host,
                'port': e.port,
            }
            for e in closest
        ]

        return DHTMessage(
            type=DHTMessageType.FIND_VALUE_RESPONSE,
            **self._make_sender_info(),
            payload={'found': False, 'nodes': nodes},
        )

    def _cleanup_store(self) -> None:
        """Remove expired store entries."""
        now = time.time()
        expired = [k for k, (_, exp) in self._store.items() if now >= exp]
        for k in expired:
            del self._store[k]


# ---------------------------------------------------------------------------
# KademliaDiscovery (client-side iterative lookups)
# ---------------------------------------------------------------------------

class KademliaDiscovery:
    """
    Client-side Kademlia discovery — performs iterative lookups
    to find nodes closest to a target.

    Features:
    - Iterative FIND_NODE with α=3 concurrent RPCs
    - Bootstrap from seed nodes
    - Periodic bucket refresh
    - Self-sustaining: persists routing table across restarts
    - Integrates with BootstrapManager for initial seeds
    """

    def __init__(
        self,
        local_node: Node,
        routing_table: RoutingTable,
        *,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self._local = local_node
        self._rt = routing_table
        self._protocol = KademliaProtocol(routing_table, local_node)
        self._client = http_client
        self._running = False
        self._refresh_task: Optional[asyncio.Task] = None

    @property
    def routing_table(self) -> RoutingTable:
        return self._rt

    @property
    def protocol(self) -> KademliaProtocol:
        return self._protocol

    # -- RPC calls ----------------------------------------------------------

    async def _send_rpc(
        self,
        host: str,
        port: int,
        msg: DHTMessage,
    ) -> Optional[DHTMessage]:
        """
        Send a DHT RPC message to a remote node via HTTP POST.

        Returns the response message, or None on failure.
        """
        url = f"http://{host}:{port}/dht/message"
        client = self._client or httpx.AsyncClient()
        should_close = self._client is None

        try:
            response = await client.post(
                url,
                json=msg.to_dict(),
                timeout=DHT_RPC_TIMEOUT,
            )
            if response.status_code == 200:
                return DHTMessage.from_dict(response.json())
            return None
        except (httpx.RequestError, httpx.HTTPStatusError, Exception) as e:
            logger.debug(f"DHT RPC to {host}:{port} failed: {e}")
            return None
        finally:
            if should_close:
                await client.aclose()

    async def ping(self, host: str, port: int) -> bool:
        """
        Send a PING to a remote node.

        Returns True if the node responds with PONG.
        """
        addr = self._local.address
        msg = DHTMessage(
            type=DHTMessageType.PING,
            sender_id=self._local.node_id_hex,
            sender_host=addr.ip if addr else '127.0.0.1',
            sender_port=addr.tcp_port if addr else 30303,
        )
        response = await self._send_rpc(host, port, msg)
        return response is not None and response.type == DHTMessageType.PONG

    async def find_node(
        self,
        host: str,
        port: int,
        target: NodeID,
    ) -> List[KBucketEntry]:
        """
        Send a FIND_NODE RPC to a remote node.

        Returns list of node entries from the response.
        """
        addr = self._local.address
        msg = DHTMessage(
            type=DHTMessageType.FIND_NODE,
            sender_id=self._local.node_id_hex,
            sender_host=addr.ip if addr else '127.0.0.1',
            sender_port=addr.tcp_port if addr else 30303,
            payload={'target': node_id_to_hex(target)},
        )

        response = await self._send_rpc(host, port, msg)
        if not response or response.type != DHTMessageType.FIND_NODE_RESPONSE:
            return []

        entries = []
        for node_data in response.payload.get('nodes', []):
            try:
                nid = hex_to_node_id(node_data['node_id'])
                entry = KBucketEntry(
                    node_id=nid,
                    node_id_hex=node_data['node_id'],
                    host=node_data['host'],
                    port=node_data['port'],
                    public_key_hex=node_data.get('public_key_hex', ''),
                    at_schema='',
                    last_seen=time.monotonic(),
                    added_at=time.monotonic(),
                    is_inbound=False,
                )
                entries.append(entry)
            except (KeyError, ValueError) as e:
                logger.debug(f"Skipping malformed node in FIND_NODE response: {e}")

        return entries

    # -- Iterative lookup ---------------------------------------------------

    async def iterative_find_node(
        self,
        target: NodeID,
        *,
        count: int = MAX_FIND_RESULTS,
    ) -> List[KBucketEntry]:
        """
        Perform an iterative Kademlia FIND_NODE lookup.

        Algorithm (Kademlia §2.3):
        1. Start with α closest nodes from local routing table
        2. Send FIND_NODE to α closest unqueried nodes
        3. Add responses to shortlist, resort by distance
        4. Repeat until no closer nodes are found or all queried

        Returns:
            Up to `count` closest nodes to target.
        """
        target_int = int.from_bytes(target, 'big')

        # Seed shortlist from local routing table
        initial = self._rt.find_closest(target, count=ALPHA)
        if not initial:
            return []

        # Shortlist: all discovered nodes sorted by distance
        shortlist: Dict[bytes, KBucketEntry] = {}
        for entry in initial:
            shortlist[entry.node_id] = entry

        queried: Set[bytes] = set()
        closest_seen = float('inf')

        for _round in range(MAX_LOOKUP_ROUNDS):
            # Pick α closest unqueried nodes
            candidates = sorted(
                [e for nid, e in shortlist.items() if nid not in queried],
                key=lambda e: target_int ^ int.from_bytes(e.node_id, 'big'),
            )[:ALPHA]

            if not candidates:
                break  # All nodes queried

            # Query them concurrently
            tasks = []
            for candidate in candidates:
                queried.add(candidate.node_id)
                tasks.append(
                    self.find_node(candidate.host, candidate.port, target)
                )

            results = await asyncio.gather(*tasks, return_exceptions=True)

            new_nodes_found = False
            for result in results:
                if isinstance(result, Exception) or not result:
                    continue
                for entry in result:
                    if entry.node_id not in shortlist and entry.node_id != self._local.node_id:
                        shortlist[entry.node_id] = entry
                        # Add to routing table
                        self._rt.add_node(entry, is_inbound=False)
                        new_nodes_found = True

            # Check convergence: has our closest node improved?
            current_closest = min(
                (target_int ^ int.from_bytes(nid, 'big') for nid in shortlist),
                default=float('inf'),
            )
            if current_closest >= closest_seen and not new_nodes_found:
                break  # Converged
            closest_seen = current_closest

        # Return the `count` closest from shortlist
        sorted_entries = sorted(
            shortlist.values(),
            key=lambda e: target_int ^ int.from_bytes(e.node_id, 'big'),
        )
        return sorted_entries[:count]

    # -- Bootstrap ----------------------------------------------------------

    async def bootstrap(
        self,
        seed_nodes: List[Tuple[str, int]],
    ) -> int:
        """
        Bootstrap the DHT from a list of seed nodes.

        Performs FIND_NODE(self) to each seed, then an iterative lookup
        for our own ID to populate the routing table.

        Args:
            seed_nodes: List of (host, port) tuples for bootstrap nodes.

        Returns:
            Number of nodes discovered.
        """
        logger.info(f"DHT bootstrap starting with {len(seed_nodes)} seeds")

        # Ping and FIND_NODE(self) to each seed
        for host, port in seed_nodes:
            is_alive = await self.ping(host, port)
            if not is_alive:
                logger.debug(f"Seed {host}:{port} unreachable")
                continue

            # Ask the seed for nodes close to us
            found = await self.find_node(host, port, self._local.node_id)
            for entry in found:
                self._rt.add_node(entry, is_inbound=False)

            logger.debug(f"Seed {host}:{port} returned {len(found)} nodes")

        # Iterative lookup for our own ID to fill routing table
        await self.iterative_find_node(self._local.node_id)

        total = self._rt.total_nodes
        logger.info(f"DHT bootstrap complete: {total} nodes in routing table")
        return total

    # -- Periodic refresh ---------------------------------------------------

    async def refresh(self) -> int:
        """
        Refresh stale buckets by performing random lookups.

        For each bucket that hasn't been touched recently, generate
        a random target in that bucket's range and perform an
        iterative FIND_NODE.

        Returns:
            Number of buckets refreshed.
        """
        stale_buckets = self._rt.get_buckets_needing_refresh()
        refreshed = 0

        for bucket_idx in stale_buckets:
            target = self._rt.generate_refresh_target(bucket_idx)
            await self.iterative_find_node(target)
            self._rt.mark_bucket_refreshed(bucket_idx)
            refreshed += 1

        if refreshed:
            logger.debug(f"Refreshed {refreshed} stale buckets")

        # Save routing table after refresh
        self._rt.save()

        return refreshed

    async def _refresh_loop(self) -> None:
        """Background loop that periodically refreshes the routing table."""
        while self._running:
            try:
                await asyncio.sleep(REFRESH_LOOP_INTERVAL)
                if self._running:
                    await self.refresh()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"DHT refresh loop error: {e}")

    def start(self) -> None:
        """Start the periodic refresh loop."""
        if self._running:
            return
        self._running = True
        self._refresh_task = asyncio.ensure_future(self._refresh_loop())
        logger.info("DHT discovery started")

    def stop(self) -> None:
        """Stop the periodic refresh loop and save routing table."""
        self._running = False
        if self._refresh_task:
            self._refresh_task.cancel()
            self._refresh_task = None
        self._rt.save()
        logger.info("DHT discovery stopped")

    # -- Handle incoming messages -------------------------------------------

    def handle_incoming(self, message_dict: dict) -> dict:
        """
        Handle an incoming DHT message (from HTTP endpoint).

        Args:
            message_dict: Raw JSON dict of the incoming message.

        Returns:
            JSON-serializable response dict.
        """
        try:
            msg = DHTMessage.from_dict(message_dict)
            response = self._protocol.handle_message(msg)
            return response.to_dict()
        except (KeyError, ValueError) as e:
            return {
                'type': 'error',
                'error': f'Invalid DHT message: {e}',
            }

    # -- Statistics ----------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Get DHT discovery statistics."""
        rt_stats = self._rt.get_stats()
        return {
            'running': self._running,
            'local_node_id': self._local.node_id_hex,
            'routing_table': rt_stats,
            'store_entries': len(self._protocol._store),
        }
