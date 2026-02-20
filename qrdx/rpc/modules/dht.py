"""
QRDX dht_* RPC Methods

Kademlia DHT JSON-RPC methods for peer discovery.

These methods are always registered (not gated by QRDX_RPC_ENABLED)
because they are essential for inter-node DHT protocol communication.

Methods:
    dht_message     — Handle an incoming DHT protocol message (PING, FIND_NODE, STORE, FIND_VALUE)
    dht_getStats    — Return DHT discovery statistics
    dht_getPeers    — Return peers from the DHT routing table
    dht_getRoutingTable — Return detailed routing table info
"""

from typing import Any, Dict, List, Optional

from ..server import RPCModule, rpc_method, RPCError, RPCErrorCode
from ...logger import get_logger

logger = get_logger(__name__)


class DHTModule(RPCModule):
    """
    Kademlia DHT RPC methods (dht_* namespace).

    The module holds a reference to the live KademliaDiscovery instance
    and the optional DNSSeedDiscovery instance set by the node during
    startup via ``set_discovery()``.
    """

    namespace = "dht"

    def __init__(self, context: Any = None):
        super().__init__(context)
        self._discovery = None        # KademliaDiscovery
        self._dns_seeds = None         # DNSSeedDiscovery

    # -- Wiring (called from _init_dht in main.py) -------------------------

    def set_discovery(self, discovery, dns_seeds=None) -> None:
        """
        Attach the live DHT subsystem so RPC handlers can delegate to it.

        Args:
            discovery: KademliaDiscovery instance (or None).
            dns_seeds: DNSSeedDiscovery instance (or None).
        """
        self._discovery = discovery
        self._dns_seeds = dns_seeds

    def _require_discovery(self):
        """Raise RPCError if DHT is not initialized."""
        if self._discovery is None:
            raise RPCError(
                RPCErrorCode.RESOURCE_UNAVAILABLE,
                "DHT subsystem not initialized",
            )

    # -- RPC methods --------------------------------------------------------

    @rpc_method
    async def message(self, msg: Dict) -> Dict:
        """
        Handle an incoming Kademlia DHT protocol message.

        This is the main entry-point used by remote nodes to send
        PING, FIND_NODE, STORE, and FIND_VALUE RPCs.

        Args:
            msg: DHT message dict with ``type``, ``sender_id``, etc.

        Returns:
            DHT response message dict.
        """
        self._require_discovery()
        try:
            return self._discovery.handle_incoming(msg)
        except Exception as e:
            logger.error(f"DHT message handling error: {e}")
            raise RPCError(RPCErrorCode.INTERNAL_ERROR, f"DHT message error: {e}")

    @rpc_method
    async def getStats(self) -> Dict:
        """
        Return Kademlia DHT discovery statistics.

        Returns:
            Dict with ``running``, ``local_node_id``, ``routing_table``,
            ``store_entries``, and optionally ``dns_seeds`` stats.
        """
        self._require_discovery()
        stats = self._discovery.get_stats()
        if self._dns_seeds is not None:
            stats['dns_seeds'] = self._dns_seeds.get_stats()
        return stats

    @rpc_method
    async def getPeers(self, count: int = 20) -> List[Dict]:
        """
        Return peers from the DHT routing table, sorted by most recently seen.

        Args:
            count: Maximum number of peers to return (default 20).

        Returns:
            List of peer dicts with ``node_id``, ``host``, ``port``, ``last_seen``.
        """
        self._require_discovery()
        count = min(max(1, count), 200)  # clamp to [1, 200]
        peers: List[Dict] = []
        for bucket in self._discovery.routing_table._buckets:
            for entry in bucket.entries:
                peers.append({
                    'node_id': entry.node_id_hex,
                    'host': entry.host,
                    'port': entry.port,
                    'last_seen': entry.last_seen,
                    'is_inbound': entry.is_inbound,
                })
        # Sort by last_seen descending (most recent first)
        peers.sort(key=lambda p: p['last_seen'], reverse=True)
        return peers[:count]

    @rpc_method
    async def getRoutingTable(self) -> Dict:
        """
        Return detailed routing table information.

        Returns:
            Dict with per-bucket fill levels and aggregate statistics.
        """
        self._require_discovery()
        rt = self._discovery.routing_table
        stats = rt.get_stats()
        # Add per-bucket fill levels
        bucket_fills = []
        for bucket in rt._buckets:
            bucket_fills.append({
                'index': bucket.index,
                'size': len(bucket.entries),
                'replacement_cache': len(bucket.replacement_cache),
            })
        stats['buckets'] = bucket_fills
        return stats
