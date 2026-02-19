"""
QRDX Node Bootstrap Manager

Handles initial peer discovery and network bootstrapping from a list of
bootstrap nodes. Provides resilient connection logic with fallback
to multiple bootstrap nodes.
"""

import asyncio
import random
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import httpx

from ..logger import get_logger
from ..constants import (
    BOOTSTRAP_NODES, BOOTSTRAP_NODES_PARSED, DENARO_BOOTSTRAP_NODE, 
    CONNECTION_TIMEOUT, parse_bootstrap_node, ParsedBootstrapNode
)

logger = get_logger(__name__)


class BootstrapStatus(Enum):
    """Status of bootstrap node."""
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNREACHABLE = "unreachable"


@dataclass
class BootstrapNode:
    """
    Represents a bootstrap node with health tracking.
    
    Supports HTTP URLs, qnode:// URIs, and @-schema addresses.
    When created from an @-schema address, the node_id field
    can be used for identity verification during PQ handshake.
    """
    url: str                              # HTTP URL for API connection
    public_key: str = ""                  # Node's public key (from qnode URI)
    host: str = ""                        # Hostname
    port: int = 0                         # Port number
    original_uri: str = ""                # Original URI (@-schema, qnode://, or http://)
    is_qnode_uri: bool = False            # True if from qnode:// or @-schema URI
    node_id: str = ""                     # PQ node ID (qx…) from @-schema
    algo: str = ""                        # PQ algorithm from @-schema
    status: BootstrapStatus = BootstrapStatus.UNKNOWN
    last_check: float = 0
    failures: int = 0
    peers_discovered: int = 0
    latency_ms: float = 0
    
    @classmethod
    def from_parsed(cls, parsed: ParsedBootstrapNode) -> 'BootstrapNode':
        """Create BootstrapNode from ParsedBootstrapNode."""
        return cls(
            url=parsed.url,
            public_key=parsed.public_key,
            host=parsed.host,
            port=parsed.port,
            original_uri=parsed.original,
            is_qnode_uri=parsed.is_qnode,
            node_id=getattr(parsed, 'node_id', ''),
            algo=getattr(parsed, 'algo', ''),
        )
    
    @classmethod
    def from_uri(cls, uri: str) -> 'BootstrapNode':
        """Create BootstrapNode from URI string (@-schema, qnode://, or http://)."""
        parsed = parse_bootstrap_node(uri)
        return cls.from_parsed(parsed)

    @property
    def is_pq(self) -> bool:
        """True if this node was parsed from an @-schema address."""
        return bool(self.node_id and self.algo)


@dataclass
class BootstrapResult:
    """Result of a bootstrap attempt."""
    success: bool
    bootstrap_node: str
    peers_discovered: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None


class BootstrapManager:
    """
    Manages bootstrapping from multiple bootstrap nodes.
    
    Features:
    - Multiple bootstrap node support with health tracking
    - Support for both HTTP URLs and qnode:// URIs
    - Automatic failover when nodes are unreachable
    - Peer discovery aggregation from multiple sources
    - Identity verification via qnode public keys
    """
    
    def __init__(
        self,
        bootstrap_nodes: Optional[List[str]] = None,
        max_retries: int = 3,
        retry_delay: float = 5.0,
    ):
        """
        Initialize bootstrap manager.
        
        Args:
            bootstrap_nodes: List of bootstrap node URIs (http:// or qnode://)
            max_retries: Maximum retry attempts per node
            retry_delay: Delay between retries in seconds
        """
        self._nodes: Dict[str, BootstrapNode] = {}
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._discovered_peers: Set[str] = set()  # Track discovered node IDs
        
        # Initialize bootstrap nodes
        if bootstrap_nodes:
            # Parse provided URIs
            for uri in bootstrap_nodes:
                uri = uri.strip()
                if uri:
                    node = BootstrapNode.from_uri(uri)
                    self._nodes[node.url] = node
        else:
            # Use pre-parsed nodes from constants
            for parsed in BOOTSTRAP_NODES_PARSED:
                node = BootstrapNode.from_parsed(parsed)
                self._nodes[node.url] = node
        
        logger.info(f"Bootstrap manager initialized with {len(self._nodes)} nodes")
    
    @property
    def healthy_nodes(self) -> List[BootstrapNode]:
        """Get list of healthy bootstrap nodes."""
        return [
            node for node in self._nodes.values()
            if node.status in (BootstrapStatus.HEALTHY, BootstrapStatus.UNKNOWN)
        ]
    
    @property
    def all_nodes(self) -> List[BootstrapNode]:
        """Get all bootstrap nodes."""
        return list(self._nodes.values())
    
    async def check_node_health(
        self,
        client: httpx.AsyncClient,
        node: BootstrapNode,
    ) -> bool:
        """
        Check if a bootstrap node is healthy.
        
        Args:
            client: HTTP client
            node: Bootstrap node to check
            
        Returns:
            True if node is healthy
        """
        import time
        
        try:
            start = time.monotonic()
            response = await client.get(
                f"{node.url}/get_status",
                timeout=CONNECTION_TIMEOUT,
            )
            elapsed = (time.monotonic() - start) * 1000
            
            if response.status_code == 200:
                node.status = BootstrapStatus.HEALTHY
                node.latency_ms = elapsed
                node.failures = 0
                node.last_check = time.time()
                return True
            else:
                node.status = BootstrapStatus.UNHEALTHY
                node.failures += 1
                node.last_check = time.time()
                return False
                
        except httpx.RequestError as e:
            node.status = BootstrapStatus.UNREACHABLE
            node.failures += 1
            node.last_check = time.time()
            logger.debug(f"Bootstrap node {node.url} unreachable: {e}")
            return False
    
    async def discover_peers_from_node(
        self,
        client: httpx.AsyncClient,
        node: BootstrapNode,
        signed_request_func: Optional[callable] = None,
    ) -> BootstrapResult:
        """
        Discover peers from a single bootstrap node.
        
        Args:
            client: HTTP client
            node: Bootstrap node to query
            signed_request_func: Optional function to make signed requests
            
        Returns:
            BootstrapResult with discovered peers
        """
        try:
            # First check node health
            if not await self.check_node_health(client, node):
                return BootstrapResult(
                    success=False,
                    bootstrap_node=node.url,
                    error=f"Node unhealthy or unreachable (status: {node.status.value})",
                )
            
            # Get peers - try signed request if available, otherwise unsigned
            if signed_request_func:
                response = await signed_request_func(f"{node.url}/get_peers")
            else:
                response = await client.post(
                    f"{node.url}/get_peers",
                    timeout=CONNECTION_TIMEOUT,
                )
                if response.status_code == 200:
                    response = response.json()
                else:
                    response = None
            
            if not response or not response.get('ok'):
                return BootstrapResult(
                    success=False,
                    bootstrap_node=node.url,
                    error="Failed to get peers from node",
                )
            
            peers = response.get('result', {}).get('peers', [])
            node.peers_discovered = len(peers)
            
            # Filter out already discovered peers
            new_peers = []
            for peer in peers:
                peer_id = peer.get('node_id')
                if peer_id and peer_id not in self._discovered_peers:
                    self._discovered_peers.add(peer_id)
                    new_peers.append(peer)
            
            logger.info(
                f"Discovered {len(new_peers)} new peers from {node.url} "
                f"({len(peers)} total)"
            )
            
            return BootstrapResult(
                success=True,
                bootstrap_node=node.url,
                peers_discovered=new_peers,
            )
            
        except Exception as e:
            logger.error(f"Error discovering peers from {node.url}: {e}")
            return BootstrapResult(
                success=False,
                bootstrap_node=node.url,
                error=str(e),
            )
    
    async def bootstrap(
        self,
        client: httpx.AsyncClient,
        signed_request_func: Optional[callable] = None,
        min_peers: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        Bootstrap from all available bootstrap nodes.
        
        Queries multiple bootstrap nodes in parallel and aggregates
        discovered peers. Uses healthy nodes first, falls back to
        unknown status nodes if needed.
        
        Args:
            client: HTTP client
            signed_request_func: Optional function for signed requests
            min_peers: Minimum peers to discover before stopping
            
        Returns:
            List of discovered peers
        """
        logger.info(f"Starting bootstrap from {len(self._nodes)} nodes...")
        
        all_peers: List[Dict[str, Any]] = []
        self._discovered_peers.clear()
        
        # Shuffle nodes to distribute load
        nodes = list(self._nodes.values())
        random.shuffle(nodes)
        
        # Try each node
        for node in nodes:
            result = await self.discover_peers_from_node(
                client, node, signed_request_func
            )
            
            if result.success and result.peers_discovered:
                all_peers.extend(result.peers_discovered)
                
                # Check if we have enough peers
                if len(all_peers) >= min_peers:
                    logger.info(
                        f"Bootstrap complete: discovered {len(all_peers)} peers "
                        f"from {sum(1 for n in nodes if n.peers_discovered > 0)} nodes"
                    )
                    return all_peers
            
            # Small delay between nodes to prevent hammering
            await asyncio.sleep(0.5)
        
        logger.info(f"Bootstrap finished: discovered {len(all_peers)} total peers")
        return all_peers
    
    async def get_best_bootstrap_node(
        self,
        client: httpx.AsyncClient,
    ) -> Optional[str]:
        """
        Get the best (lowest latency, healthy) bootstrap node.
        
        Args:
            client: HTTP client
            
        Returns:
            URL of best bootstrap node, or None if all unavailable
        """
        # Check health of all nodes
        await asyncio.gather(*[
            self.check_node_health(client, node)
            for node in self._nodes.values()
        ])
        
        # Get healthy nodes sorted by latency
        healthy = sorted(
            [n for n in self._nodes.values() if n.status == BootstrapStatus.HEALTHY],
            key=lambda n: n.latency_ms,
        )
        
        if healthy:
            return healthy[0].url
        
        # Fall back to any unknown status node
        unknown = [n for n in self._nodes.values() if n.status == BootstrapStatus.UNKNOWN]
        if unknown:
            return random.choice(unknown).url
        
        return None
    
    def add_bootstrap_node(self, uri: str) -> bool:
        """
        Add a new bootstrap node dynamically.
        
        Args:
            uri: Bootstrap node URI (http:// or qnode://)
            
        Returns:
            True if added, False if already exists
        """
        node = BootstrapNode.from_uri(uri)
        if node.url in self._nodes:
            return False
        
        self._nodes[node.url] = node
        logger.info(f"Added bootstrap node: {uri} -> {node.url}")
        return True
    
    def remove_bootstrap_node(self, url: str) -> bool:
        """
        Remove a bootstrap node.
        
        Args:
            url: Bootstrap node URL or original URI
            
        Returns:
            True if removed
        """
        # Try direct URL match first
        url = url.strip().rstrip('/')
        if url in self._nodes:
            del self._nodes[url]
            logger.info(f"Removed bootstrap node: {url}")
            return True
        
        # Try matching by original URI
        for node_url, node in list(self._nodes.items()):
            if node.original_uri.rstrip('/') == url:
                del self._nodes[node_url]
                logger.info(f"Removed bootstrap node: {url}")
                return True
        
        return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get bootstrap manager statistics."""
        return {
            "total_nodes": len(self._nodes),
            "healthy_nodes": len([n for n in self._nodes.values() if n.status == BootstrapStatus.HEALTHY]),
            "unhealthy_nodes": len([n for n in self._nodes.values() if n.status == BootstrapStatus.UNHEALTHY]),
            "unreachable_nodes": len([n for n in self._nodes.values() if n.status == BootstrapStatus.UNREACHABLE]),
            "qnode_uri_nodes": len([n for n in self._nodes.values() if n.is_qnode_uri]),
            "pq_nodes": len([n for n in self._nodes.values() if n.is_pq]),
            "total_peers_discovered": len(self._discovered_peers),
            "nodes": [
                {
                    "url": n.url,
                    "original_uri": n.original_uri,
                    "public_key": n.public_key[:32] + "..." if n.public_key else "",
                    "node_id": n.node_id,
                    "algo": n.algo,
                    "is_qnode_uri": n.is_qnode_uri,
                    "is_pq": n.is_pq,
                    "status": n.status.value,
                    "failures": n.failures,
                    "latency_ms": round(n.latency_ms, 2),
                    "peers_discovered": n.peers_discovered,
                }
                for n in self._nodes.values()
            ],
        }
    
    def get_node_public_key(self, url: str) -> Optional[str]:
        """
        Get the public key for a bootstrap node if available.
        
        Args:
            url: Bootstrap node URL
            
        Returns:
            Public key hex string or None
        """
        node = self._nodes.get(url)
        return node.public_key if node and node.public_key else None


# Global bootstrap manager instance
bootstrap_manager: Optional[BootstrapManager] = None


def get_bootstrap_manager() -> BootstrapManager:
    """Get or create the global bootstrap manager."""
    global bootstrap_manager
    if bootstrap_manager is None:
        bootstrap_manager = BootstrapManager()
    return bootstrap_manager


def init_bootstrap_manager(
    bootstrap_nodes: Optional[List[str]] = None,
) -> BootstrapManager:
    """
    Initialize the global bootstrap manager.
    
    Args:
        bootstrap_nodes: Optional list of bootstrap node URLs
        
    Returns:
        Initialized BootstrapManager
    """
    global bootstrap_manager
    bootstrap_manager = BootstrapManager(bootstrap_nodes=bootstrap_nodes)
    return bootstrap_manager
