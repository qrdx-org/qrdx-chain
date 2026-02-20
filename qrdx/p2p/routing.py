"""
QRDX Kademlia Routing Table

Implements the full Kademlia routing table for peer discovery:
- 160 k-buckets (one per bit of the 160-bit BLAKE3 node ID)
- k = 20 contacts per bucket (Kademlia replication parameter)
- XOR-distance-based closest-node lookup
- Bucket refresh via random ID generation
- Inbound/outbound separation for eclipse-attack resistance
- Per-bucket IP diversity limit (max 2 nodes per /16 subnet)
- Rate-limited bucket insertions
- Persistence to JSON for self-sustaining operation without bootstrap
- Thread-safe via threading.Lock

Reference: Petar Maymounkov & David Mazières, "Kademlia: A Peer-to-Peer
Information System Based on the XOR Metric" (2002)
"""

import json
import os
import time
import threading
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Set

from .node import Node, NodeID, Address, derive_node_id, node_id_to_hex, hex_to_node_id

from ..logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Kademlia replication parameter — contacts per bucket
K_BUCKET_SIZE = 20

# Number of buckets (160-bit node IDs)
NUM_BUCKETS = 160

# Concurrency parameter for iterative lookups
ALPHA = 3

# Maximum nodes to return from a lookup
MAX_FIND_RESULTS = K_BUCKET_SIZE

# Bucket refresh interval (seconds) — refresh idle buckets every 15 minutes
BUCKET_REFRESH_INTERVAL = 15 * 60

# Per-bucket IP diversity: max nodes sharing the same /16 subnet
MAX_SAME_SUBNET_PER_BUCKET = 2

# Rate limit: minimum seconds between insertions into the same bucket
BUCKET_INSERT_COOLDOWN = 0.5

# Routing table persistence filename
ROUTING_TABLE_FILE = "routing_table.json"

# Replacement cache size per bucket
REPLACEMENT_CACHE_SIZE = 10

# Node eviction: consider a node stale after this many seconds without contact
STALE_NODE_TIMEOUT = 60 * 60  # 1 hour


# ---------------------------------------------------------------------------
# KBucketEntry
# ---------------------------------------------------------------------------

@dataclass
class KBucketEntry:
    """A single entry in a k-bucket."""

    node_id: bytes          # 20-byte node ID
    node_id_hex: str        # 'qx'-prefixed hex string
    host: str               # IP / hostname
    port: int               # TCP port
    public_key_hex: str     # Dilithium public key hex (empty if unresolved)
    at_schema: str          # Full @-schema address (empty if unknown)
    last_seen: float        # Monotonic timestamp of last contact
    added_at: float         # When this entry was first added
    is_inbound: bool        # True if this peer connected to us (vs us to them)
    failures: int = 0       # Consecutive communication failures

    @classmethod
    def from_node(cls, node: Node, *, is_inbound: bool = False) -> 'KBucketEntry':
        """Create from a Node object."""
        addr = node.address
        return cls(
            node_id=node.node_id,
            node_id_hex=node.node_id_hex,
            host=addr.ip if addr else '',
            port=addr.tcp_port if addr else 0,
            public_key_hex=node.public_key_hex or '',
            at_schema='',
            last_seen=time.monotonic(),
            added_at=time.monotonic(),
            is_inbound=is_inbound,
        )

    @classmethod
    def from_dict(cls, d: dict) -> 'KBucketEntry':
        """Deserialize from a dict (JSON persistence)."""
        return cls(
            node_id=bytes.fromhex(d['node_id_hex'].replace('qx', '')),
            node_id_hex=d['node_id_hex'],
            host=d['host'],
            port=d['port'],
            public_key_hex=d.get('public_key_hex', ''),
            at_schema=d.get('at_schema', ''),
            last_seen=time.monotonic(),  # Reset on load
            added_at=d.get('added_at', time.monotonic()),
            is_inbound=d.get('is_inbound', False),
            failures=d.get('failures', 0),
        )

    def to_dict(self) -> dict:
        """Serialize to dict for JSON persistence."""
        return {
            'node_id_hex': self.node_id_hex,
            'host': self.host,
            'port': self.port,
            'public_key_hex': self.public_key_hex,
            'at_schema': self.at_schema,
            'is_inbound': self.is_inbound,
            'failures': self.failures,
        }

    def to_node(self) -> Node:
        """Convert back to a Node object (without secret key)."""
        addr = Address(ip=self.host, tcp_port=self.port)
        if self.public_key_hex:
            pk = bytes.fromhex(self.public_key_hex)
            return Node(public_key=pk, address=addr)
        else:
            # Create unresolved node from ID
            node = Node.__new__(Node)
            node._public_key = None
            node._secret_key = None
            node._address = addr
            node._node_id = self.node_id
            node._node_id_hex = self.node_id_hex
            return node

    @property
    def subnet_prefix(self) -> str:
        """
        /16 subnet prefix for IP diversity check.
        For IPv4 addresses: first two octets (e.g. '192.168').
        For hostnames: the full hostname (treated as unique subnet).
        """
        parts = self.host.split('.')
        if len(parts) == 4:
            try:
                # Validate it's a real IPv4
                _ = [int(p) for p in parts]
                return f"{parts[0]}.{parts[1]}"
            except ValueError:
                pass
        return self.host


# ---------------------------------------------------------------------------
# KBucket
# ---------------------------------------------------------------------------

class KBucket:
    """
    A single Kademlia k-bucket holding up to K_BUCKET_SIZE entries.

    Implements:
    - LRU eviction (least-recently-seen at front)
    - Replacement cache for failed eviction pings
    - IP diversity limit per /16 subnet
    - Inbound/outbound separation tracking
    """

    def __init__(self, index: int):
        self.index = index
        self.entries: List[KBucketEntry] = []
        self.replacement_cache: List[KBucketEntry] = []
        self.last_refresh: float = time.monotonic()
        self.last_insert_time: float = 0.0

    @property
    def is_full(self) -> bool:
        return len(self.entries) >= K_BUCKET_SIZE

    @property
    def size(self) -> int:
        return len(self.entries)

    def needs_refresh(self) -> bool:
        """True if this bucket hasn't been refreshed recently."""
        return (time.monotonic() - self.last_refresh) > BUCKET_REFRESH_INTERVAL

    def touch(self) -> None:
        """Mark bucket as recently refreshed."""
        self.last_refresh = time.monotonic()

    def contains(self, node_id: bytes) -> bool:
        """Check if a node ID is in this bucket."""
        return any(e.node_id == node_id for e in self.entries)

    def get_entry(self, node_id: bytes) -> Optional[KBucketEntry]:
        """Get entry by node ID."""
        for entry in self.entries:
            if entry.node_id == node_id:
                return entry
        return None

    def _subnet_count(self, subnet: str) -> int:
        """Count entries sharing the same /16 subnet."""
        return sum(1 for e in self.entries if e.subnet_prefix == subnet)

    def _inbound_count(self) -> int:
        """Count inbound entries."""
        return sum(1 for e in self.entries if e.is_inbound)

    def add_or_update(
        self,
        entry: KBucketEntry,
        *,
        rate_limit: bool = True,
    ) -> Tuple[bool, Optional[KBucketEntry]]:
        """
        Add or update an entry in this bucket.

        Returns:
            (added, eviction_candidate)
            - (True, None): entry added or updated successfully
            - (False, None): rejected (IP diversity / rate limit / full with no eviction)
            - (False, oldest_entry): bucket full — caller should ping oldest_entry;
              if ping fails, call evict_and_replace()
        """
        # Rate limit insertions
        if rate_limit:
            now = time.monotonic()
            if (now - self.last_insert_time) < BUCKET_INSERT_COOLDOWN:
                return False, None

        # If node already in bucket, move to tail (most recently seen)
        for i, existing in enumerate(self.entries):
            if existing.node_id == entry.node_id:
                existing.last_seen = time.monotonic()
                existing.failures = 0
                if entry.public_key_hex:
                    existing.public_key_hex = entry.public_key_hex
                if entry.at_schema:
                    existing.at_schema = entry.at_schema
                # Move to end (most recently seen)
                self.entries.append(self.entries.pop(i))
                self.touch()
                return True, None

        # IP diversity check
        if self._subnet_count(entry.subnet_prefix) >= MAX_SAME_SUBNET_PER_BUCKET:
            logger.debug(
                f"Bucket {self.index}: rejected {entry.node_id_hex[:16]} — "
                f"subnet {entry.subnet_prefix} already has "
                f"{MAX_SAME_SUBNET_PER_BUCKET} entries"
            )
            return False, None

        # Eclipse resistance: limit inbound entries to half the bucket
        if entry.is_inbound and self._inbound_count() >= K_BUCKET_SIZE // 2:
            logger.debug(
                f"Bucket {self.index}: rejected inbound {entry.node_id_hex[:16]} — "
                f"inbound limit reached"
            )
            return False, None

        # Bucket not full — just add
        if not self.is_full:
            self.entries.append(entry)
            self.last_insert_time = time.monotonic()
            self.touch()
            return True, None

        # Bucket full — return the oldest entry as eviction candidate
        # Caller should ping it; if unresponsive, call evict_and_replace
        oldest = self.entries[0]

        # Add to replacement cache in the meantime
        self._add_to_replacement_cache(entry)

        return False, oldest

    def evict_and_replace(self, stale_node_id: bytes) -> bool:
        """
        Evict a stale node and replace with the best entry from replacement cache.

        Called after a ping to the eviction candidate fails.

        Returns True if replacement was made.
        """
        # Remove the stale entry
        self.entries = [e for e in self.entries if e.node_id != stale_node_id]

        # Pull replacement from cache
        if self.replacement_cache:
            replacement = self.replacement_cache.pop(0)
            replacement.last_seen = time.monotonic()
            self.entries.append(replacement)
            self.touch()
            logger.debug(
                f"Bucket {self.index}: evicted stale node, "
                f"replaced with {replacement.node_id_hex[:16]}"
            )
            return True

        return False

    def remove(self, node_id: bytes) -> bool:
        """Remove a node by ID."""
        before = len(self.entries)
        self.entries = [e for e in self.entries if e.node_id != node_id]
        return len(self.entries) < before

    def get_nodes(self) -> List[KBucketEntry]:
        """Get all entries, most recently seen last."""
        return list(self.entries)

    def get_stale_entries(self) -> List[KBucketEntry]:
        """Get entries that haven't been seen recently."""
        now = time.monotonic()
        return [
            e for e in self.entries
            if (now - e.last_seen) > STALE_NODE_TIMEOUT
        ]

    def _add_to_replacement_cache(self, entry: KBucketEntry) -> None:
        """Add to the replacement cache (FIFO, bounded)."""
        # Don't add duplicates
        for cached in self.replacement_cache:
            if cached.node_id == entry.node_id:
                return
        self.replacement_cache.append(entry)
        if len(self.replacement_cache) > REPLACEMENT_CACHE_SIZE:
            self.replacement_cache.pop(0)


# ---------------------------------------------------------------------------
# RoutingTable
# ---------------------------------------------------------------------------

class RoutingTable:
    """
    Full Kademlia routing table with 160 k-buckets.

    Features:
    - XOR-distance-based bucket assignment
    - Closest-node lookups
    - Bucket refresh with random target generation
    - Persistence to/from JSON for self-sustaining operation
    - Thread-safe via Lock
    - Eclipse-attack resistance (IP diversity, inbound limits)
    """

    def __init__(self, local_node_id: NodeID, *, persist_path: Optional[str] = None):
        """
        Initialize routing table.

        Args:
            local_node_id: This node's 20-byte ID.
            persist_path: Directory to store routing_table.json. None disables persistence.
        """
        if len(local_node_id) != 20:
            raise ValueError(f"Node ID must be 20 bytes, got {len(local_node_id)}")

        self._local_id = local_node_id
        self._local_int = int.from_bytes(local_node_id, 'big')
        self._buckets: List[KBucket] = [KBucket(i) for i in range(NUM_BUCKETS)]
        self._lock = threading.Lock()
        self._persist_path = persist_path
        self._total_added = 0
        self._total_evicted = 0

    # -- Bucket index -------------------------------------------------------

    def _bucket_index(self, node_id: NodeID) -> int:
        """
        Determine which bucket a node belongs in based on XOR distance.

        Bucket index = floor(log2(distance)) = bit_length(XOR) - 1
        Same node → bucket 0.
        """
        distance = self._local_int ^ int.from_bytes(node_id, 'big')
        if distance == 0:
            return 0
        return min(distance.bit_length() - 1, NUM_BUCKETS - 1)

    # -- Core operations ----------------------------------------------------

    def add_node(
        self,
        entry: KBucketEntry,
        *,
        is_inbound: bool = False,
    ) -> Tuple[bool, Optional[KBucketEntry]]:
        """
        Add a node to the routing table.

        Args:
            entry: The node entry to add.
            is_inbound: True if this node connected to us.

        Returns:
            (added, eviction_candidate):
            - (True, None) → success
            - (False, None) → rejected
            - (False, candidate) → bucket full; ping candidate and evict if dead
        """
        if entry.node_id == self._local_id:
            return False, None  # Don't add self

        entry.is_inbound = is_inbound
        idx = self._bucket_index(entry.node_id)

        with self._lock:
            added, candidate = self._buckets[idx].add_or_update(entry)
            if added:
                self._total_added += 1
            return added, candidate

    def remove_node(self, node_id: NodeID) -> bool:
        """Remove a node from the routing table."""
        idx = self._bucket_index(node_id)
        with self._lock:
            removed = self._buckets[idx].remove(node_id)
            if removed:
                self._total_evicted += 1
            return removed

    def evict_and_replace(self, stale_node_id: NodeID) -> bool:
        """Evict a stale node and replace from the bucket's replacement cache."""
        idx = self._bucket_index(stale_node_id)
        with self._lock:
            replaced = self._buckets[idx].evict_and_replace(stale_node_id)
            if replaced:
                self._total_evicted += 1
            return replaced

    def get_node(self, node_id: NodeID) -> Optional[KBucketEntry]:
        """Look up a specific node."""
        idx = self._bucket_index(node_id)
        with self._lock:
            return self._buckets[idx].get_entry(node_id)

    def contains(self, node_id: NodeID) -> bool:
        """Check if a node is in the routing table."""
        idx = self._bucket_index(node_id)
        with self._lock:
            return self._buckets[idx].contains(node_id)

    # -- Lookups ------------------------------------------------------------

    def find_closest(self, target: NodeID, *, count: int = MAX_FIND_RESULTS,
                     exclude: Optional[Set[bytes]] = None) -> List[KBucketEntry]:
        """
        Find the `count` closest nodes to a target ID by XOR distance.

        This is the core Kademlia lookup primitive.

        Args:
            target: The 20-byte target node ID.
            count: Maximum number of results.
            exclude: Set of node IDs to exclude from results.

        Returns:
            List of entries sorted by ascending XOR distance to target.
        """
        if exclude is None:
            exclude = set()

        target_int = int.from_bytes(target, 'big')

        with self._lock:
            all_entries = []
            for bucket in self._buckets:
                for entry in bucket.entries:
                    if entry.node_id not in exclude:
                        dist = target_int ^ int.from_bytes(entry.node_id, 'big')
                        all_entries.append((dist, entry))

        all_entries.sort(key=lambda x: x[0])
        return [entry for _, entry in all_entries[:count]]

    def get_all_nodes(self) -> List[KBucketEntry]:
        """Get all nodes across all buckets."""
        with self._lock:
            result = []
            for bucket in self._buckets:
                result.extend(bucket.entries)
            return result

    @property
    def total_nodes(self) -> int:
        """Total number of nodes in the routing table."""
        with self._lock:
            return sum(b.size for b in self._buckets)

    @property
    def non_empty_buckets(self) -> int:
        """Number of non-empty buckets."""
        with self._lock:
            return sum(1 for b in self._buckets if b.size > 0)

    # -- Bucket refresh -----------------------------------------------------

    def get_buckets_needing_refresh(self) -> List[int]:
        """Get indices of buckets that need refreshing."""
        with self._lock:
            return [i for i, b in enumerate(self._buckets) if b.needs_refresh()]

    def generate_refresh_target(self, bucket_index: int) -> NodeID:
        """
        Generate a random node ID that falls into the given bucket.

        Used to initiate a FIND_NODE lookup for bucket refresh.
        """
        # A node ID that is distance 2^bucket_index from our local ID
        # will fall into bucket `bucket_index`.
        # We generate a random ID with the correct prefix bits.
        import secrets

        if bucket_index == 0:
            # Bucket 0 = same as us (distance 0) — use our own ID
            return self._local_id

        # Generate random 160-bit value with bit_length = bucket_index + 1
        # This ensures it falls in the correct bucket
        random_bits = secrets.randbits(bucket_index)
        # Set the highest bit
        distance = (1 << bucket_index) | random_bits
        target_int = self._local_int ^ distance
        # Clamp to 160 bits
        target_int &= (1 << 160) - 1
        return target_int.to_bytes(20, 'big')

    def mark_bucket_refreshed(self, bucket_index: int) -> None:
        """Mark a bucket as just refreshed."""
        with self._lock:
            if 0 <= bucket_index < NUM_BUCKETS:
                self._buckets[bucket_index].touch()

    # -- Persistence --------------------------------------------------------

    def save(self, path: Optional[str] = None) -> None:
        """
        Save the routing table to a JSON file.

        Enables self-sustaining operation: on next startup, the node can
        reconnect to known peers without needing bootstrap nodes.
        """
        save_path = path or self._persist_path
        if not save_path:
            return

        filepath = os.path.join(save_path, ROUTING_TABLE_FILE)
        os.makedirs(save_path, exist_ok=True)

        with self._lock:
            data = {
                'local_node_id': node_id_to_hex(self._local_id),
                'saved_at': time.time(),
                'total_added': self._total_added,
                'total_evicted': self._total_evicted,
                'buckets': {},
            }
            for i, bucket in enumerate(self._buckets):
                if bucket.entries:
                    data['buckets'][str(i)] = [e.to_dict() for e in bucket.entries]

        try:
            tmp_path = filepath + '.tmp'
            with open(tmp_path, 'w') as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, filepath)
            logger.debug(f"Saved routing table: {self.total_nodes} nodes to {filepath}")
        except OSError as e:
            logger.warning(f"Failed to save routing table: {e}")

    @classmethod
    def load(cls, local_node_id: NodeID, persist_path: str) -> 'RoutingTable':
        """
        Load a routing table from a JSON file.

        Falls back to an empty table if the file doesn't exist or is corrupt.
        """
        rt = cls(local_node_id, persist_path=persist_path)
        filepath = os.path.join(persist_path, ROUTING_TABLE_FILE)

        if not os.path.exists(filepath):
            logger.info("No saved routing table found — starting fresh")
            return rt

        try:
            with open(filepath, 'r') as f:
                data = json.load(f)

            loaded = 0
            for idx_str, entries_data in data.get('buckets', {}).items():
                for entry_data in entries_data:
                    try:
                        entry = KBucketEntry.from_dict(entry_data)
                        # Bypass rate limiting when loading from disk
                        if entry.node_id != rt._local_id:
                            bucket_idx = rt._bucket_index(entry.node_id)
                            added, _ = rt._buckets[bucket_idx].add_or_update(
                                entry, rate_limit=False
                            )
                            if added:
                                loaded += 1
                    except (KeyError, ValueError) as e:
                        logger.debug(f"Skipped corrupt entry: {e}")

            logger.info(f"Loaded routing table: {loaded} nodes from {filepath}")
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load routing table: {e} — starting fresh")

        return rt

    # -- Statistics ----------------------------------------------------------

    def get_stats(self) -> Dict:
        """Get routing table statistics."""
        with self._lock:
            total = 0
            inbound = 0
            outbound = 0
            subnets: Set[str] = set()
            stale = 0
            now = time.monotonic()

            for bucket in self._buckets:
                for entry in bucket.entries:
                    total += 1
                    if entry.is_inbound:
                        inbound += 1
                    else:
                        outbound += 1
                    subnets.add(entry.subnet_prefix)
                    if (now - entry.last_seen) > STALE_NODE_TIMEOUT:
                        stale += 1

            return {
                'total_nodes': total,
                'inbound_nodes': inbound,
                'outbound_nodes': outbound,
                'unique_subnets': len(subnets),
                'stale_nodes': stale,
                'non_empty_buckets': sum(1 for b in self._buckets if b.size > 0),
                'total_added': self._total_added,
                'total_evicted': self._total_evicted,
                'replacement_cache_size': sum(
                    len(b.replacement_cache) for b in self._buckets
                ),
            }

    def __repr__(self) -> str:
        return (
            f"RoutingTable(local={node_id_to_hex(self._local_id)[:16]}..., "
            f"nodes={self.total_nodes}, "
            f"buckets={self.non_empty_buckets}/{NUM_BUCKETS})"
        )
