"""
QRDX P2P Networking Module (Post-Quantum)

Implements post-quantum peer-to-peer networking with:
- Dilithium3 node identity and @-schema addressing
- 4-step PQ handshake (Dilithium + Kyber → AES-256-GCM)
- Kademlia DHT peer discovery with BLAKE3 160-bit node IDs
- Full k-bucket routing table with eclipse-attack resistance
- Iterative FIND_NODE lookups with α=3 concurrency
- DNS seed discovery with Dilithium signature verification
- Encrypted transport via Kyber-derived shared secrets
"""

from .config import P2PConfig
from .discovery import (
    DHTMessage,
    DHTMessageType,
    KademliaDiscovery,
    KademliaProtocol,
)
from .dns_seeds import (
    DNSSeedDiscovery,
    DNSSeedResult,
    SeedOperator,
)
from .handshake import (
    AuthAckMessage,
    AuthMessage,
    HandshakeInitiator,
    HandshakeResponder,
    HandshakeResult,
    HelloAckMessage,
    HelloMessage,
    decrypt_message,
    derive_channel_keys,
    encrypt_message,
)
from .node import (
    Address,
    Node,
    NodeID,
    derive_node_id,
    derive_node_id_hex,
    hex_to_node_id,
    node_id_to_hex,
)
from .routing import (
    ALPHA,
    K_BUCKET_SIZE,
    NUM_BUCKETS,
    KBucket,
    KBucketEntry,
    RoutingTable,
)

__all__ = [
    # Node
    "Node",
    "NodeID",
    "Address",
    "derive_node_id",
    "derive_node_id_hex",
    "node_id_to_hex",
    "hex_to_node_id",
    # Config
    "P2PConfig",
    # Handshake
    "HandshakeInitiator",
    "HandshakeResponder",
    "HandshakeResult",
    "HelloMessage",
    "HelloAckMessage",
    "AuthMessage",
    "AuthAckMessage",
    "encrypt_message",
    "decrypt_message",
    "derive_channel_keys",
    # Routing Table
    "RoutingTable",
    "KBucket",
    "KBucketEntry",
    "K_BUCKET_SIZE",
    "NUM_BUCKETS",
    "ALPHA",
    # Discovery
    "KademliaDiscovery",
    "KademliaProtocol",
    "DHTMessage",
    "DHTMessageType",
    # DNS Seeds
    "DNSSeedDiscovery",
    "SeedOperator",
    "DNSSeedResult",
]
