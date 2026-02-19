"""
QRDX P2P Networking Module (Post-Quantum)

Implements post-quantum peer-to-peer networking with:
- Dilithium3 node identity and @-schema addressing
- 4-step PQ handshake (Dilithium + Kyber → AES-256-GCM)
- Kademlia DHT peer discovery with BLAKE3 node IDs
- Encrypted transport via Kyber-derived shared secrets
"""

from .node import (
    Node,
    NodeID,
    Address,
    derive_node_id,
    derive_node_id_hex,
    node_id_to_hex,
    hex_to_node_id,
)
from .config import P2PConfig
from .handshake import (
    HandshakeInitiator,
    HandshakeResponder,
    HandshakeResult,
    HelloMessage,
    HelloAckMessage,
    AuthMessage,
    AuthAckMessage,
    encrypt_message,
    decrypt_message,
    derive_channel_keys,
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
]
