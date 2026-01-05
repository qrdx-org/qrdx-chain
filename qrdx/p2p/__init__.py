"""
QRDX P2P Networking Module

Implements devp2p-style peer-to-peer networking with:
- Node discovery via Kademlia DHT
- Encrypted transport (RLPx)
- Post-quantum cryptography support
- Protocol multiplexing
"""

from .node import Node, NodeID
from .config import P2PConfig

__all__ = [
    "Node",
    "NodeID",
    "P2PConfig",
]
