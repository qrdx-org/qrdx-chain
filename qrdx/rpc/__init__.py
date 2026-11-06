"""
QRDX RPC Module

Provides JSON-RPC 2.0 interfaces for the QRDX blockchain:
- HTTP JSON-RPC server (Web3 compatible)
- WebSocket JSON-RPC server (with subscriptions)
- Legacy Denaro REST endpoints (deprecated, toggleable)
"""

from .config import RPCConfig
from .server import RPCServer

__all__ = [
    "RPCServer",
    "RPCConfig",
]
