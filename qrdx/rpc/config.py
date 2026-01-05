"""
QRDX RPC Configuration
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class HTTPConfig:
    """HTTP RPC configuration."""
    
    # Enable HTTP RPC
    enabled: bool = True
    
    # Listen address
    host: str = "127.0.0.1"
    
    # Listen port
    port: int = 8545
    
    # Enable CORS
    cors_enabled: bool = True
    
    # CORS allowed origins
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    
    # Rate limit (requests per minute per IP)
    rate_limit: int = 1000
    
    # Maximum request body size (bytes)
    max_request_size: int = 5 * 1024 * 1024  # 5MB
    
    # Request timeout (seconds)
    timeout: float = 30.0


@dataclass
class WebSocketConfig:
    """WebSocket RPC configuration."""
    
    # Enable WebSocket RPC
    enabled: bool = True
    
    # Listen address
    host: str = "127.0.0.1"
    
    # Listen port
    port: int = 8546
    
    # Maximum concurrent connections
    max_connections: int = 100
    
    # Enable subscriptions
    subscriptions_enabled: bool = True
    
    # Maximum subscriptions per connection
    max_subscriptions: int = 100
    
    # Ping interval (seconds)
    ping_interval: float = 30.0
    
    # Connection timeout (seconds)
    timeout: float = 60.0


@dataclass
class ModulesConfig:
    """RPC modules configuration."""
    
    # eth_* namespace (Web3 compatible)
    eth: bool = True
    
    # net_* namespace
    net: bool = True
    
    # web3_* namespace
    web3: bool = True
    
    # qrdx_* namespace (chain-specific)
    qrdx: bool = True
    
    # admin_* namespace (privileged)
    admin: bool = False
    
    # debug_* namespace (development)
    debug: bool = False


@dataclass
class LegacyConfig:
    """Legacy Denaro REST configuration."""
    
    # Enable legacy endpoints
    enabled: bool = False
    
    # Use separate port (None = same as HTTP RPC)
    port: Optional[int] = None
    
    # Show deprecation warnings
    deprecation_warnings: bool = True


@dataclass
class RPCConfig:
    """RPC configuration."""
    
    # Enable RPC interfaces
    enabled: bool = True
    
    # HTTP configuration
    http: HTTPConfig = field(default_factory=HTTPConfig)
    
    # WebSocket configuration
    websocket: WebSocketConfig = field(default_factory=WebSocketConfig)
    
    # Enabled modules
    modules: ModulesConfig = field(default_factory=ModulesConfig)
    
    # Legacy REST configuration
    legacy: LegacyConfig = field(default_factory=LegacyConfig)
    
    @classmethod
    def from_dict(cls, config: dict) -> "RPCConfig":
        """Create from dictionary."""
        http_dict = config.pop("http", {})
        websocket_dict = config.pop("websocket", {})
        modules_dict = config.pop("modules", {})
        legacy_dict = config.pop("legacy", {})
        
        return cls(
            **config,
            http=HTTPConfig(**http_dict),
            websocket=WebSocketConfig(**websocket_dict),
            modules=ModulesConfig(**modules_dict),
            legacy=LegacyConfig(**legacy_dict),
        )
