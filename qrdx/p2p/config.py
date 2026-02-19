"""
QRDX P2P Configuration
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class DiscoveryConfig:
    """Discovery protocol configuration."""
    
    # Enable discovery
    enabled: bool = True
    
    # Bootstrap nodes (qnode:// URIs)
    bootnodes: List[str] = field(default_factory=list)
    
    # Enable DNS-based discovery
    dns_enabled: bool = False
    
    # DNS discovery networks
    dns_networks: List[str] = field(default_factory=list)
    
    # Kademlia k-bucket size
    bucket_size: int = 16
    
    # Number of k-buckets (256 for 256-bit node IDs)
    num_buckets: int = 256
    
    # Discovery refresh interval (seconds)
    refresh_interval: int = 30
    
    # Node lookup concurrency
    lookup_concurrency: int = 3


@dataclass
class SecurityConfig:
    """P2P security configuration."""
    
    # Enable post-quantum cryptography
    post_quantum_enabled: bool = True
    
    # Post-quantum KEM algorithm
    pq_kem_algorithm: str = "Kyber768"
    
    # Post-quantum signature algorithm
    pq_sig_algorithm: str = "Dilithium3"
    
    # Require PQ-capable peers (reject others)
    pq_required: bool = True
    
    # Connection timeout (seconds)
    handshake_timeout: float = 10.0


@dataclass
class P2PConfig:
    """P2P networking configuration."""
    
    # Enable P2P networking
    enabled: bool = True
    
    # Listen address
    listen_addr: str = "0.0.0.0"
    
    # TCP port for RLPx connections
    listen_port: int = 30303
    
    # UDP port for discovery
    discovery_port: int = 30303
    
    # Maximum peers
    max_peers: int = 50
    
    # Maximum pending connections
    max_pending_peers: int = 25
    
    # Private key file path (optional, generated if not set)
    private_key_path: Optional[str] = None
    
    # Node name (for status messages)
    node_name: str = "QRDX/v3.0.0"
    
    # Chain ID
    chain_id: int = 1
    
    # Discovery configuration
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    
    # Security configuration
    security: SecurityConfig = field(default_factory=SecurityConfig)
    
    @classmethod
    def from_dict(cls, config: dict) -> "P2PConfig":
        """Create from dictionary."""
        discovery_dict = config.pop("discovery", {})
        security_dict = config.pop("security", {})
        
        return cls(
            **config,
            discovery=DiscoveryConfig(**discovery_dict),
            security=SecurityConfig(**security_dict),
        )
