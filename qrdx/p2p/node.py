"""
QRDX P2P Node Identity

Implements node identity using secp256k1 keys and optional
post-quantum keys for enhanced security.
"""

import os
import hashlib
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode

from ..crypto.keys import PrivateKey, PublicKey, generate_keypair
from ..crypto.hashing import keccak256


# Type alias for 32-byte node ID
NodeID = bytes


@dataclass
class Address:
    """Network address for a node."""
    
    ip: str
    tcp_port: int
    udp_port: Optional[int] = None
    
    def __post_init__(self):
        if self.udp_port is None:
            self.udp_port = self.tcp_port
    
    @property
    def tcp_endpoint(self) -> Tuple[str, int]:
        """Get TCP endpoint tuple."""
        return (self.ip, self.tcp_port)
    
    @property
    def udp_endpoint(self) -> Tuple[str, int]:
        """Get UDP endpoint tuple."""
        return (self.ip, self.udp_port)
    
    def __str__(self) -> str:
        if self.tcp_port == self.udp_port:
            return f"{self.ip}:{self.tcp_port}"
        return f"{self.ip}:{self.tcp_port}/udp:{self.udp_port}"


class Node:
    """
    Represents a node in the QRDX network.
    
    Each node has:
    - A secp256k1 keypair for identity and authentication
    - A unique node ID (keccak256 of public key)
    - Optional post-quantum keys for future-proof communication
    - Network address information
    """
    
    def __init__(
        self,
        private_key: Optional[PrivateKey] = None,
        address: Optional[Address] = None,
        pq_public_key: Optional[bytes] = None,
    ):
        """
        Initialize node.
        
        Args:
            private_key: Node's private key (generates new if None)
            address: Network address (None for local-only nodes)
            pq_public_key: Post-quantum public key (optional)
        """
        if private_key is None:
            private_key = PrivateKey.generate()
        
        self._private_key = private_key
        self._public_key = private_key.public_key
        self._address = address
        self._pq_public_key = pq_public_key
        
        # Compute node ID (keccak256 of uncompressed public key)
        self._node_id = keccak256(self._public_key.to_bytes())
    
    @classmethod
    def from_uri(cls, uri: str) -> "Node":
        """
        Parse node from URI.
        
        Format: qnode://<pubkey>@<host>:<port>[?pq=<pq_pubkey>][&chain=<chain_id>]
        
        Args:
            uri: Node URI string
            
        Returns:
            Node instance (without private key)
        """
        if not uri.startswith("qnode://"):
            raise ValueError(f"Invalid node URI scheme: {uri}")
        
        # Parse URI
        parsed = urlparse(uri)
        
        # Extract public key from username part
        pubkey_hex = parsed.username
        if not pubkey_hex:
            raise ValueError(f"Missing public key in URI: {uri}")
        
        # Parse host and port
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            raise ValueError(f"Missing host or port in URI: {uri}")
        
        # Parse query parameters
        params = parse_qs(parsed.query)
        pq_pubkey = None
        if "pq" in params:
            import base64
            pq_pubkey = base64.b64decode(params["pq"][0])
        
        # Create public key
        public_key = PublicKey.from_hex(pubkey_hex)
        
        # Create node without private key
        node = cls.__new__(cls)
        node._private_key = None
        node._public_key = public_key
        node._address = Address(ip=host, tcp_port=port)
        node._pq_public_key = pq_pubkey
        node._node_id = keccak256(public_key.to_bytes())
        
        return node
    
    @classmethod
    def from_enode(cls, enode: str) -> "Node":
        """
        Parse node from Ethereum enode URI.
        
        Format: enode://<pubkey>@<host>:<port>
        
        Args:
            enode: Enode URI string
            
        Returns:
            Node instance (without private key)
        """
        if not enode.startswith("enode://"):
            raise ValueError(f"Invalid enode URI: {enode}")
        
        # Convert to qnode format
        uri = "qnode://" + enode[8:]
        return cls.from_uri(uri)
    
    @classmethod
    def load_or_generate(cls, key_path: str, address: Optional[Address] = None) -> "Node":
        """
        Load node from key file or generate new.
        
        Args:
            key_path: Path to private key file
            address: Network address
            
        Returns:
            Node instance
        """
        if os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                key_bytes = f.read()
            private_key = PrivateKey(key_bytes)
        else:
            private_key = PrivateKey.generate()
            os.makedirs(os.path.dirname(key_path), exist_ok=True)
            with open(key_path, 'wb') as f:
                f.write(private_key.to_bytes())
            os.chmod(key_path, 0o600)  # Restrict permissions
        
        return cls(private_key=private_key, address=address)
    
    @property
    def node_id(self) -> NodeID:
        """Get 32-byte node ID."""
        return self._node_id
    
    @property
    def node_id_hex(self) -> str:
        """Get node ID as hex string."""
        return self._node_id.hex()
    
    @property
    def public_key(self) -> PublicKey:
        """Get node's public key."""
        return self._public_key
    
    @property
    def private_key(self) -> Optional[PrivateKey]:
        """Get node's private key (None for remote nodes)."""
        return self._private_key
    
    @property
    def address(self) -> Optional[Address]:
        """Get node's network address."""
        return self._address
    
    @address.setter
    def address(self, value: Address):
        """Set node's network address."""
        self._address = value
    
    @property
    def pq_public_key(self) -> Optional[bytes]:
        """Get post-quantum public key."""
        return self._pq_public_key
    
    @pq_public_key.setter
    def pq_public_key(self, value: bytes):
        """Set post-quantum public key."""
        self._pq_public_key = value
    
    def to_uri(self, include_pq: bool = True) -> str:
        """
        Convert to qnode URI.
        
        Args:
            include_pq: Include post-quantum key in URI
            
        Returns:
            URI string
        """
        if self._address is None:
            raise ValueError("Cannot create URI without address")
        
        pubkey_hex = self._public_key.to_hex(with_prefix=False)
        base_uri = f"qnode://{pubkey_hex}@{self._address.ip}:{self._address.tcp_port}"
        
        params = {}
        if include_pq and self._pq_public_key:
            import base64
            params["pq"] = base64.b64encode(self._pq_public_key).decode()
        
        if params:
            return base_uri + "?" + urlencode(params)
        return base_uri
    
    def to_enode(self) -> str:
        """
        Convert to Ethereum enode URI.
        
        Returns:
            Enode URI string
        """
        if self._address is None:
            raise ValueError("Cannot create enode without address")
        
        pubkey_hex = self._public_key.to_hex(with_prefix=False)
        return f"enode://{pubkey_hex}@{self._address.ip}:{self._address.tcp_port}"
    
    def distance(self, other: "Node") -> int:
        """
        Calculate XOR distance to another node.
        
        Used for Kademlia routing.
        
        Args:
            other: Other node
            
        Returns:
            Distance as integer
        """
        return int.from_bytes(self._node_id, 'big') ^ int.from_bytes(other._node_id, 'big')
    
    def distance_to(self, node_id: NodeID) -> int:
        """
        Calculate XOR distance to a node ID.
        
        Args:
            node_id: Target node ID bytes
            
        Returns:
            Distance as integer
        """
        return int.from_bytes(self._node_id, 'big') ^ int.from_bytes(node_id, 'big')
    
    def log_distance(self, other: "Node") -> int:
        """
        Calculate log2 distance (bucket index) to another node.
        
        Args:
            other: Other node
            
        Returns:
            Bucket index (0-255)
        """
        distance = self.distance(other)
        if distance == 0:
            return 0
        return distance.bit_length() - 1
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, Node):
            return False
        return self._node_id == other._node_id
    
    def __hash__(self) -> int:
        return hash(self._node_id)
    
    def __repr__(self) -> str:
        addr = f"@{self._address}" if self._address else ""
        return f"Node({self.node_id_hex[:16]}...{addr})"


def node_id_to_hex(node_id: NodeID) -> str:
    """Convert node ID bytes to hex string."""
    return node_id.hex()


def hex_to_node_id(hex_str: str) -> NodeID:
    """Convert hex string to node ID bytes."""
    if hex_str.startswith('0x'):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)
