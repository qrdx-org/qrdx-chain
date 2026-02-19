"""
QRDX P2P Node Identity (Post-Quantum)

Implements node identity and addressing for the P2P layer using:
- Dilithium3 (ML-DSA-65) keypairs for identity/authentication
- BLAKE3 hash of public key as Node ID (prefixed 'qx')
- @-schema addressing: dilithium3@qx<blake3_hash>@<host>:<port>
- Kademlia XOR distance using 160-bit BLAKE3-derived node IDs

All classical identity (secp256k1, keccak256, qnode://, enode://) has been removed.
"""

import os
import re
from dataclasses import dataclass
from typing import Optional, Tuple

import blake3
import oqs

from ..logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Resolve algorithm name at import time (ML-DSA-65 preferred, Dilithium3 legacy)
def _resolve_sig_algorithm() -> str:
    for name in ('ML-DSA-65', 'Dilithium3'):
        try:
            oqs.Signature(name)
            return name
        except Exception:
            continue
    raise RuntimeError('No supported PQ signature algorithm found in liboqs')

PQ_SIG_ALGORITHM = _resolve_sig_algorithm()
NODE_ID_HEX_LEN = 40          # 20 bytes = 160 bits, expressed as 40 hex chars
NODE_ID_PREFIX = 'qx'
NODE_ID_FULL_LEN = len(NODE_ID_PREFIX) + NODE_ID_HEX_LEN  # 42

# @-schema regex
_AT_SCHEMA_RE = re.compile(
    r'^(?P<algo>[a-zA-Z0-9-]+)@(?P<id>qx[a-fA-F0-9]{40,})@(?P<host>[^:]+):(?P<port>\d+)$'
)

# Type alias for 20-byte node ID
NodeID = bytes  # 20 bytes


# ---------------------------------------------------------------------------
# Address
# ---------------------------------------------------------------------------

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
        return (self.ip, self.tcp_port)

    @property
    def udp_endpoint(self) -> Tuple[str, int]:
        return (self.ip, self.udp_port)

    def __str__(self) -> str:
        if self.tcp_port == self.udp_port:
            return f"{self.ip}:{self.tcp_port}"
        return f"{self.ip}:{self.tcp_port}/udp:{self.udp_port}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def derive_node_id(public_key: bytes) -> NodeID:
    """
    Derive the 20-byte Kademlia node ID from a Dilithium public key.

    Algorithm: first 20 bytes of BLAKE3(pubkey).
    """
    h = blake3.blake3(public_key).digest()
    return h[:20]


def derive_node_id_hex(public_key: bytes) -> str:
    """
    Derive the 'qx'-prefixed hex node ID from a Dilithium public key.

    Returns 'qx' + first 40 hex chars of BLAKE3(pubkey).
    """
    return NODE_ID_PREFIX + blake3.blake3(public_key).hexdigest()[:NODE_ID_HEX_LEN]


def node_id_to_hex(node_id: NodeID) -> str:
    """Convert 20-byte node ID to 'qx'-prefixed hex string."""
    return NODE_ID_PREFIX + node_id.hex()


def hex_to_node_id(hex_str: str) -> NodeID:
    """Convert 'qx'-prefixed or plain hex string to 20-byte node ID."""
    if hex_str.startswith(NODE_ID_PREFIX):
        hex_str = hex_str[len(NODE_ID_PREFIX):]
    if hex_str.startswith('0x'):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------

class Node:
    """
    Represents a node in the QRDX P2P network.

    Each node has:
    - A Dilithium3 public key for identity and authentication
    - A 160-bit BLAKE3-derived node ID for Kademlia routing
    - An @-schema address for peer discovery
    - Network address information (host, port)
    """

    def __init__(
        self,
        public_key: bytes,
        address: Optional[Address] = None,
        *,
        secret_key: Optional[bytes] = None,
    ):
        """
        Initialize a node.

        Args:
            public_key: Dilithium3 public key bytes.
            address: Network address (None for local-only nodes).
            secret_key: Dilithium3 secret key (only for local node).
        """
        self._public_key = public_key
        self._secret_key = secret_key
        self._address = address

        # Compute Kademlia node ID — first 20 bytes of BLAKE3(pubkey)
        self._node_id: NodeID = derive_node_id(public_key)
        self._node_id_hex: str = derive_node_id_hex(public_key)

    # -- Constructors -------------------------------------------------------

    @classmethod
    def from_at_schema(cls, address: str) -> 'Node':
        """
        Parse a node from an @-schema address string.

        Format: dilithium3@qx<blake3_40hex>@<host>:<port>

        Returns a Node **without** a secret key (remote peer).
        """
        m = _AT_SCHEMA_RE.match(address)
        if not m:
            raise ValueError(f"Invalid @-schema address: {address!r}")

        algo = m.group('algo')
        # Accept both legacy 'dilithium3' and FIPS 'ml-dsa-65' names
        accepted = {PQ_SIG_ALGORITHM.lower(), 'dilithium3', 'ml-dsa-65'}
        if algo.lower() not in accepted:
            raise ValueError(f"Unsupported algorithm in @-schema: {algo}")

        node_id_hex = m.group('id')
        host = m.group('host')
        port = int(m.group('port'))

        # We don't have the public key from the @-schema alone —
        # store the node ID and address. Public key is obtained during handshake.
        node = cls.__new__(cls)
        node._public_key = None  # Unknown until handshake
        node._secret_key = None
        node._address = Address(ip=host, tcp_port=port)
        node._node_id = hex_to_node_id(node_id_hex)
        node._node_id_hex = node_id_hex
        return node

    @classmethod
    def from_http_url(cls, url: str) -> 'Node':
        """
        Create a placeholder node from an HTTP(S) URL.

        Used for legacy/bootstrap compatibility. The node will have no
        public key or node ID until a handshake completes.
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.hostname or 'localhost'
        port = parsed.port or 30303

        node = cls.__new__(cls)
        node._public_key = None
        node._secret_key = None
        node._address = Address(ip=host, tcp_port=port)
        node._node_id = b'\x00' * 20  # Placeholder — resolved after handshake
        node._node_id_hex = NODE_ID_PREFIX + '0' * NODE_ID_HEX_LEN
        return node

    @classmethod
    def generate(cls, address: Optional[Address] = None) -> 'Node':
        """Generate a new node with a fresh Dilithium3 keypair."""
        signer = oqs.Signature(PQ_SIG_ALGORITHM)
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
        return cls(public_key=public_key, address=address, secret_key=secret_key)

    @classmethod
    def load_or_generate(cls, key_path: str, address: Optional[Address] = None) -> 'Node':
        """
        Load node from key files on disk, or generate new.

        Stores: <key_path> (secret key) and <key_path>.pub (public key).
        """
        pub_path = key_path + '.pub'
        if os.path.exists(key_path) and os.path.exists(pub_path):
            with open(key_path, 'rb') as f:
                secret_key = f.read()
            with open(pub_path, 'rb') as f:
                public_key = f.read()
            return cls(public_key=public_key, address=address, secret_key=secret_key)

        node = cls.generate(address=address)

        os.makedirs(os.path.dirname(key_path) or '.', exist_ok=True)
        with open(key_path, 'wb') as f:
            f.write(node._secret_key)
        os.chmod(key_path, 0o600)
        with open(pub_path, 'wb') as f:
            f.write(node._public_key)
        os.chmod(pub_path, 0o644)

        logger.info(f"Generated new PQ node identity at {key_path}")
        return node

    # -- Properties ---------------------------------------------------------

    @property
    def node_id(self) -> NodeID:
        """20-byte Kademlia node ID."""
        return self._node_id

    @property
    def node_id_hex(self) -> str:
        """'qx'-prefixed hex node ID (42 chars)."""
        return self._node_id_hex

    @property
    def public_key(self) -> Optional[bytes]:
        """Dilithium3 public key bytes (None for unresolved peers)."""
        return self._public_key

    @property
    def public_key_hex(self) -> Optional[str]:
        """Dilithium3 public key hex string."""
        return self._public_key.hex() if self._public_key else None

    @property
    def secret_key(self) -> Optional[bytes]:
        """Dilithium3 secret key (only for the local node)."""
        return self._secret_key

    @property
    def has_secret_key(self) -> bool:
        """True if this is the local node with signing capability."""
        return self._secret_key is not None

    @property
    def address(self) -> Optional[Address]:
        return self._address

    @address.setter
    def address(self, value: Address):
        self._address = value

    @property
    def is_resolved(self) -> bool:
        """True if the public key is known (handshake completed)."""
        return self._public_key is not None

    # -- @-Schema -----------------------------------------------------------

    def to_at_schema(self) -> str:
        """
        Convert to @-schema address string.

        Format: dilithium3@qx<blake3_hex>@<host>:<port>
        """
        if self._address is None:
            raise ValueError("Cannot create @-schema URI without address")
        return (
            f"{PQ_SIG_ALGORITHM.lower()}@{self._node_id_hex}"
            f"@{self._address.ip}:{self._address.tcp_port}"
        )

    def to_http_url(self) -> str:
        """
        Convert to an HTTP base URL for API requests.

        Returns: http://<host>:<port>
        """
        if self._address is None:
            raise ValueError("Cannot create URL without address")
        return f"http://{self._address.ip}:{self._address.tcp_port}"

    # -- Identity operations ------------------------------------------------

    def resolve(self, public_key: bytes) -> None:
        """
        Resolve this node's identity after a successful handshake.

        Sets the public key and recomputes the Kademlia node ID.
        """
        self._public_key = public_key
        self._node_id = derive_node_id(public_key)
        self._node_id_hex = derive_node_id_hex(public_key)

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message with this node's Dilithium3 secret key.

        Returns raw signature bytes.
        Raises RuntimeError if this node has no secret key.
        """
        if self._secret_key is None:
            raise RuntimeError("Cannot sign: no secret key (remote node)")

        signer = oqs.Signature(PQ_SIG_ALGORITHM, self._secret_key)
        return signer.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a Dilithium3 signature against this node's public key.

        Returns True if valid.
        """
        if self._public_key is None:
            raise RuntimeError("Cannot verify: public key unknown (unresolved node)")

        verifier = oqs.Signature(PQ_SIG_ALGORITHM)
        return verifier.verify(message, signature, self._public_key)

    # -- Kademlia XOR distance ---------------------------------------------

    def distance(self, other: 'Node') -> int:
        """XOR distance to another node (for Kademlia routing)."""
        return int.from_bytes(self._node_id, 'big') ^ int.from_bytes(other._node_id, 'big')

    def distance_to(self, node_id: NodeID) -> int:
        """XOR distance to a raw node ID."""
        return int.from_bytes(self._node_id, 'big') ^ int.from_bytes(node_id, 'big')

    def log_distance(self, other: 'Node') -> int:
        """
        Log2 distance (Kademlia bucket index) to another node.

        Returns 0-159 for 160-bit node IDs.
        """
        d = self.distance(other)
        if d == 0:
            return 0
        return d.bit_length() - 1

    # -- Dunder -------------------------------------------------------------

    def __eq__(self, other) -> bool:
        if not isinstance(other, Node):
            return False
        return self._node_id == other._node_id

    def __hash__(self) -> int:
        return hash(self._node_id)

    def __repr__(self) -> str:
        addr = f"@{self._address}" if self._address else ""
        resolved = "" if self.is_resolved else " [unresolved]"
        return f"Node({self._node_id_hex[:16]}...{addr}{resolved})"
