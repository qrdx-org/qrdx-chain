"""
QRDX Node Identity — Post-Quantum (Dilithium3 + BLAKE3)

Implements PQ node identity per Whitepaper §5.1:
- Dilithium3 (ML-DSA-65) keypair for signing and authentication
- BLAKE3 hash of public key as Node ID, prefixed with 'qx'
- @-schema addressing: dilithium3@qx<blake3_hash>@<host>:<port>

All classical identity (P256/ECDSA, secp256k1) has been removed.
"""

import os
import json
import re
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

PQ_ALGORITHM = _resolve_sig_algorithm()  # NIST Level 3 — CRYSTALS-Dilithium / ML-DSA-65
KEY_FILE_PATH = os.path.join(os.path.dirname(__file__), 'node_key.pq')
PUBKEY_FILE_PATH = os.path.join(os.path.dirname(__file__), 'node_key.pq.pub')

# @-schema regex: dilithium3@qx<hex40>@host:port
_AT_SCHEMA_RE = re.compile(
    r'^(?P<algo>[a-zA-Z0-9-]+)@(?P<id>qx[a-fA-F0-9]{40,})@(?P<host>[^:]+):(?P<port>\d+)$'
)

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------
_secret_key: Optional[bytes] = None
_public_key: Optional[bytes] = None
_node_id: Optional[str] = None  # qx<blake3_hex_40>


# ---------------------------------------------------------------------------
# Key Management
# ---------------------------------------------------------------------------

def _derive_node_id(public_key: bytes) -> str:
    """
    Derive the node ID from a Dilithium public key.

    Returns 'qx' + first 20 bytes (40 hex chars) of BLAKE3(pubkey).
    """
    h = blake3.blake3(public_key).hexdigest()
    return f"qx{h[:40]}"


def generate_new_keypair() -> Tuple[bytes, bytes]:
    """Generate a fresh Dilithium3 keypair. Returns (secret_key, public_key)."""
    signer = oqs.Signature(PQ_ALGORITHM)
    public_key = signer.generate_keypair()
    secret_key = signer.export_secret_key()
    return secret_key, public_key


def save_keys(secret_key: bytes, public_key: bytes) -> None:
    """Persist keys to disk with restrictive permissions."""
    with open(KEY_FILE_PATH, 'wb') as f:
        f.write(secret_key)
    os.chmod(KEY_FILE_PATH, 0o600)

    with open(PUBKEY_FILE_PATH, 'wb') as f:
        f.write(public_key)
    os.chmod(PUBKEY_FILE_PATH, 0o644)

    logger.info(f"PQ node identity saved to {KEY_FILE_PATH}")


def load_keys() -> Optional[Tuple[bytes, bytes]]:
    """Load keys from disk. Returns (secret_key, public_key) or None."""
    if not os.path.exists(KEY_FILE_PATH) or not os.path.exists(PUBKEY_FILE_PATH):
        return None
    with open(KEY_FILE_PATH, 'rb') as f:
        secret_key = f.read()
    with open(PUBKEY_FILE_PATH, 'rb') as f:
        public_key = f.read()
    if not secret_key or not public_key:
        return None
    return secret_key, public_key


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

def initialize_identity() -> None:
    """
    Load or create the PQ node identity.

    Populates module globals: _secret_key, _public_key, _node_id.
    """
    global _secret_key, _public_key, _node_id

    loaded = load_keys()
    if loaded is None:
        logger.info("No PQ node key found. Generating a new Dilithium3 identity...")
        _secret_key, _public_key = generate_new_keypair()
        save_keys(_secret_key, _public_key)
    else:
        _secret_key, _public_key = loaded

    _node_id = _derive_node_id(_public_key)
    logger.info(f"PQ Node Identity Initialized. Node ID: {_node_id}")


# ---------------------------------------------------------------------------
# Accessors
# ---------------------------------------------------------------------------

def get_node_id() -> str:
    """Return the node's BLAKE3-derived ID (e.g. 'qx1a2b3c…')."""
    if _node_id is None:
        raise RuntimeError("Identity not initialized. Call initialize_identity() first.")
    return _node_id


def get_public_key_bytes() -> bytes:
    """Return raw Dilithium3 public key bytes."""
    if _public_key is None:
        raise RuntimeError("Identity not initialized.")
    return _public_key


def get_public_key_hex() -> str:
    """Return Dilithium3 public key as hex string."""
    return get_public_key_bytes().hex()


def get_secret_key_bytes() -> bytes:
    """Return raw Dilithium3 secret key bytes."""
    if _secret_key is None:
        raise RuntimeError("Identity not initialized.")
    return _secret_key


# ---------------------------------------------------------------------------
# @-Schema Addressing
# ---------------------------------------------------------------------------

def get_at_schema_address(host: str, port: int) -> str:
    """
    Build the @-schema address for this node.

    Format: dilithium3@<node_id>@<host>:<port>
    Example: dilithium3@qx1a2b3c4d5e6f7890abcdef1234567890abcdef12@node.qrdx.org:30303
    """
    return f"dilithium3@{get_node_id()}@{host}:{port}"


def parse_at_schema(address: str) -> dict:
    """
    Parse an @-schema address string.

    Returns dict with keys: algo, node_id, host, port.
    Raises ValueError on invalid format.
    """
    m = _AT_SCHEMA_RE.match(address)
    if not m:
        raise ValueError(f"Invalid @-schema address: {address!r}")
    return {
        'algo': m.group('algo'),
        'node_id': m.group('id'),
        'host': m.group('host'),
        'port': int(m.group('port')),
    }


def validate_at_schema(address: str) -> bool:
    """Return True if address is a valid @-schema string."""
    return _AT_SCHEMA_RE.match(address) is not None


# ---------------------------------------------------------------------------
# Signing & Verification
# ---------------------------------------------------------------------------

def sign_message(message: bytes) -> str:
    """
    Sign *message* with this node's Dilithium3 secret key.

    Returns the signature as a hex string.
    """
    if _secret_key is None:
        raise RuntimeError("Identity not initialized. Cannot sign.")

    signer = oqs.Signature(PQ_ALGORITHM, _secret_key)
    signature = signer.sign(message)
    return signature.hex()


def verify_signature(pubkey_hex: str, signature_hex: str, message: bytes) -> bool:
    """
    Verify a Dilithium3 signature.

    Args:
        pubkey_hex: Signer's Dilithium public key (hex).
        signature_hex: Signature (hex).
        message: Original message bytes.

    Returns True iff valid.
    """
    try:
        pub = bytes.fromhex(pubkey_hex)
        sig = bytes.fromhex(signature_hex)
        verifier = oqs.Signature(PQ_ALGORITHM)
        return verifier.verify(message, sig, pub)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------

def get_canonical_json_bytes(data: dict) -> bytes:
    """Deterministic JSON serialization for signing payloads."""
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
