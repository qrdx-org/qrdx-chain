"""
QRDX Crypto Module

This module provides cryptographic primitives for the QRDX blockchain:
- secp256k1 keys (Web3 standard for transactions)
- Post-quantum cryptography (Dilithium for PQ wallets)
- Hash functions (keccak256, sha256)
- RLP encoding
- Address derivation for both wallet types
"""

from .keys import PrivateKey, PublicKey, generate_keypair, Signature
from .signing import (
    sign_transaction,
    sign_message,
    recover_public_key,
    verify_signature,
    sign_message_hash,
)
from .hashing import keccak256, sha256, keccak256_hex, sha256_hex
from .address import (
    public_key_to_address,
    is_valid_address,
    to_checksum_address,
    to_pq_checksum_address,
    normalize_address,
    is_checksum_address,
    is_pq_address,
    is_traditional_address,
    get_address_type,
    AddressType,
)
from .encoding import rlp_encode, rlp_decode, encode_transaction

# Post-quantum cryptography - lazy loaded
# Import directly from qrdx.crypto.pq when needed
def __getattr__(name):
    """Lazy loading for PQ crypto to avoid liboqs dependency issues."""
    pq_names = {
        'PQPrivateKey', 'PQPublicKey', 'PQSignature',
        'pq_generate_keypair', 'pq_sign', 'pq_verify'
    }
    if name in pq_names:
        from . import pq
        if name == 'pq_generate_keypair':
            return pq.generate_keypair
        elif name == 'pq_sign':
            return pq.sign
        elif name == 'pq_verify':
            return pq.verify
        return getattr(pq, name)
    raise AttributeError(f"module 'qrdx.crypto' has no attribute {name!r}")

__all__ = [
    # Traditional Keys (secp256k1)
    "PrivateKey",
    "PublicKey",
    "Signature",
    "generate_keypair",
    # Post-Quantum Keys (Dilithium3)
    "PQPrivateKey",
    "PQPublicKey",
    "PQSignature",
    "pq_generate_keypair",
    "pq_sign",
    "pq_verify",
    # Signing
    "sign_transaction",
    "sign_message",
    "sign_message_hash",
    "recover_public_key",
    "verify_signature",
    # Hashing
    "keccak256",
    "sha256",
    "keccak256_hex",
    "sha256_hex",
    # Address
    "public_key_to_address",
    "is_valid_address",
    "is_checksum_address",
    "to_checksum_address",
    "to_pq_checksum_address",
    "normalize_address",
    "is_pq_address",
    "is_traditional_address",
    "get_address_type",
    "AddressType",
    # Encoding
    "rlp_encode",
    "rlp_decode",
    "encode_transaction",
]

