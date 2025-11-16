"""
Post-Quantum Cryptography Module for QRDX Chain

This module provides quantum-resistant cryptographic primitives:
- CRYSTALS-Dilithium (FIPS 204) for digital signatures
- CRYSTALS-Kyber (FIPS 203) for key encapsulation
- BLAKE3 for quantum-resistant hashing

All algorithms are NIST-standardized and provide >256-bit quantum security.
"""

from trinity.crypto.pq.dilithium import (  # noqa: F401
    DilithiumPrivateKey,
    DilithiumPublicKey,
    DILITHIUM_VARIANT,
    DILITHIUM_PUBKEY_SIZE,
    DILITHIUM_PRIVKEY_SIZE,
    DILITHIUM_SIGNATURE_SIZE,
)

from trinity.crypto.pq.kyber import (  # noqa: F401
    KyberPrivateKey,
    KyberPublicKey,
    KYBER_VARIANT,
    KYBER_PUBKEY_SIZE,
    KYBER_PRIVKEY_SIZE,
    KYBER_CIPHERTEXT_SIZE,
    KYBER_SHARED_SECRET_SIZE,
)

from trinity.crypto.pq.blake3_hash import (  # noqa: F401
    blake3_hash,
    blake3_merkle_root,
    blake3_kdf,
)

from trinity.crypto.pq.keys import (  # noqa: F401
    HybridPrivateKey,
    HybridPublicKey,
    HybridSignature,
)

from trinity.crypto.pq.addresses import (  # noqa: F401
    generate_pq_address,
    validate_pq_address,
    encode_pq_address,
    decode_pq_address,
)

__all__ = [
    # Dilithium
    'DilithiumPrivateKey',
    'DilithiumPublicKey',
    'DILITHIUM_VARIANT',
    'DILITHIUM_PUBKEY_SIZE',
    'DILITHIUM_PRIVKEY_SIZE',
    'DILITHIUM_SIGNATURE_SIZE',
    # Kyber
    'KyberPrivateKey',
    'KyberPublicKey',
    'KYBER_VARIANT',
    'KYBER_PUBKEY_SIZE',
    'KYBER_PRIVKEY_SIZE',
    'KYBER_CIPHERTEXT_SIZE',
    'KYBER_SHARED_SECRET_SIZE',
    # BLAKE3
    'blake3_hash',
    'blake3_merkle_root',
    'blake3_kdf',
    # Hybrid keys
    'HybridPrivateKey',
    'HybridPublicKey',
    'HybridSignature',
    # Addresses
    'generate_pq_address',
    'validate_pq_address',
    'encode_pq_address',
    'decode_pq_address',
]
