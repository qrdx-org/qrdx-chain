"""
QRDX Post-Quantum Cryptography Module

Provides post-quantum cryptographic primitives:
- Dilithium3: Digital signatures (NIST PQC standard)
- Kyber768: Key encapsulation mechanism (for future node communication)
"""

from .dilithium import (
    PQPrivateKey,
    PQPublicKey,
    PQSignature,
    generate_keypair,
    sign,
    verify,
    is_available,
    get_liboqs_error,
    get_algorithm_info,
)

__all__ = [
    'PQPrivateKey',
    'PQPublicKey',
    'PQSignature',
    'generate_keypair',
    'sign',
    'verify',
    'is_available',
    'get_liboqs_error',
    'get_algorithm_info',
]
