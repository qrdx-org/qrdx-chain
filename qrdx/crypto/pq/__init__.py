"""
QRDX Post-Quantum Cryptography Module

Provides post-quantum cryptographic primitives:
- ML-DSA-65 (Dilithium3): Digital signatures (FIPS 204)
- ML-KEM-768 (Kyber768): Key encapsulation mechanism (FIPS 203)

Both primitives REQUIRE liboqs-python. There is NO fallback mode.
"""

# Dilithium signatures (ML-DSA-65)
from .dilithium import (
    PQCryptoError,
    PQPrivateKey,
    PQPublicKey,
    PQSignature,
    PQSignatureError,
    generate_keypair,
    get_algorithm_info,
    get_liboqs_error,
    is_available,
    sign,
    verify,
)

# Kyber KEM (ML-KEM-768)
from .kyber import (
    KEMError,
    KEMPrivateKey,
    KEMPublicKey,
    get_algorithm_info as kem_get_algorithm_info,
    is_available as kem_is_available,
    kyber_decapsulate,
    kyber_encapsulate,
    kyber_generate_keypair,
)

__all__ = [
    # Dilithium signatures
    "PQPrivateKey",
    "PQPublicKey",
    "PQSignature",
    "PQCryptoError",
    "PQSignatureError",
    "generate_keypair",
    "sign",
    "verify",
    "is_available",
    "get_liboqs_error",
    "get_algorithm_info",
    # Kyber KEM
    "KEMPrivateKey",
    "KEMPublicKey",
    "KEMError",
    "kyber_generate_keypair",
    "kyber_encapsulate",
    "kyber_decapsulate",
    "kem_is_available",
    "kem_get_algorithm_info",
]
