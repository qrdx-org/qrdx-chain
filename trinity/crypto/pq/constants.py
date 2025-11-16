"""
Post-Quantum Cryptography Constants

NIST security levels and algorithm parameters for quantum-resistant cryptography.
"""

# Security Levels (NIST)
# Level 1: Equivalent to AES-128 (128-bit classical, 64-bit quantum)
# Level 2: Equivalent to SHA-256/SHA3-256 (256-bit classical, 128-bit quantum)
# Level 3: Equivalent to AES-192 (192-bit classical, 96-bit quantum)
# Level 5: Equivalent to AES-256 (256-bit classical, 128-bit quantum)

# CRYSTALS-Dilithium Algorithm Variants (now ML-DSA in FIPS 204)
DILITHIUM2_VARIANT = "ML-DSA-44"   # NIST Level 2 (was Dilithium2)
DILITHIUM3_VARIANT = "ML-DSA-65"   # NIST Level 3 (was Dilithium3)
DILITHIUM5_VARIANT = "ML-DSA-87"   # NIST Level 5 (was Dilithium5)

# Default variant for QRDX Chain (Level 5 = 256-bit security)
DEFAULT_DILITHIUM_VARIANT = DILITHIUM5_VARIANT

# Dilithium5/ML-DSA-87 Key Sizes (NIST Level 5)
DILITHIUM5_PUBKEY_SIZE = 2592      # bytes
DILITHIUM5_PRIVKEY_SIZE = 4896     # bytes (updated for ML-DSA)
DILITHIUM5_SIGNATURE_SIZE = 4627   # bytes (updated for ML-DSA)

# Dilithium3 Key Sizes (NIST Level 3) - Alternative
DILITHIUM3_PUBKEY_SIZE = 1952
DILITHIUM3_PRIVKEY_SIZE = 4000
DILITHIUM3_SIGNATURE_SIZE = 3293

# Dilithium2 Key Sizes (NIST Level 2) - Alternative
DILITHIUM2_PUBKEY_SIZE = 1312
DILITHIUM2_PRIVKEY_SIZE = 2528
DILITHIUM2_SIGNATURE_SIZE = 2420

# CRYSTALS-Kyber Algorithm Variants (now ML-KEM in FIPS 203)
KYBER512_VARIANT = "ML-KEM-512"    # NIST Level 1 (was Kyber512)
KYBER768_VARIANT = "ML-KEM-768"    # NIST Level 3 (was Kyber768)
KYBER1024_VARIANT = "ML-KEM-1024"  # NIST Level 5 (was Kyber1024)

# Default variant for QRDX Chain (Level 5)
DEFAULT_KYBER_VARIANT = KYBER1024_VARIANT

# Kyber1024 Sizes (NIST Level 5)
KYBER1024_PUBKEY_SIZE = 1568
KYBER1024_PRIVKEY_SIZE = 3168
KYBER1024_CIPHERTEXT_SIZE = 1568
KYBER1024_SHARED_SECRET_SIZE = 32

# Kyber768 Sizes (NIST Level 3) - Alternative
KYBER768_PUBKEY_SIZE = 1184
KYBER768_PRIVKEY_SIZE = 2400
KYBER768_CIPHERTEXT_SIZE = 1088
KYBER768_SHARED_SECRET_SIZE = 32

# Kyber512 Sizes (NIST Level 1) - Alternative
KYBER512_PUBKEY_SIZE = 800
KYBER512_PRIVKEY_SIZE = 1632
KYBER512_CIPHERTEXT_SIZE = 768
KYBER512_SHARED_SECRET_SIZE = 32

# BLAKE3 Parameters
BLAKE3_DEFAULT_DIGEST_SIZE = 64    # 512 bits for quantum resistance
BLAKE3_MIN_DIGEST_SIZE = 32        # 256 bits minimum
BLAKE3_MAX_DIGEST_SIZE = 2**64 - 1 # Arbitrary output length

# Address Formats
CLASSICAL_ADDRESS_SIZE = 20  # bytes (Ethereum-style)
PQ_ADDRESS_SIZE = 32        # bytes (quantum-resistant)

# Bech32m encoding for PQ addresses
BECH32M_HRP = "qrdx"  # Human-readable part for QRDX Chain addresses
BECH32M_ENCODING = "bech32m"  # Use bech32m (not bech32) per BIP-350

# Transaction Type IDs (EIP-2718)
TX_TYPE_LEGACY = 0          # Legacy (pre-EIP-155)
TX_TYPE_EIP2930 = 1        # EIP-2930 (access list)
TX_TYPE_EIP1559 = 2        # EIP-1559 (dynamic fee)
TX_TYPE_PQ = 4             # Pure post-quantum transaction
TX_TYPE_HYBRID = 5         # Hybrid (ECDSA + Dilithium) transaction

# Gas Costs (EIP proposals needed for optimized PQ costs)
GAS_COST_DILITHIUM_VERIFY = 500_000   # High cost for PQ signature verification
GAS_COST_KYBER_ENCAPSULATE = 100_000  # Kyber encapsulation
GAS_COST_KYBER_DECAPSULATE = 100_000  # Kyber decapsulation
GAS_COST_BLAKE3_BASE = 60             # Base cost for BLAKE3
GAS_COST_BLAKE3_PER_WORD = 12         # Per 32-byte word

# Precompiled Contract Addresses
PRECOMPILE_DILITHIUM_VERIFY = bytes.fromhex('000000000000000000000000000000000000000a')
PRECOMPILE_KYBER_KEM = bytes.fromhex('000000000000000000000000000000000000000b')
PRECOMPILE_BLAKE3_HASH = bytes.fromhex('000000000000000000000000000000000000000c')

# Address Registry Contract
ADDRESS_REGISTRY_ADDRESS = bytes.fromhex('0000000000000000000000000000000000000100')

# Validator Registry Contract
VALIDATOR_REGISTRY_ADDRESS = bytes.fromhex('0000000000000000000000000000000000000101')
