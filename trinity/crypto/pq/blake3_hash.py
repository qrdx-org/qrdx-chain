"""
BLAKE3 Cryptographic Hash Function

BLAKE3 is a quantum-resistant cryptographic hash function that provides:
- Arbitrary output length (XOF - extendable output function)
- Parallelizable (fast on modern hardware)
- Secure against quantum attacks (Grover's algorithm only reduces to 256-bit → 128-bit)

For quantum resistance, we use 512-bit (64-byte) outputs by default.
"""

from typing import List, Optional
import blake3

from trinity.crypto.pq.constants import (
    BLAKE3_DEFAULT_DIGEST_SIZE,
    BLAKE3_MIN_DIGEST_SIZE,
)


def blake3_hash(data: bytes, digest_size: int = BLAKE3_DEFAULT_DIGEST_SIZE) -> bytes:
    """
    Hash data using BLAKE3 with specified output size.
    
    Args:
        data: Input data to hash
        digest_size: Output size in bytes (default: 64 bytes = 512 bits for quantum resistance)
    
    Returns:
        Hash digest of specified length
    
    Example:
        >>> digest = blake3_hash(b"hello world")
        >>> len(digest)
        64
    """
    if digest_size < BLAKE3_MIN_DIGEST_SIZE:
        raise ValueError(f"Digest size must be at least {BLAKE3_MIN_DIGEST_SIZE} bytes")
    
    hasher = blake3.blake3()
    hasher.update(data)
    return hasher.digest(length=digest_size)


def blake3_merkle_root(hashes: List[bytes]) -> bytes:
    """
    Compute Merkle root using BLAKE3.
    
    Builds a binary Merkle tree from leaf hashes.
    Empty list returns hash of empty bytes.
    
    Args:
        hashes: List of leaf hashes (should all be same length)
    
    Returns:
        32-byte Merkle root hash
    
    Example:
        >>> leaves = [blake3_hash(b"tx1"), blake3_hash(b"tx2")]
        >>> root = blake3_merkle_root(leaves)
    """
    if not hashes:
        return blake3_hash(b'', digest_size=32)
    
    if len(hashes) == 1:
        return hashes[0][:32]  # Ensure 32-byte output
    
    # Build tree bottom-up
    current_level = list(hashes)
    
    while len(current_level) > 1:
        next_level = []
        
        # Process pairs
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                # Hash pair
                combined = current_level[i] + current_level[i + 1]
                parent_hash = blake3_hash(combined, digest_size=32)
            else:
                # Odd node - promote to next level
                parent_hash = current_level[i][:32]
            
            next_level.append(parent_hash)
        
        current_level = next_level
    
    return current_level[0]


def blake3_kdf(
    key_material: bytes,
    context: str,
    output_len: int = 32
) -> bytes:
    """
    BLAKE3 Key Derivation Function.
    
    Derives a key from input key material using a context string.
    Uses BLAKE3's keyed hashing mode for domain separation.
    
    Args:
        key_material: Input key material (can be shared secret, password, etc.)
        context: Context string for domain separation (e.g., "devp2p-handshake")
        output_len: Output key length in bytes (default: 32)
    
    Returns:
        Derived key of specified length
    
    Example:
        >>> shared_secret = b"..." # from Kyber
        >>> aes_key = blake3_kdf(shared_secret, "aes-encryption", 32)
        >>> mac_key = blake3_kdf(shared_secret, "mac-authentication", 32)
    """
    # Use BLAKE3 derive_key mode with context
    hasher = blake3.blake3(derive_key_context=context)
    hasher.update(key_material)
    return hasher.digest(length=output_len)


def blake3_incremental() -> blake3.blake3:
    """
    Create an incremental BLAKE3 hasher.
    
    Useful for hashing large data streams without loading everything into memory.
    
    Returns:
        BLAKE3 hasher object that can be updated incrementally
    
    Example:
        >>> hasher = blake3_incremental()
        >>> hasher.update(b"chunk1")
        >>> hasher.update(b"chunk2")
        >>> digest = hasher.digest(length=64)
    """
    return blake3.blake3()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte strings (must be same length).
    
    Used for combining secrets in hybrid cryptography.
    
    Args:
        a: First byte string
        b: Second byte string (must be same length as a)
    
    Returns:
        XOR of a and b
    
    Raises:
        ValueError: If lengths don't match
    """
    if len(a) != len(b):
        raise ValueError(f"Cannot XOR byte strings of different lengths: {len(a)} != {len(b)}")
    
    return bytes(x ^ y for x, y in zip(a, b))
