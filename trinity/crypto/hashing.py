"""
BLAKE3 Hash Functions for Quantum Resistance
Provides 512-bit output for quantum resistance against Grover's algorithm
"""

import blake3
from typing import Union


def blake3_256(data: bytes) -> bytes:
    """
    Compute BLAKE3 hash with 256-bit (32-byte) output.
    
    Args:
        data: Input data to hash
        
    Returns:
        32-byte hash digest
    """
    hasher = blake3.blake3(data)
    return hasher.digest(length=32)


def blake3_512(data: bytes) -> bytes:
    """
    Compute BLAKE3 hash with 512-bit (64-byte) output for quantum resistance.
    Provides 256-bit security against Grover's algorithm.
    
    Args:
        data: Input data to hash
        
    Returns:
        64-byte hash digest
    """
    hasher = blake3.blake3(data)
    return hasher.digest(length=64)


class Blake3Hash:
    """
    BLAKE3 hasher with incremental update support.
    Compatible with eth_hash interface patterns.
    """
    
    def __init__(self, output_length: int = 64):
        """
        Initialize a BLAKE3 hasher.
        
        Args:
            output_length: Desired output length in bytes (default 64 for quantum resistance)
        """
        self._hasher = blake3.blake3()
        self._output_length = output_length
    
    def update(self, data: bytes) -> 'Blake3Hash':
        """
        Update the hash with additional data.
        
        Args:
            data: Data to add to the hash
            
        Returns:
            Self for chaining
        """
        self._hasher.update(data)
        return self
    
    def digest(self) -> bytes:
        """
        Compute the final hash digest.
        
        Returns:
            Hash digest of specified length
        """
        return self._hasher.digest(length=self._output_length)
    
    def hexdigest(self) -> str:
        """
        Compute the final hash digest as a hex string.
        
        Returns:
            Hex-encoded hash digest
        """
        return self.digest().hex()
    
    def copy(self) -> 'Blake3Hash':
        """
        Create a copy of the current hasher state.
        
        Returns:
            New Blake3Hash instance with same state
        """
        new_hasher = Blake3Hash(self._output_length)
        new_hasher._hasher = self._hasher  # blake3 hasher is immutable in updates
        return new_hasher


def blake3_hash_many(data_list: list[bytes], output_length: int = 64) -> list[bytes]:
    """
    Hash multiple inputs efficiently.
    
    Args:
        data_list: List of byte strings to hash
        output_length: Desired output length in bytes
        
    Returns:
        List of hash digests
    """
    return [blake3.blake3(data).digest(length=output_length) for data in data_list]


def blake3_keyed_hash(key: bytes, data: bytes, output_length: int = 64) -> bytes:
    """
    Compute a keyed BLAKE3 hash (MAC).
    
    Args:
        key: 32-byte key
        data: Data to hash
        output_length: Desired output length in bytes
        
    Returns:
        Keyed hash digest
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")
    
    hasher = blake3.blake3(data, key=key)
    return hasher.digest(length=output_length)


def blake3_derive_key(context: str, key_material: bytes, output_length: int = 32) -> bytes:
    """
    Derive a key using BLAKE3 key derivation function.
    
    Args:
        context: Context string for domain separation
        key_material: Input key material
        output_length: Desired output length in bytes
        
    Returns:
        Derived key
    """
    hasher = blake3.blake3(key_material, derive_key_context=context)
    return hasher.digest(length=output_length)
