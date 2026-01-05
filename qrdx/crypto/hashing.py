"""
QRDX Crypto Hashing Module

Provides hash functions used throughout the blockchain:
- keccak256: Web3 standard for addresses and transaction hashes
- sha256: Used for block hashes (chain continuity)
"""

import hashlib
from typing import Union

# Try to use pycryptodome's keccak for speed, fall back to pysha3
try:
    from Crypto.Hash import keccak as _keccak
    
    def keccak256(data: Union[bytes, str]) -> bytes:
        """
        Compute Keccak-256 hash (Ethereum standard).
        
        Args:
            data: Input bytes or hex string
            
        Returns:
            32-byte hash
        """
        if isinstance(data, str):
            if data.startswith('0x') or data.startswith('0X'):
                data = bytes.fromhex(data[2:])
            else:
                data = bytes.fromhex(data)
        
        k = _keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()

except ImportError:
    try:
        import sha3
        
        def keccak256(data: Union[bytes, str]) -> bytes:
            """
            Compute Keccak-256 hash (Ethereum standard).
            
            Args:
                data: Input bytes or hex string
                
            Returns:
                32-byte hash
            """
            if isinstance(data, str):
                if data.startswith('0x') or data.startswith('0X'):
                    data = bytes.fromhex(data[2:])
                else:
                    data = bytes.fromhex(data)
            
            return sha3.keccak_256(data).digest()
    
    except ImportError:
        # Last resort: use eth_hash
        from eth_hash.auto import keccak as _eth_keccak
        
        def keccak256(data: Union[bytes, str]) -> bytes:
            """
            Compute Keccak-256 hash (Ethereum standard).
            
            Args:
                data: Input bytes or hex string
                
            Returns:
                32-byte hash
            """
            if isinstance(data, str):
                if data.startswith('0x') or data.startswith('0X'):
                    data = bytes.fromhex(data[2:])
                else:
                    data = bytes.fromhex(data)
            
            return _eth_keccak(data)


def sha256(data: Union[bytes, str]) -> bytes:
    """
    Compute SHA-256 hash.
    
    Used for block hashes to maintain chain continuity with
    the original implementation.
    
    Args:
        data: Input bytes or hex string
        
    Returns:
        32-byte hash
    """
    if isinstance(data, str):
        if data.startswith('0x') or data.startswith('0X'):
            data = bytes.fromhex(data[2:])
        else:
            # Assume hex string
            try:
                data = bytes.fromhex(data)
            except ValueError:
                # Plain text string
                data = data.encode('utf-8')
    
    return hashlib.sha256(data).digest()


def keccak256_hex(data: Union[bytes, str]) -> str:
    """
    Compute Keccak-256 hash and return as hex string.
    
    Args:
        data: Input bytes or hex string
        
    Returns:
        Hex string with 0x prefix
    """
    return '0x' + keccak256(data).hex()


def sha256_hex(data: Union[bytes, str]) -> str:
    """
    Compute SHA-256 hash and return as hex string.
    
    Args:
        data: Input bytes or hex string
        
    Returns:
        Hex string with 0x prefix
    """
    return '0x' + sha256(data).hex()


def double_sha256(data: Union[bytes, str]) -> bytes:
    """
    Compute double SHA-256 hash (SHA-256(SHA-256(data))).
    
    Used in Bitcoin-style protocols.
    
    Args:
        data: Input bytes or hex string
        
    Returns:
        32-byte hash
    """
    return sha256(sha256(data))
