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


# ---------------------------------------------------------------------------
# BLAKE3 — quantum-resistant state hashing (Whitepaper §3.6)
# ---------------------------------------------------------------------------
# The whitepaper specifies the State Root Hash as BLAKE3 with a 256-bit core
# output extended to 512-bit for quantum (Grover) resistance. BLAKE3 is an XOF,
# so the output length is a parameter.

# Bytes produced for a consensus state root (512-bit per Whitepaper §3.6).
STATE_ROOT_SIZE = 64


def _to_bytes(data: Union[bytes, str]) -> bytes:
    return data if isinstance(data, (bytes, bytearray)) else str(data).encode("utf-8")


def blake3_hash(data: Union[bytes, str], size: int = 32) -> bytes:
    """
    BLAKE3 digest of ``data`` with ``size`` output bytes (default 256-bit).

    Args:
        data: Input bytes or string.
        size: Output length in bytes (BLAKE3 is extendable-output).

    Returns:
        ``size``-byte BLAKE3 digest.
    """
    import blake3
    return blake3.blake3(_to_bytes(data)).digest(length=size)


def state_root_hash(data: Union[bytes, str]) -> bytes:
    """
    Quantum-resistant consensus state-root hash (Whitepaper §3.6):
    BLAKE3 with 512-bit output.
    """
    return blake3_hash(data, STATE_ROOT_SIZE)


def state_root_hex(data: Union[bytes, str]) -> str:
    """``state_root_hash`` as a lowercase hex string (128 chars)."""
    return state_root_hash(data).hex()


def unified_state_root(utxo_root: str, account_root: str, exchange_root: str) -> str:
    """
    Combine the per-domain state roots into one block state root (Whitepaper §3.6).

    The unified root commits to every state domain — the UTXO set, the
    account/EVM state, and the protocol-level exchange state — under a single
    BLAKE3-512 hash. Domain order is fixed (utxo, account, exchange) and must be
    identical on every validator.

    Args:
        utxo_root: hex digest of the UTXO set.
        account_root: hex digest of account/EVM state.
        exchange_root: hex digest of exchange state.

    Returns:
        128-char hex BLAKE3-512 unified state root.
    """
    payload = f"{utxo_root}|{account_root}|{exchange_root}".encode("utf-8")
    return state_root_hex(payload)
