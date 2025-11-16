"""
Post-Quantum Address Generation and Management

Handles PQ address format (32 bytes) with bech32m encoding.
Provides utilities for address mapping between classical and PQ addresses.
"""

from typing import Optional
try:
    import bech32
    BECH32_AVAILABLE = True
except ImportError:
    BECH32_AVAILABLE = False

from trinity.crypto.pq.blake3_hash import blake3_hash
from trinity.crypto.pq.dilithium import DilithiumPublicKey
from trinity.crypto.pq.constants import (
    PQ_ADDRESS_SIZE,
    CLASSICAL_ADDRESS_SIZE,
    BECH32M_HRP,
)
from trinity.crypto.pq.exceptions import (
    InvalidAddress,
    AddressEncodingError,
)


def generate_pq_address(dilithium_pubkey: DilithiumPublicKey) -> bytes:
    """
    Generate a 32-byte post-quantum address from a Dilithium public key.
    
    Address = BLAKE3(dilithium_pubkey)[:32]
    
    Args:
        dilithium_pubkey: Dilithium public key
    
    Returns:
        32-byte PQ address
    
    Example:
        >>> from trinity.crypto.pq import DilithiumPrivateKey, generate_pq_address
        >>> privkey = DilithiumPrivateKey.generate()
        >>> pubkey = privkey.public_key()
        >>> address = generate_pq_address(pubkey)
        >>> len(address)
        32
    """
    pubkey_bytes = dilithium_pubkey.to_bytes()
    # Use BLAKE3 for quantum-resistant hashing
    # Take first 32 bytes (256 bits)
    address_hash = blake3_hash(pubkey_bytes, digest_size=32)
    return address_hash


def validate_pq_address(address: bytes) -> bool:
    """
    Validate PQ address format.
    
    Args:
        address: Address bytes to validate
    
    Returns:
        True if valid PQ address (32 bytes), False otherwise
    
    Example:
        >>> validate_pq_address(b"\\x00" * 32)
        True
        >>> validate_pq_address(b"\\x00" * 20)
        False
    """
    return len(address) == PQ_ADDRESS_SIZE


def encode_pq_address(address: bytes) -> str:
    """
    Encode PQ address to bech32m format.
    
    Format: qrdx1<bech32m_encoded_address>
    
    Args:
        address: 32-byte PQ address
    
    Returns:
        Bech32m-encoded address string (e.g., "qrdx1qw508d6qejxtdg4y5r3zarvary...")
    
    Raises:
        InvalidAddress: If address is not 32 bytes
        AddressEncodingError: If bech32 library not available or encoding fails
    
    Example:
        >>> address = bytes.fromhex("00" * 32)
        >>> encoded = encode_pq_address(address)
        >>> encoded.startswith("qrdx1")
        True
    """
    if not validate_pq_address(address):
        raise InvalidAddress(f"Invalid PQ address size: expected {PQ_ADDRESS_SIZE}, got {len(address)}")
    
    if not BECH32_AVAILABLE:
        raise AddressEncodingError(
            "bech32 library not available. Install with: pip install bech32"
        )
    
    try:
        # Convert bytes to 5-bit groups for bech32
        # Use bech32m variant (BIP-350)
        witver = 1  # Witness version for bech32m
        witprog = list(address)
        
        # Encode using bech32m
        encoded = bech32.encode(BECH32M_HRP, witver, witprog)
        
        if encoded is None:
            raise AddressEncodingError("Bech32m encoding failed")
        
        return encoded
    except Exception as e:
        raise AddressEncodingError(f"Failed to encode PQ address: {e}")


def decode_pq_address(encoded_address: str) -> bytes:
    """
    Decode bech32m-encoded PQ address to bytes.
    
    Args:
        encoded_address: Bech32m string (e.g., "qrdx1qw508d6qejxtdg4y5r3zarvary...")
    
    Returns:
        32-byte PQ address
    
    Raises:
        InvalidAddress: If address format is invalid
        AddressEncodingError: If bech32 library not available or decoding fails
    
    Example:
        >>> encoded = "qrdx1..." # bech32m address
        >>> address = decode_pq_address(encoded)
        >>> len(address)
        32
    """
    if not BECH32_AVAILABLE:
        raise AddressEncodingError(
            "bech32 library not available. Install with: pip install bech32"
        )
    
    try:
        # Decode bech32m
        hrp, witver, witprog = bech32.decode(BECH32M_HRP, encoded_address)
        
        if hrp != BECH32M_HRP:
            raise InvalidAddress(f"Invalid HRP: expected {BECH32M_HRP}, got {hrp}")
        
        if witver != 1:
            raise InvalidAddress(f"Invalid witness version: expected 1 (bech32m), got {witver}")
        
        if witprog is None:
            raise InvalidAddress("Failed to decode bech32m address")
        
        # Convert 5-bit groups back to bytes
        address = bytes(witprog)
        
        if not validate_pq_address(address):
            raise InvalidAddress(f"Decoded address has invalid size: {len(address)}")
        
        return address
    except InvalidAddress:
        raise
    except Exception as e:
        raise AddressEncodingError(f"Failed to decode PQ address: {e}")


def is_classical_address(address: bytes) -> bool:
    """
    Check if address is classical Ethereum format (20 bytes).
    
    Args:
        address: Address bytes
    
    Returns:
        True if classical address, False otherwise
    """
    return len(address) == CLASSICAL_ADDRESS_SIZE


def is_pq_address(address: bytes) -> bool:
    """
    Check if address is PQ format (32 bytes).
    
    Args:
        address: Address bytes
    
    Returns:
        True if PQ address, False otherwise
    """
    return len(address) == PQ_ADDRESS_SIZE


def format_address(address: bytes, encode: bool = True) -> str:
    """
    Format address for display.
    
    Args:
        address: Address bytes (20 or 32 bytes)
        encode: If True and PQ address, use bech32m encoding
    
    Returns:
        Formatted address string
    
    Example:
        >>> classical = bytes.fromhex("742d35Cc6634C0532925a3b8...")
        >>> format_address(classical)
        '0x742d35Cc6634C0532925a3b8...'
        
        >>> pq = bytes.fromhex("00" * 32)
        >>> format_address(pq)
        'qrdx1...'
    """
    if is_classical_address(address):
        # Classical: 0x-prefixed hex
        return "0x" + address.hex()
    elif is_pq_address(address):
        if encode and BECH32_AVAILABLE:
            try:
                return encode_pq_address(address)
            except Exception:
                # Fall back to hex if encoding fails
                return "0x" + address.hex()
        else:
            # Fall back to hex
            return "0x" + address.hex()
    else:
        # Unknown format - just hex
        return "0x" + address.hex()


def shorten_address(address: str, start_chars: int = 6, end_chars: int = 4) -> str:
    """
    Shorten address for display (e.g., "qrdx1qw50...v9k").
    
    Args:
        address: Full address string
        start_chars: Number of characters to show at start
        end_chars: Number of characters to show at end
    
    Returns:
        Shortened address with ellipsis
    
    Example:
        >>> shorten_address("qrdx1qw508d6qejxtdg4y5r3zarvary0c5xw7k3jhv9k")
        'qrdx1q...hv9k'
    """
    if len(address) <= start_chars + end_chars + 3:
        return address
    
    return address[:start_chars] + "..." + address[-end_chars:]
