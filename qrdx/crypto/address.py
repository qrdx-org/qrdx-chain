"""
QRDX Crypto Address Module

Implements addresses for both wallet types:
- Traditional (secp256k1): Ethereum-style with EIP-55 checksum
- Post-Quantum (Dilithium): Extended format with PQ marker
"""

from enum import Enum
from typing import Union
from .hashing import keccak256


class AddressType(Enum):
    """Address type enumeration."""
    TRADITIONAL = "traditional"  # secp256k1, 0x prefix
    POST_QUANTUM = "pq"          # Dilithium, 0xPQ prefix
    LEGACY = "legacy"            # Old Q/R prefix (migration)


# Address prefixes
TRADITIONAL_PREFIX = "0x"
PQ_PREFIX = "0xPQ"
LEGACY_PREFIXES = ("Q", "R")

# Address lengths (without prefix)
TRADITIONAL_LENGTH = 40  # 20 bytes = 40 hex chars
PQ_LENGTH = 64           # 32 bytes = 64 hex chars (for Dilithium pubkey hash)


def get_address_type(address: str) -> AddressType:
    """
    Determine the type of an address.
    
    Args:
        address: Address string
        
    Returns:
        AddressType enum value
    """
    if address.startswith(PQ_PREFIX):
        return AddressType.POST_QUANTUM
    elif address.startswith(TRADITIONAL_PREFIX):
        return AddressType.TRADITIONAL
    elif address[0] in LEGACY_PREFIXES:
        return AddressType.LEGACY
    else:
        raise ValueError(f"Unknown address format: {address}")


def is_pq_address(address: str) -> bool:
    """Check if address is a post-quantum address."""
    return address.startswith(PQ_PREFIX)


def is_traditional_address(address: str) -> bool:
    """Check if address is a traditional secp256k1 address."""
    return address.startswith(TRADITIONAL_PREFIX) and not address.startswith(PQ_PREFIX)


def public_key_to_address(public_key, address_type: AddressType = AddressType.TRADITIONAL) -> str:
    """
    Derive address from public key.
    
    For traditional (secp256k1): Last 20 bytes of keccak256(pubkey)
    For post-quantum (Dilithium): First 32 bytes of keccak256(pubkey) with PQ prefix
    
    Args:
        public_key: PublicKey instance or bytes
        address_type: Type of address to generate
        
    Returns:
        Checksum address with appropriate prefix
    """
    if hasattr(public_key, 'to_bytes'):
        pub_bytes = public_key.to_bytes()
    else:
        pub_bytes = public_key
    
    # Remove 04 prefix if present (uncompressed secp256k1)
    if len(pub_bytes) == 65 and pub_bytes[0] == 0x04:
        pub_bytes = pub_bytes[1:]
    
    if address_type == AddressType.TRADITIONAL:
        # Traditional: last 20 bytes of keccak256
        if len(pub_bytes) != 64:
            raise ValueError(f"secp256k1 public key must be 64 bytes, got {len(pub_bytes)}")
        address_bytes = keccak256(pub_bytes)[-20:]
        address_hex = address_bytes.hex()
        return to_checksum_address(address_hex)
    
    elif address_type == AddressType.POST_QUANTUM:
        # PQ: first 32 bytes of keccak256 with PQ prefix
        address_bytes = keccak256(pub_bytes)[:32]
        address_hex = address_bytes.hex()
        return to_pq_checksum_address(address_hex)
    
    else:
        raise ValueError(f"Cannot generate address for type: {address_type}")


def to_checksum_address(address: str) -> str:
    """
    Convert traditional address to EIP-55 checksum format.
    
    Args:
        address: Hex address (with or without 0x prefix)
        
    Returns:
        Checksum address with 0x prefix
    """
    # Remove prefix and lowercase
    if address.startswith(PQ_PREFIX):
        raise ValueError("Use to_pq_checksum_address for PQ addresses")
    if address.startswith(TRADITIONAL_PREFIX):
        address = address[2:]
    address = address.lower()
    
    if len(address) != TRADITIONAL_LENGTH:
        raise ValueError(f"Traditional address must be {TRADITIONAL_LENGTH} hex chars, got {len(address)}")
    
    # Compute hash for checksum
    address_hash = keccak256(address.encode('utf-8')).hex()
    
    # Apply checksum
    checksummed = ''
    for i, char in enumerate(address):
        if char in '0123456789':
            checksummed += char
        else:
            if int(address_hash[i], 16) >= 8:
                checksummed += char.upper()
            else:
                checksummed += char.lower()
    
    return TRADITIONAL_PREFIX + checksummed


def to_pq_checksum_address(address: str) -> str:
    """
    Convert PQ address to checksum format.
    
    Uses same EIP-55 style checksum but with 0xPQ prefix.
    
    Args:
        address: Hex address (with or without 0xPQ prefix)
        
    Returns:
        Checksum address with 0xPQ prefix
    """
    # Remove prefix and lowercase
    if address.startswith(PQ_PREFIX):
        address = address[4:]  # Remove "0xPQ"
    elif address.startswith(TRADITIONAL_PREFIX):
        address = address[2:]
    address = address.lower()
    
    if len(address) != PQ_LENGTH:
        raise ValueError(f"PQ address must be {PQ_LENGTH} hex chars, got {len(address)}")
    
    # Compute hash for checksum
    address_hash = keccak256(address.encode('utf-8')).hex()
    
    # Apply checksum
    checksummed = ''
    for i, char in enumerate(address):
        if char in '0123456789':
            checksummed += char
        else:
            if int(address_hash[i % len(address_hash)], 16) >= 8:
                checksummed += char.upper()
            else:
                checksummed += char.lower()
    
    return PQ_PREFIX + checksummed


def normalize_address(address: str) -> str:
    """
    Normalize address to lowercase with appropriate prefix.
    
    Args:
        address: Address in any format
        
    Returns:
        Lowercase address with prefix
    """
    addr_type = get_address_type(address)
    
    if addr_type == AddressType.POST_QUANTUM:
        raw = address[4:].lower()  # Remove 0xPQ
        return PQ_PREFIX + raw
    elif addr_type == AddressType.TRADITIONAL:
        raw = address[2:].lower()  # Remove 0x
        return TRADITIONAL_PREFIX + raw
    else:
        raise ValueError(f"Cannot normalize legacy address: {address}")


def is_valid_address(address: str) -> bool:
    """
    Check if address is valid.
    
    Args:
        address: Address to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not isinstance(address, str):
        return False
    
    try:
        addr_type = get_address_type(address)
        
        if addr_type == AddressType.POST_QUANTUM:
            raw = address[4:]
            if len(raw) != PQ_LENGTH:
                return False
        elif addr_type == AddressType.TRADITIONAL:
            raw = address[2:]
            if len(raw) != TRADITIONAL_LENGTH:
                return False
        elif addr_type == AddressType.LEGACY:
            # Legacy addresses have different validation
            return len(address) == 45
        
        # Verify hex
        int(raw, 16)
        return True
        
    except (ValueError, IndexError):
        return False


def is_checksum_address(address: str) -> bool:
    """
    Check if address has valid checksum.
    
    Args:
        address: Address to validate
        
    Returns:
        True if checksum is valid, False otherwise
    """
    if not is_valid_address(address):
        return False
    
    try:
        addr_type = get_address_type(address)
        
        if addr_type == AddressType.POST_QUANTUM:
            expected = to_pq_checksum_address(address)
        elif addr_type == AddressType.TRADITIONAL:
            expected = to_checksum_address(address)
        else:
            return True  # Legacy addresses don't have checksums
        
        return address == expected
        
    except ValueError:
        return False


# Legacy address conversion utilities

def legacy_address_to_web3(legacy_address: str) -> str:
    """
    Convert legacy QRDX address (Base58, Q/R prefix) to Web3 format.
    
    This requires a migration mapping table as legacy addresses
    are derived differently (from P256 curve).
    
    Args:
        legacy_address: Legacy QRDX address starting with Q or R
        
    Returns:
        Web3 checksum address
        
    Raises:
        NotImplementedError: Migration table not yet implemented
    """
    if not legacy_address or legacy_address[0] not in LEGACY_PREFIXES:
        raise ValueError("Legacy address must start with Q or R")
    
    # TODO: Implement actual conversion via migration table
    raise NotImplementedError(
        "Legacy address conversion requires migration mapping table. "
        "See docs/MODERNIZATION_PLAN.md for details."
    )


def web3_to_legacy_address(web3_address: str) -> str:
    """
    Convert Web3 address to legacy QRDX format.
    
    Args:
        web3_address: Web3 checksum address
        
    Returns:
        Legacy QRDX address if mapping exists
        
    Raises:
        NotImplementedError: Migration table not yet implemented
    """
    if not is_valid_address(web3_address):
        raise ValueError("Invalid Web3 address")
    
    raise NotImplementedError(
        "Web3 to legacy address conversion requires migration mapping table. "
        "See docs/MODERNIZATION_PLAN.md for details."
    )


# System wallet address validation

def is_system_address(address: str) -> bool:
    """
    Check if an address is a system-owned address.
    
    System addresses are in the reserved range:
    - 0x0000...0001 through 0x0000...00FF (system wallets)
    - 0x0000...0100 through 0x0000...0FFF (reserved for future use)
    
    Args:
        address: Address to check
        
    Returns:
        True if address is a system address
    """
    from .system_wallets import is_system_wallet_address, is_address_off_curve
    return is_system_wallet_address(address) or is_address_off_curve(address)


def validate_system_address(address: str) -> tuple[bool, str]:
    """
    Validate a system address.
    
    Args:
        address: Address to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not address.startswith("0x"):
        return False, "System address must start with 0x"
    
    if not is_valid_address(address):
        return False, "Invalid address format"
    
    if not is_system_address(address):
        return False, f"Address {address} is not in system address range"
    
    return True, "OK"


def is_reserved_address(address: str) -> bool:
    """
    Check if address is in any reserved range.
    
    Reserved ranges:
    - System wallets: 0x0000...0001 - 0x0000...00FF
    - Precompiles: 0x0000...0100 - 0x0000...01FF
    - QPL programs: 0x0000...0200 - 0x0000...02FF
    - Future: 0x0000...0300 - 0x0000...0FFF
    
    Args:
        address: Address to check
        
    Returns:
        True if address is in any reserved range
    """
    if not address.startswith("0x"):
        return False
    
    try:
        addr_int = int(address, 16)
        # All addresses from 0x0 to 0xFFF are reserved
        return 0x0000000000000000000000000000000000000000 <= addr_int <= 0x0000000000000000000000000000000000000FFF
    except ValueError:
        return False

