"""
Quantum-Resistant Address Generation for QRDX Chain
Supports both legacy (ECDSA/secp256k1) and PQ (Dilithium) addresses
"""

from typing import Union
from eth_utils import to_checksum_address, ValidationError
from eth_keys import datatypes as eth_datatypes
from .hashing import blake3_256, blake3_512
from .pqc import DilithiumPublicKey


# Address format prefixes
LEGACY_ADDRESS_PREFIX = 0x01  # 20-byte Ethereum-style address with prefix
PQ_ADDRESS_PREFIX = 0x02      # 32-byte quantum-resistant address with prefix

# Address sizes (including prefix byte)
LEGACY_ADDRESS_SIZE = 21  # 1 byte prefix + 20 bytes address
PQ_ADDRESS_SIZE = 33      # 1 byte prefix + 32 bytes address


def generate_legacy_address(public_key: eth_datatypes.PublicKey) -> bytes:
    """
    Generate a legacy Ethereum-style address from an ECDSA public key.
    Format: 0x01 || keccak256(pubkey)[-20:]
    
    Args:
        public_key: eth_keys PublicKey instance
        
    Returns:
        21-byte address (1-byte prefix + 20-byte address)
    """
    from eth_hash.auto import keccak
    
    # Get the Ethereum address (last 20 bytes of keccak hash)
    pubkey_bytes = public_key.to_bytes()
    address_bytes = keccak(pubkey_bytes)[-20:]
    
    # Prepend the legacy prefix
    return bytes([LEGACY_ADDRESS_PREFIX]) + address_bytes


def generate_pq_address(public_key: DilithiumPublicKey) -> bytes:
    """
    Generate a quantum-resistant address from a Dilithium public key.
    Format: 0x02 || blake3_256(dilithium_pubkey)
    
    Due to the large size of Dilithium public keys (1952 bytes), we use
    BLAKE3 to compress it to a 32-byte address.
    
    Args:
        public_key: DilithiumPublicKey instance
        
    Returns:
        33-byte address (1-byte prefix + 32-byte address)
    """
    # Hash the Dilithium public key to 32 bytes using BLAKE3
    pubkey_bytes = public_key.to_bytes()
    address_bytes = blake3_256(pubkey_bytes)
    
    # Prepend the PQ prefix
    return bytes([PQ_ADDRESS_PREFIX]) + address_bytes


def is_legacy_address(address: bytes) -> bool:
    """
    Check if an address is a legacy ECDSA address.
    
    Args:
        address: Address bytes to check
        
    Returns:
        True if legacy address, False otherwise
    """
    return len(address) == LEGACY_ADDRESS_SIZE and address[0] == LEGACY_ADDRESS_PREFIX


def is_pq_address(address: bytes) -> bool:
    """
    Check if an address is a quantum-resistant address.
    
    Args:
        address: Address bytes to check
        
    Returns:
        True if PQ address, False otherwise
    """
    return len(address) == PQ_ADDRESS_SIZE and address[0] == PQ_ADDRESS_PREFIX


def validate_address(address: bytes) -> None:
    """
    Validate that an address is properly formatted.
    
    Args:
        address: Address bytes to validate
        
    Raises:
        ValidationError: If address is invalid
    """
    if not isinstance(address, bytes):
        raise ValidationError(f"Address must be bytes, got {type(address)}")
    
    if is_legacy_address(address):
        return
    
    if is_pq_address(address):
        return
    
    raise ValidationError(
        f"Invalid address format. Expected {LEGACY_ADDRESS_SIZE} bytes (legacy) "
        f"or {PQ_ADDRESS_SIZE} bytes (PQ), got {len(address)} bytes"
    )


def address_to_hex(address: bytes) -> str:
    """
    Convert address bytes to hex string representation.
    
    Args:
        address: Address bytes
        
    Returns:
        Hex string with 0x prefix
    """
    validate_address(address)
    return "0x" + address.hex()


def hex_to_address(hex_address: str) -> bytes:
    """
    Convert hex string to address bytes.
    
    Args:
        hex_address: Hex string (with or without 0x prefix)
        
    Returns:
        Address bytes
    """
    if hex_address.startswith("0x"):
        hex_address = hex_address[2:]
    
    address_bytes = bytes.fromhex(hex_address)
    validate_address(address_bytes)
    
    return address_bytes


def get_address_type(address: bytes) -> str:
    """
    Get the type of an address.
    
    Args:
        address: Address bytes
        
    Returns:
        "legacy" or "pq"
        
    Raises:
        ValidationError: If address is invalid
    """
    validate_address(address)
    
    if is_legacy_address(address):
        return "legacy"
    elif is_pq_address(address):
        return "pq"
    else:
        raise ValidationError(f"Unknown address type for address: {address.hex()}")


def generate_pq_contract_address(sender: bytes, nonce: int) -> bytes:
    """
    Generate a contract address for a PQ transaction.
    Uses BLAKE3 instead of Keccak256 for quantum resistance.
    
    Format: 0x02 || blake3_256(sender || nonce)[-32:]
    
    Args:
        sender: Sender address (legacy or PQ)
        nonce: Transaction nonce
        
    Returns:
        33-byte PQ contract address
    """
    import rlp
    
    validate_address(sender)
    
    # RLP encode sender and nonce
    rlp_encoded = rlp.encode([sender, nonce])
    
    # Hash with BLAKE3
    address_bytes = blake3_256(rlp_encoded)
    
    # Prepend PQ prefix
    return bytes([PQ_ADDRESS_PREFIX]) + address_bytes


def generate_legacy_contract_address(sender: bytes, nonce: int) -> bytes:
    """
    Generate a contract address for a legacy transaction.
    Uses standard Ethereum CREATE opcode logic.
    
    Format: 0x01 || keccak256(rlp([sender, nonce]))[-20:]
    
    Args:
        sender: Sender address (must be legacy)
        nonce: Transaction nonce
        
    Returns:
        21-byte legacy contract address
    """
    import rlp
    from eth_hash.auto import keccak
    
    if not is_legacy_address(sender):
        raise ValidationError("Legacy contract address requires legacy sender address")
    
    # Remove prefix for Ethereum compatibility
    sender_eth = sender[1:]
    
    # RLP encode sender and nonce
    rlp_encoded = rlp.encode([sender_eth, nonce])
    
    # Hash with Keccak256
    address_bytes = keccak(rlp_encoded)[-20:]
    
    # Prepend legacy prefix
    return bytes([LEGACY_ADDRESS_PREFIX]) + address_bytes
