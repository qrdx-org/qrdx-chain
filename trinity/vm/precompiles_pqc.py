"""
Post-Quantum Cryptography Precompiled Contracts for QEVM
Provides efficient on-chain PQC operations for smart contracts
"""

from eth.vm.computation import BaseComputation
from eth.exceptions import VMError
from eth_typing import Address
from eth_utils import ValidationError

from trinity.crypto.pqc import (
    DilithiumPublicKey,
    DILITHIUM_PUBLIC_KEY_SIZE,
    DILITHIUM_SIGNATURE_SIZE,
)
from trinity.crypto.hashing import blake3_256, blake3_512


# Precompiled contract addresses (0x0A through 0x0F)
DILITHIUM_VERIFY_ADDRESS = Address(b'\x00' * 19 + b'\x0A')
BLAKE3_HASH_256_ADDRESS = Address(b'\x00' * 19 + b'\x0B')
BLAKE3_HASH_512_ADDRESS = Address(b'\x00' * 19 + b'\x0C')
BLAKE3_KEYED_HASH_ADDRESS = Address(b'\x00' * 19 + b'\x0D')

# Gas costs for PQC operations
# These are higher than ECDSA due to computational complexity
DILITHIUM_VERIFY_BASE_GAS = 6000  # ~2x higher than ecrecover
DILITHIUM_VERIFY_PER_BYTE_GAS = 10

BLAKE3_256_BASE_GAS = 60
BLAKE3_256_PER_WORD_GAS = 12

BLAKE3_512_BASE_GAS = 90
BLAKE3_512_PER_WORD_GAS = 18

BLAKE3_KEYED_BASE_GAS = 100
BLAKE3_KEYED_PER_WORD_GAS = 20


def dilithium_verify(computation: BaseComputation) -> BaseComputation:
    """
    Precompiled contract for Dilithium signature verification.
    
    Input format (5277 bytes total):
    - message_hash (32 bytes): BLAKE3 hash of the message
    - public_key (1952 bytes): Dilithium public key
    - signature (3293 bytes): Dilithium signature
    
    Output:
    - 1 byte: 0x01 if valid, 0x00 if invalid
    
    Gas cost: 6000 + (input_size * 10)
    """
    # Calculate gas cost
    input_size = len(computation.msg.data)
    gas_cost = DILITHIUM_VERIFY_BASE_GAS + (input_size * DILITHIUM_VERIFY_PER_BYTE_GAS)
    
    computation.consume_gas(
        gas_cost,
        reason="Dilithium signature verification"
    )
    
    # Expected input size
    expected_size = 32 + DILITHIUM_PUBLIC_KEY_SIZE + DILITHIUM_SIGNATURE_SIZE
    
    if input_size != expected_size:
        # Invalid input - return 0x00
        computation.output = b'\x00'
        return computation
    
    try:
        # Parse input
        data = computation.msg.data
        offset = 0
        
        message_hash = bytes(data[offset:offset + 32])
        offset += 32
        
        public_key_bytes = bytes(data[offset:offset + DILITHIUM_PUBLIC_KEY_SIZE])
        offset += DILITHIUM_PUBLIC_KEY_SIZE
        
        signature = bytes(data[offset:offset + DILITHIUM_SIGNATURE_SIZE])
        
        # Verify signature
        public_key = DilithiumPublicKey(public_key_bytes)
        is_valid = public_key.verify(message_hash, signature)
        
        # Return result
        computation.output = b'\x01' if is_valid else b'\x00'
        
    except Exception:
        # Any error in verification returns invalid
        computation.output = b'\x00'
    
    return computation


def blake3_hash_256(computation: BaseComputation) -> BaseComputation:
    """
    Precompiled contract for BLAKE3 256-bit hash.
    
    Input: arbitrary bytes
    Output: 32-byte hash
    
    Gas cost: 60 + (words * 12)
    """
    # Calculate gas cost (per 32-byte word)
    data = computation.msg.data
    num_words = (len(data) + 31) // 32
    gas_cost = BLAKE3_256_BASE_GAS + (num_words * BLAKE3_256_PER_WORD_GAS)
    
    computation.consume_gas(
        gas_cost,
        reason="BLAKE3-256 hash"
    )
    
    try:
        hash_output = blake3_256(bytes(data))
        computation.output = hash_output
    except Exception as e:
        raise VMError(f"BLAKE3-256 hash failed: {e}")
    
    return computation


def blake3_hash_512(computation: BaseComputation) -> BaseComputation:
    """
    Precompiled contract for BLAKE3 512-bit hash (quantum-resistant).
    
    Input: arbitrary bytes
    Output: 64-byte hash
    
    Gas cost: 90 + (words * 18)
    """
    # Calculate gas cost (per 32-byte word)
    data = computation.msg.data
    num_words = (len(data) + 31) // 32
    gas_cost = BLAKE3_512_BASE_GAS + (num_words * BLAKE3_512_PER_WORD_GAS)
    
    computation.consume_gas(
        gas_cost,
        reason="BLAKE3-512 hash"
    )
    
    try:
        hash_output = blake3_512(bytes(data))
        computation.output = hash_output
    except Exception as e:
        raise VMError(f"BLAKE3-512 hash failed: {e}")
    
    return computation


def blake3_keyed_hash(computation: BaseComputation) -> BaseComputation:
    """
    Precompiled contract for BLAKE3 keyed hash (MAC).
    
    Input format:
    - key (32 bytes): MAC key
    - data (remaining bytes): Data to hash
    
    Output: 32-byte keyed hash
    
    Gas cost: 100 + (words * 20)
    """
    data = computation.msg.data
    
    if len(data) < 32:
        raise VMError("BLAKE3 keyed hash requires at least 32 bytes (key)")
    
    # Calculate gas cost (per 32-byte word)
    num_words = (len(data) + 31) // 32
    gas_cost = BLAKE3_KEYED_BASE_GAS + (num_words * BLAKE3_KEYED_PER_WORD_GAS)
    
    computation.consume_gas(
        gas_cost,
        reason="BLAKE3 keyed hash"
    )
    
    try:
        # Extract key and data
        key = bytes(data[:32])
        message = bytes(data[32:])
        
        # Compute keyed hash
        from trinity.crypto.hashing import blake3_keyed_hash as keyed_hash
        hash_output = keyed_hash(key, message, output_length=32)
        
        computation.output = hash_output
    except Exception as e:
        raise VMError(f"BLAKE3 keyed hash failed: {e}")
    
    return computation


# Map of precompiled contract addresses to their implementations
PQC_PRECOMPILES = {
    DILITHIUM_VERIFY_ADDRESS: dilithium_verify,
    BLAKE3_HASH_256_ADDRESS: blake3_hash_256,
    BLAKE3_HASH_512_ADDRESS: blake3_hash_512,
    BLAKE3_KEYED_HASH_ADDRESS: blake3_keyed_hash,
}


def get_pqc_precompiles():
    """
    Get the dictionary of PQC precompiled contracts.
    
    Returns:
        Dict mapping addresses to precompile functions
    """
    return PQC_PRECOMPILES


def is_pqc_precompile(address: Address) -> bool:
    """
    Check if an address is a PQC precompiled contract.
    
    Args:
        address: Address to check
        
    Returns:
        True if address is a PQC precompile
    """
    return address in PQC_PRECOMPILES
