"""
Contract Address Generation

Ethereum-compatible contract address computation for QRDX.
"""

import hashlib
from typing import Optional
from eth_utils import keccak, to_checksum_address
import rlp


def generate_contract_address(sender: str, nonce: int) -> str:
    """
    Generate contract address using CREATE opcode logic.
    
    Address = keccak256(rlp([sender, nonce]))[-20:]
    
    Args:
        sender: Sender address (QRDX or Ethereum format)
        nonce: Account nonce
        
    Returns:
        Contract address (Ethereum checksum format)
    """
    # Convert QRDX address to bytes if needed
    if sender.startswith('qrdx_'):
        # QRDX address format - convert to bytes
        sender_bytes = bytes.fromhex(sender[5:])  # Remove 'qrdx_' prefix
    elif sender.startswith('0x'):
        # Ethereum address format
        sender_bytes = bytes.fromhex(sender[2:])
    else:
        sender_bytes = bytes.fromhex(sender)
    
    # RLP encode [sender, nonce]
    rlp_encoded = rlp.encode([sender_bytes, nonce])
    
    # Keccak256 hash
    hash_bytes = keccak(rlp_encoded)
    
    # Take last 20 bytes as address
    address_bytes = hash_bytes[-20:]
    
    # Return as Ethereum checksum address
    return to_checksum_address('0x' + address_bytes.hex())


def generate_contract_address_create2(
    sender: str,
    salt: bytes,
    bytecode: bytes
) -> str:
    """
    Generate contract address using CREATE2 opcode logic.
    
    Address = keccak256(0xff + sender + salt + keccak256(bytecode))[-20:]
    
    Args:
        sender: Sender address
        salt: 32-byte salt
        bytecode: Contract initialization bytecode
        
    Returns:
        Contract address (Ethereum checksum format)
    """
    # Convert sender to bytes
    if sender.startswith('qrdx_'):
        sender_bytes = bytes.fromhex(sender[5:])
    elif sender.startswith('0x'):
        sender_bytes = bytes.fromhex(sender[2:])
    else:
        sender_bytes = bytes.fromhex(sender)
    
    # Ensure sender is 20 bytes
    if len(sender_bytes) > 20:
        sender_bytes = sender_bytes[-20:]
    elif len(sender_bytes) < 20:
        sender_bytes = b'\x00' * (20 - len(sender_bytes)) + sender_bytes
    
    # Ensure salt is 32 bytes
    if len(salt) > 32:
        salt = salt[:32]
    elif len(salt) < 32:
        salt = b'\x00' * (32 - len(salt)) + salt
    
    # Compute bytecode hash
    bytecode_hash = keccak(bytecode)
    
    # Concatenate: 0xff + sender + salt + bytecode_hash
    data = b'\xff' + sender_bytes + salt + bytecode_hash
    
    # Keccak256 hash
    hash_bytes = keccak(data)
    
    # Take last 20 bytes as address
    address_bytes = hash_bytes[-20:]
    
    # Return as Ethereum checksum address
    return to_checksum_address('0x' + address_bytes.hex())


def convert_qrdx_to_eth_address(qrdx_address: str) -> str:
    """
    Convert QRDX address to Ethereum-compatible address.
    
    Args:
        qrdx_address: QRDX address (qrdx_... format)
        
    Returns:
        Ethereum checksum address (0x... format)
    """
    if qrdx_address.startswith('0x'):
        return to_checksum_address(qrdx_address)
    
    if qrdx_address.startswith('qrdx_'):
        address_bytes = bytes.fromhex(qrdx_address[5:])
    else:
        address_bytes = bytes.fromhex(qrdx_address)
    
    # Take last 20 bytes for Ethereum address
    if len(address_bytes) > 20:
        address_bytes = address_bytes[-20:]
    elif len(address_bytes) < 20:
        address_bytes = b'\x00' * (20 - len(address_bytes)) + address_bytes
    
    return to_checksum_address('0x' + address_bytes.hex())


def convert_eth_to_qrdx_address(eth_address: str) -> str:
    """
    Convert Ethereum address to QRDX format.
    
    Args:
        eth_address: Ethereum address (0x... format)
        
    Returns:
        QRDX address (qrdx_... format)
    """
    if eth_address.startswith('qrdx_'):
        return eth_address
    
    if eth_address.startswith('0x'):
        address_bytes = bytes.fromhex(eth_address[2:])
    else:
        address_bytes = bytes.fromhex(eth_address)
    
    return 'qrdx_' + address_bytes.hex()


def compute_function_selector(function_signature: str) -> bytes:
    """
    Compute Ethereum function selector (first 4 bytes of keccak256(sig)).
    
    Args:
        function_signature: Function signature like "transfer(address,uint256)"
        
    Returns:
        4-byte function selector
    """
    sig_hash = keccak(function_signature.encode('utf-8'))
    return sig_hash[:4]


def encode_function_call(function_signature: str, *args) -> bytes:
    """
    Encode function call data (selector + ABI-encoded arguments).
    
    Args:
        function_signature: Function signature
        *args: Function arguments
        
    Returns:
        Encoded call data
    """
    from eth_abi import encode
    
    # Get function selector
    selector = compute_function_selector(function_signature)
    
    # Parse argument types from signature
    # E.g., "transfer(address,uint256)" -> ['address', 'uint256']
    args_start = function_signature.index('(') + 1
    args_end = function_signature.index(')')
    arg_types_str = function_signature[args_start:args_end]
    
    if arg_types_str:
        arg_types = [t.strip() for t in arg_types_str.split(',')]
        encoded_args = encode(arg_types, args)
    else:
        encoded_args = b''
    
    return selector + encoded_args


def decode_function_call(data: bytes) -> tuple[bytes, bytes]:
    """
    Decode function call data into selector and arguments.
    
    Args:
        data: Encoded function call data
        
    Returns:
        Tuple of (selector, arguments)
    """
    if len(data) < 4:
        return b'', b''
    
    selector = data[:4]
    args = data[4:]
    
    return selector, args
