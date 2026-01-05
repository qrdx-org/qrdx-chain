"""
QRDX Crypto Signing Module

Provides transaction and message signing using secp256k1.
"""

from typing import Tuple, Union, Optional
from .keys import PrivateKey, PublicKey, Signature
from .hashing import keccak256


def sign_message_hash(private_key: PrivateKey, msg_hash: bytes) -> Signature:
    """
    Sign a 32-byte message hash.
    
    Args:
        private_key: PrivateKey to sign with
        msg_hash: 32-byte hash to sign
        
    Returns:
        Signature
    """
    return private_key.sign_msg_hash(msg_hash)


def sign_message(private_key: PrivateKey, message: bytes) -> Signature:
    """
    Sign a message (Ethereum personal_sign style).
    
    The message is prefixed with "\x19Ethereum Signed Message:\n{length}"
    before hashing and signing.
    
    Args:
        private_key: PrivateKey to sign with
        message: Raw message bytes
        
    Returns:
        Signature
    """
    prefix = b'\x19Ethereum Signed Message:\n' + str(len(message)).encode()
    prefixed_message = prefix + message
    msg_hash = keccak256(prefixed_message)
    return private_key.sign_msg_hash(msg_hash)


def sign_typed_data(private_key: PrivateKey, domain_separator: bytes, struct_hash: bytes) -> Signature:
    """
    Sign typed data (EIP-712 style).
    
    Args:
        private_key: PrivateKey to sign with
        domain_separator: EIP-712 domain separator
        struct_hash: Hash of the struct to sign
        
    Returns:
        Signature
    """
    # EIP-712: 0x19 0x01 domainSeparator structHash
    message = b'\x19\x01' + domain_separator + struct_hash
    msg_hash = keccak256(message)
    return private_key.sign_msg_hash(msg_hash)


def sign_transaction(private_key: PrivateKey, tx_hash: bytes, chain_id: Optional[int] = None) -> Signature:
    """
    Sign a transaction hash.
    
    If chain_id is provided, EIP-155 replay protection is applied.
    The signature's v value will be chain_id * 2 + 35 + recovery_id.
    
    Args:
        private_key: PrivateKey to sign with
        tx_hash: 32-byte transaction hash (RLP encoded tx without signature)
        chain_id: Optional chain ID for EIP-155
        
    Returns:
        Signature with adjusted v value if chain_id provided
    """
    signature = private_key.sign_msg_hash(tx_hash)
    
    if chain_id is not None:
        # EIP-155: v = chain_id * 2 + 35 + recovery_id
        # recovery_id is 0 or 1 (stored in signature.v)
        new_v = chain_id * 2 + 35 + signature.v
        return Signature.from_vrs(new_v, signature.r, signature.s)
    
    return signature


def recover_public_key(msg_hash: bytes, signature: Signature) -> PublicKey:
    """
    Recover public key from signature.
    
    Args:
        msg_hash: 32-byte message hash that was signed
        signature: Signature to recover from
        
    Returns:
        Recovered PublicKey
    """
    return PublicKey.recover_from_msg_hash(msg_hash, signature)


def recover_message_signer(message: bytes, signature: Signature) -> PublicKey:
    """
    Recover signer public key from personal_sign signature.
    
    Args:
        message: Original message bytes
        signature: Signature from sign_message()
        
    Returns:
        Recovered PublicKey
    """
    prefix = b'\x19Ethereum Signed Message:\n' + str(len(message)).encode()
    prefixed_message = prefix + message
    msg_hash = keccak256(prefixed_message)
    return recover_public_key(msg_hash, signature)


def verify_signature(public_key: PublicKey, msg_hash: bytes, signature: Signature) -> bool:
    """
    Verify a signature against a public key.
    
    Args:
        public_key: PublicKey to verify against
        msg_hash: 32-byte message hash
        signature: Signature to verify
        
    Returns:
        True if valid, False otherwise
    """
    return public_key.verify_msg_hash(msg_hash, signature)


def verify_message(public_key: PublicKey, message: bytes, signature: Signature) -> bool:
    """
    Verify a personal_sign signature.
    
    Args:
        public_key: PublicKey to verify against
        message: Original message bytes
        signature: Signature to verify
        
    Returns:
        True if valid, False otherwise
    """
    try:
        recovered = recover_message_signer(message, signature)
        return recovered == public_key
    except Exception:
        return False


def ecrecover(msg_hash: bytes, v: int, r: int, s: int) -> str:
    """
    Recover signer address from signature components.
    
    This mirrors the Solidity ecrecover() function.
    
    Args:
        msg_hash: 32-byte message hash
        v: Recovery parameter (27 or 28)
        r: R component
        s: S component
        
    Returns:
        Recovered address (0x prefixed)
    """
    signature = Signature.from_vrs(v, r, s)
    public_key = recover_public_key(msg_hash, signature)
    return public_key.to_address()
