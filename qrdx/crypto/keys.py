"""
QRDX Crypto Keys Module

Implements secp256k1 key management for Web3 compatibility.
This replaces the previous P256 (NIST) curve implementation.
"""

import os
import secrets
from typing import Optional, Tuple, Union

from eth_keys import keys as eth_keys
from eth_keys.datatypes import PrivateKey as EthPrivateKey, PublicKey as EthPublicKey
from eth_utils import encode_hex, decode_hex

from ..exceptions import InvalidKeyError


class PrivateKey:
    """
    secp256k1 private key for transaction signing.
    
    Wraps eth-keys PrivateKey for Web3 compatibility.
    """
    
    def __init__(self, key_bytes: bytes):
        """
        Initialize from raw 32-byte private key.
        
        Args:
            key_bytes: 32 bytes of private key data
            
        Raises:
            InvalidKeyError: If key bytes are invalid
        """
        if len(key_bytes) != 32:
            raise InvalidKeyError(f"Private key must be 32 bytes, got {len(key_bytes)}")
        
        try:
            self._key = EthPrivateKey(key_bytes)
        except Exception as e:
            raise InvalidKeyError(f"Invalid private key: {e}")
    
    @classmethod
    def from_hex(cls, hex_str: str) -> "PrivateKey":
        """
        Create from hex string.
        
        Args:
            hex_str: Hex-encoded private key (with or without 0x prefix)
            
        Returns:
            PrivateKey instance
        """
        key_bytes = decode_hex(hex_str)
        return cls(key_bytes)
    
    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> "PrivateKey":
        """
        Create from raw bytes.
        
        Args:
            key_bytes: 32-byte private key
            
        Returns:
            PrivateKey instance
        """
        return cls(key_bytes)
    
    @classmethod
    def from_int(cls, key_int: int) -> "PrivateKey":
        """
        Create from integer.
        
        Args:
            key_int: Private key as integer
            
        Returns:
            PrivateKey instance
        """
        key_bytes = key_int.to_bytes(32, byteorder='big')
        return cls(key_bytes)
    
    @classmethod
    def generate(cls) -> "PrivateKey":
        """
        Generate a new random private key.
        
        Returns:
            New PrivateKey instance
        """
        key_bytes = secrets.token_bytes(32)
        return cls(key_bytes)
    
    @property
    def public_key(self) -> "PublicKey":
        """
        Derive the corresponding public key.
        
        Returns:
            PublicKey instance
        """
        return PublicKey(self._key.public_key)
    
    def to_bytes(self) -> bytes:
        """Get raw private key bytes."""
        return self._key.to_bytes()
    
    def to_hex(self, with_prefix: bool = True) -> str:
        """
        Get hex-encoded private key.
        
        Args:
            with_prefix: Include 0x prefix
            
        Returns:
            Hex string
        """
        hex_str = self._key.to_bytes().hex()
        return f"0x{hex_str}" if with_prefix else hex_str
    
    def to_int(self) -> int:
        """Get private key as integer."""
        return int.from_bytes(self._key.to_bytes(), byteorder='big')
    
    def sign_msg_hash(self, msg_hash: bytes) -> "Signature":
        """
        Sign a 32-byte message hash.
        
        Args:
            msg_hash: 32-byte hash to sign
            
        Returns:
            Signature instance
        """
        if len(msg_hash) != 32:
            raise ValueError(f"Message hash must be 32 bytes, got {len(msg_hash)}")
        
        signature = self._key.sign_msg_hash(msg_hash)
        return Signature(signature)
    
    def __repr__(self) -> str:
        return f"PrivateKey({self.to_hex()[:10]}...)"
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, PrivateKey):
            return False
        return self._key == other._key


class PublicKey:
    """
    secp256k1 public key for verification.
    """
    
    def __init__(self, key: Union[EthPublicKey, bytes]):
        """
        Initialize public key.
        
        Args:
            key: eth-keys PublicKey or 64-byte uncompressed public key
        """
        if isinstance(key, EthPublicKey):
            self._key = key
        elif isinstance(key, bytes):
            if len(key) == 64:
                # Uncompressed format without prefix
                self._key = EthPublicKey(key)
            elif len(key) == 65 and key[0] == 0x04:
                # Uncompressed format with 04 prefix
                self._key = EthPublicKey(key[1:])
            elif len(key) == 33:
                # Compressed format — decompress via secp256k1 curve equation
                # y² = x³ + 7  (mod p)
                prefix = key[0]
                if prefix not in (0x02, 0x03):
                    raise InvalidKeyError(
                        f"Invalid compressed public key prefix: 0x{prefix:02x}"
                    )
                x = int.from_bytes(key[1:], "big")
                p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
                y_sq = (pow(x, 3, p) + 7) % p
                # Tonelli-Shanks for p ≡ 3 (mod 4) reduces to modular exponentiation
                y = pow(y_sq, (p + 1) // 4, p)
                if (y % 2 == 0) != (prefix == 0x02):
                    y = p - y
                uncompressed = x.to_bytes(32, "big") + y.to_bytes(32, "big")
                self._key = EthPublicKey(uncompressed)
            else:
                raise InvalidKeyError(f"Invalid public key length: {len(key)}")
        else:
            raise InvalidKeyError(f"Invalid public key type: {type(key)}")
    
    @classmethod
    def from_hex(cls, hex_str: str) -> "PublicKey":
        """
        Create from hex string.
        
        Args:
            hex_str: Hex-encoded public key (with or without 0x prefix)
            
        Returns:
            PublicKey instance
        """
        key_bytes = decode_hex(hex_str)
        return cls(key_bytes)
    
    @classmethod
    def recover_from_msg_hash(cls, msg_hash: bytes, signature: "Signature") -> "PublicKey":
        """
        Recover public key from signature.
        
        Args:
            msg_hash: 32-byte message hash that was signed
            signature: Signature to recover from
            
        Returns:
            Recovered PublicKey
        """
        eth_sig = signature._signature
        recovered = eth_sig.recover_public_key_from_msg_hash(msg_hash)
        return cls(recovered)
    
    def to_bytes(self, compressed: bool = False) -> bytes:
        """
        Get raw public key bytes.
        
        Args:
            compressed: Use compressed format (33 bytes) if True
            
        Returns:
            Public key bytes
        """
        if compressed:
            # SEC1 compressed format: 0x02/0x03 prefix + 32-byte x coordinate
            raw = self._key.to_bytes()  # 64 bytes: x (32) || y (32)
            x = raw[:32]
            y_last = raw[-1]
            prefix = bytes([0x02 if y_last % 2 == 0 else 0x03])
            return prefix + x
        return self._key.to_bytes()
    
    def to_hex(self, with_prefix: bool = True, compressed: bool = False) -> str:
        """
        Get hex-encoded public key.
        
        Args:
            with_prefix: Include 0x prefix
            compressed: Use compressed format
            
        Returns:
            Hex string
        """
        hex_str = self.to_bytes(compressed).hex()
        return f"0x{hex_str}" if with_prefix else hex_str
    
    def to_address(self) -> str:
        """
        Derive Ethereum-style address from public key.
        
        Returns:
            Checksum address string (0x prefixed)
        """
        from .address import public_key_to_address
        return public_key_to_address(self)
    
    def verify_msg_hash(self, msg_hash: bytes, signature: "Signature") -> bool:
        """
        Verify a signature against this public key.
        
        Args:
            msg_hash: 32-byte message hash
            signature: Signature to verify
            
        Returns:
            True if valid, False otherwise
        """
        try:
            recovered = PublicKey.recover_from_msg_hash(msg_hash, signature)
            return recovered == self
        except Exception:
            return False
    
    def __repr__(self) -> str:
        return f"PublicKey({self.to_hex()[:18]}...)"
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, PublicKey):
            return False
        return self._key == other._key
    
    def __hash__(self) -> int:
        return hash(self._key.to_bytes())


class Signature:
    """
    ECDSA signature (v, r, s format).
    """
    
    def __init__(self, signature):
        """
        Initialize signature.
        
        Args:
            signature: eth-keys Signature object
        """
        self._signature = signature
    
    @classmethod
    def from_vrs(cls, v: int, r: int, s: int) -> "Signature":
        """
        Create from v, r, s components.
        
        Args:
            v: Recovery parameter (27 or 28, or 0/1)
            r: R component
            s: S component
            
        Returns:
            Signature instance
        """
        from eth_keys.datatypes import Signature as EthSignature
        
        # Normalize v to 0/1
        if v >= 27:
            v -= 27
        
        vrs = (v, r, s)
        eth_sig = EthSignature(vrs=vrs)
        return cls(eth_sig)
    
    @classmethod
    def from_bytes(cls, sig_bytes: bytes) -> "Signature":
        """
        Create from 65-byte signature.
        
        Args:
            sig_bytes: 65 bytes (r[32] + s[32] + v[1])
            
        Returns:
            Signature instance
        """
        if len(sig_bytes) != 65:
            raise ValueError(f"Signature must be 65 bytes, got {len(sig_bytes)}")
        
        r = int.from_bytes(sig_bytes[0:32], byteorder='big')
        s = int.from_bytes(sig_bytes[32:64], byteorder='big')
        v = sig_bytes[64]
        
        return cls.from_vrs(v, r, s)
    
    @classmethod
    def from_hex(cls, hex_str: str) -> "Signature":
        """
        Create from hex string.
        
        Args:
            hex_str: Hex-encoded signature
            
        Returns:
            Signature instance
        """
        sig_bytes = decode_hex(hex_str)
        return cls.from_bytes(sig_bytes)
    
    @property
    def v(self) -> int:
        """Recovery parameter (0 or 1)."""
        return self._signature.v
    
    @property
    def r(self) -> int:
        """R component."""
        return self._signature.r
    
    @property
    def s(self) -> int:
        """S component."""
        return self._signature.s
    
    @property
    def vrs(self) -> Tuple[int, int, int]:
        """Get (v, r, s) tuple."""
        return (self.v, self.r, self.s)
    
    def to_bytes(self) -> bytes:
        """
        Get 65-byte signature (r + s + v).
        
        Returns:
            65 bytes
        """
        r_bytes = self.r.to_bytes(32, byteorder='big')
        s_bytes = self.s.to_bytes(32, byteorder='big')
        v_byte = bytes([self.v])
        return r_bytes + s_bytes + v_byte
    
    def to_hex(self, with_prefix: bool = True) -> str:
        """
        Get hex-encoded signature.
        
        Args:
            with_prefix: Include 0x prefix
            
        Returns:
            Hex string
        """
        hex_str = self.to_bytes().hex()
        return f"0x{hex_str}" if with_prefix else hex_str
    
    def __repr__(self) -> str:
        return f"Signature(v={self.v}, r={hex(self.r)[:10]}..., s={hex(self.s)[:10]}...)"


def generate_keypair() -> Tuple[PrivateKey, PublicKey]:
    """
    Generate a new keypair.
    
    Returns:
        Tuple of (PrivateKey, PublicKey)
    """
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    return private_key, public_key
