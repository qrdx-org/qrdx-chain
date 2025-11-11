"""
Hybrid Transaction Format for QRDX Chain
Supports both legacy (ECDSA) and post-quantum (Dilithium) signatures
"""

import rlp
from rlp.sedes import (
    Binary,
    big_endian_int,
    binary,
)
from typing import Optional, Union
from eth_typing import Address
from eth_utils import ValidationError, keccak
from eth_keys import datatypes as eth_datatypes

from trinity.crypto.pqc import (
    DilithiumPrivateKey,
    DilithiumPublicKey,
    DILITHIUM_SIGNATURE_SIZE,
)
from trinity.crypto.addresses import (
    generate_legacy_address,
    generate_pq_address,
    is_legacy_address,
    is_pq_address,
    validate_address,
)
from trinity.crypto.hashing import blake3_256


# Signature type identifiers
SIGNATURE_TYPE_ECDSA = 0x00
SIGNATURE_TYPE_DILITHIUM = 0x01


class BaseHybridTransaction(rlp.Serializable):
    """
    Base transaction class supporting both ECDSA and Dilithium signatures.
    
    RLP Structure:
    [nonce, gas_price, gas, to, value, data, signature_type, signature_data]
    
    For ECDSA (signature_type = 0x00):
        signature_data = [v, r, s]
        
    For Dilithium (signature_type = 0x01):
        signature_data = dilithium_signature (3293 bytes)
    """
    
    fields = [
        ('nonce', big_endian_int),
        ('gas_price', big_endian_int),
        ('gas', big_endian_int),
        ('to', Binary(21, 33, allow_empty=True)),  # Support both legacy (21) and PQ (33) addresses
        ('value', big_endian_int),
        ('data', binary),
        ('signature_type', big_endian_int),
        ('signature_data', binary),
    ]
    
    def __init__(self,
                 nonce: int,
                 gas_price: int,
                 gas: int,
                 to: bytes,
                 value: int,
                 data: bytes,
                 signature_type: int,
                 signature_data: bytes):
        """
        Initialize a hybrid transaction.
        
        Args:
            nonce: Transaction nonce
            gas_price: Gas price in wei
            gas: Gas limit
            to: Recipient address (21 or 33 bytes, or empty for contract creation)
            value: Value in wei
            data: Transaction data
            signature_type: 0x00 for ECDSA, 0x01 for Dilithium
            signature_data: Signature bytes (format depends on signature_type)
        """
        if to and not (is_legacy_address(to) or is_pq_address(to)):
            raise ValidationError(f"Invalid recipient address: {to.hex()}")
        
        if signature_type not in (SIGNATURE_TYPE_ECDSA, SIGNATURE_TYPE_DILITHIUM):
            raise ValidationError(
                f"Invalid signature type: {signature_type}. "
                f"Must be {SIGNATURE_TYPE_ECDSA} (ECDSA) or {SIGNATURE_TYPE_DILITHIUM} (Dilithium)"
            )
        
        super().__init__(
            nonce=nonce,
            gas_price=gas_price,
            gas=gas,
            to=to,
            value=value,
            data=data,
            signature_type=signature_type,
            signature_data=signature_data,
        )
    
    @property
    def is_ecdsa_signed(self) -> bool:
        """Check if transaction uses ECDSA signature."""
        return self.signature_type == SIGNATURE_TYPE_ECDSA
    
    @property
    def is_dilithium_signed(self) -> bool:
        """Check if transaction uses Dilithium signature."""
        return self.signature_type == SIGNATURE_TYPE_DILITHIUM
    
    @property
    def sender(self) -> bytes:
        """
        Recover the sender address from the signature.
        
        Returns:
            Sender address (21 or 33 bytes)
        """
        if self.is_ecdsa_signed:
            return self._recover_ecdsa_sender()
        elif self.is_dilithium_signed:
            return self._recover_dilithium_sender()
        else:
            raise ValidationError(f"Unknown signature type: {self.signature_type}")
    
    def _recover_ecdsa_sender(self) -> bytes:
        """
        Recover sender address from ECDSA signature.
        
        Returns:
            21-byte legacy address
        """
        # Decode v, r, s from signature_data
        try:
            v, r, s = rlp.decode(self.signature_data)
            v = int.from_bytes(v, 'big') if isinstance(v, bytes) else v
            r = int.from_bytes(r, 'big') if isinstance(r, bytes) else r
            s = int.from_bytes(s, 'big') if isinstance(s, bytes) else s
        except Exception as e:
            raise ValidationError(f"Invalid ECDSA signature data: {e}")
        
        # Get unsigned transaction hash
        unsigned_tx_hash = self._unsigned_transaction_hash_ecdsa()
        
        # Recover public key
        from eth_keys import keys
        try:
            signature = keys.Signature(vrs=(v, r, s))
            public_key = signature.recover_public_key_from_msg_hash(unsigned_tx_hash)
        except Exception as e:
            raise ValidationError(f"Failed to recover ECDSA public key: {e}")
        
        return generate_legacy_address(public_key)
    
    def _recover_dilithium_sender(self) -> bytes:
        """
        Recover sender address from Dilithium signature.
        
        For Dilithium, we need the public key to be included in the signature_data.
        Format: public_key (1952 bytes) || signature (3293 bytes)
        
        Returns:
            33-byte PQ address
        """
        from trinity.crypto.pqc import DILITHIUM_PUBLIC_KEY_SIZE
        
        # Extract public key and signature
        if len(self.signature_data) != DILITHIUM_PUBLIC_KEY_SIZE + DILITHIUM_SIGNATURE_SIZE:
            raise ValidationError(
                f"Invalid Dilithium signature data length. "
                f"Expected {DILITHIUM_PUBLIC_KEY_SIZE + DILITHIUM_SIGNATURE_SIZE}, "
                f"got {len(self.signature_data)}"
            )
        
        public_key_bytes = self.signature_data[:DILITHIUM_PUBLIC_KEY_SIZE]
        signature_bytes = self.signature_data[DILITHIUM_PUBLIC_KEY_SIZE:]
        
        # Verify signature
        try:
            public_key = DilithiumPublicKey(public_key_bytes)
        except Exception as e:
            raise ValidationError(f"Invalid Dilithium public key: {e}")
        
        # Get unsigned transaction hash
        unsigned_tx_hash = self._unsigned_transaction_hash_dilithium()
        
        # Verify the signature
        if not public_key.verify(unsigned_tx_hash, signature_bytes):
            raise ValidationError("Invalid Dilithium signature")
        
        return generate_pq_address(public_key)
    
    def _unsigned_transaction_hash_ecdsa(self) -> bytes:
        """
        Compute hash of unsigned transaction for ECDSA signing.
        Uses Keccak256 for legacy compatibility.
        
        Returns:
            32-byte hash
        """
        unsigned_tx = rlp.encode([
            self.nonce,
            self.gas_price,
            self.gas,
            self.to,
            self.value,
            self.data,
        ])
        return keccak(unsigned_tx)
    
    def _unsigned_transaction_hash_dilithium(self) -> bytes:
        """
        Compute hash of unsigned transaction for Dilithium signing.
        Uses BLAKE3 for quantum resistance.
        
        Returns:
            32-byte hash
        """
        unsigned_tx = rlp.encode([
            self.nonce,
            self.gas_price,
            self.gas,
            self.to,
            self.value,
            self.data,
        ])
        return blake3_256(unsigned_tx)
    
    @property
    def hash(self) -> bytes:
        """
        Compute the transaction hash.
        Uses appropriate hash function based on signature type.
        
        Returns:
            32-byte transaction hash
        """
        tx_bytes = rlp.encode(self)
        if self.is_ecdsa_signed:
            return keccak(tx_bytes)
        else:
            return blake3_256(tx_bytes)
    
    @property
    def intrinsic_gas(self) -> int:
        """
        Calculate the intrinsic gas cost for this transaction.
        PQ transactions have higher base cost due to larger signatures.
        
        Returns:
            Intrinsic gas cost
        """
        # Base gas costs
        if self.is_dilithium_signed:
            # Higher base cost for PQ transactions (larger signatures to verify)
            base_gas = 50000  # ~2.5x higher than legacy
        else:
            base_gas = 21000  # Standard Ethereum
        
        # Data gas
        data_gas = 0
        for byte in self.data:
            if byte == 0:
                data_gas += 4
            else:
                data_gas += 68
        
        # Contract creation
        if not self.to:
            creation_gas = 32000
        else:
            creation_gas = 0
        
        return base_gas + data_gas + creation_gas


class UnsignedTransaction:
    """
    Unsigned transaction ready to be signed with either ECDSA or Dilithium.
    """
    
    def __init__(self,
                 nonce: int,
                 gas_price: int,
                 gas: int,
                 to: bytes,
                 value: int,
                 data: bytes):
        """
        Initialize an unsigned transaction.
        
        Args:
            nonce: Transaction nonce
            gas_price: Gas price in wei
            gas: Gas limit
            to: Recipient address (21 or 33 bytes, or empty for contract creation)
            value: Value in wei
            data: Transaction data
        """
        self.nonce = nonce
        self.gas_price = gas_price
        self.gas = gas
        self.to = to
        self.value = value
        self.data = data
    
    def sign_ecdsa(self, private_key: eth_datatypes.PrivateKey, chain_id: Optional[int] = None) -> BaseHybridTransaction:
        """
        Sign the transaction with ECDSA.
        
        Args:
            private_key: ECDSA private key
            chain_id: Optional chain ID for EIP-155 replay protection
            
        Returns:
            Signed transaction
        """
        from eth_keys import keys
        
        # Compute unsigned hash
        unsigned_tx = rlp.encode([
            self.nonce,
            self.gas_price,
            self.gas,
            self.to,
            self.value,
            self.data,
        ])
        unsigned_hash = keccak(unsigned_tx)
        
        # Sign
        signature = private_key.sign_msg_hash(unsigned_hash)
        
        # Apply EIP-155 if chain_id provided
        if chain_id is not None:
            v = signature.v + (chain_id * 2 + 35)
        else:
            v = signature.v
        
        # Encode signature as [v, r, s]
        signature_data = rlp.encode([v, signature.r, signature.s])
        
        return BaseHybridTransaction(
            nonce=self.nonce,
            gas_price=self.gas_price,
            gas=self.gas,
            to=self.to,
            value=self.value,
            data=self.data,
            signature_type=SIGNATURE_TYPE_ECDSA,
            signature_data=signature_data,
        )
    
    def sign_dilithium(self, private_key: DilithiumPrivateKey) -> BaseHybridTransaction:
        """
        Sign the transaction with Dilithium.
        
        Args:
            private_key: Dilithium private key
            
        Returns:
            Signed transaction
        """
        # Compute unsigned hash using BLAKE3
        unsigned_tx = rlp.encode([
            self.nonce,
            self.gas_price,
            self.gas,
            self.to,
            self.value,
            self.data,
        ])
        unsigned_hash = blake3_256(unsigned_tx)
        
        # Sign with Dilithium
        signature = private_key.sign(unsigned_hash)
        
        # Include public key with signature for verification
        public_key = private_key.public_key()
        signature_data = public_key.to_bytes() + signature
        
        return BaseHybridTransaction(
            nonce=self.nonce,
            gas_price=self.gas_price,
            gas=self.gas,
            to=self.to,
            value=self.value,
            data=self.data,
            signature_type=SIGNATURE_TYPE_DILITHIUM,
            signature_data=signature_data,
        )


def create_transaction(nonce: int,
                       gas_price: int,
                       gas: int,
                       to: bytes,
                       value: int,
                       data: bytes) -> UnsignedTransaction:
    """
    Create an unsigned transaction.
    
    Args:
        nonce: Transaction nonce
        gas_price: Gas price in wei
        gas: Gas limit
        to: Recipient address (21 or 33 bytes, or empty for contract creation)
        value: Value in wei
        data: Transaction data
        
    Returns:
        UnsignedTransaction instance
    """
    return UnsignedTransaction(nonce, gas_price, gas, to, value, data)
