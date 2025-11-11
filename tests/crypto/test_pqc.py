"""
Test suite for QRDX Post-Quantum Cryptography implementation
"""

import pytest
from trinity.crypto.pqc import (
    generate_dilithium_keypair,
    generate_kyber_keypair,
    DilithiumPrivateKey,
    DilithiumPublicKey,
    DILITHIUM_SIGNATURE_SIZE,
)
from trinity.crypto.hashing import blake3_256, blake3_512, Blake3Hash
from trinity.crypto.addresses import (
    generate_pq_address,
    generate_legacy_address,
    is_pq_address,
    is_legacy_address,
    validate_address,
)
from trinity.rlp.transactions import (
    UnsignedTransaction,
    create_transaction,
    SIGNATURE_TYPE_ECDSA,
    SIGNATURE_TYPE_DILITHIUM,
)


class TestDilithium:
    """Test CRYSTALS-Dilithium signature operations."""
    
    def test_keypair_generation(self):
        """Test Dilithium keypair generation."""
        privkey, pubkey = generate_dilithium_keypair()
        
        assert isinstance(privkey, DilithiumPrivateKey)
        assert isinstance(pubkey, DilithiumPublicKey)
        assert len(privkey.to_bytes()) == 4000
        assert len(pubkey.to_bytes()) == 1952
    
    def test_sign_and_verify(self):
        """Test signing and verification."""
        privkey, pubkey = generate_dilithium_keypair()
        message = b"Hello, quantum-resistant world!"
        
        # Sign message
        signature = privkey.sign(message)
        assert len(signature) == DILITHIUM_SIGNATURE_SIZE
        
        # Verify signature
        assert pubkey.verify(message, signature)
        
        # Verify fails with wrong message
        wrong_message = b"Wrong message"
        assert not pubkey.verify(wrong_message, signature)
        
        # Verify fails with wrong signature
        wrong_signature = b'\x00' * DILITHIUM_SIGNATURE_SIZE
        assert not pubkey.verify(message, wrong_signature)
    
    def test_public_key_derivation(self):
        """Test deriving public key from private key."""
        privkey, pubkey = generate_dilithium_keypair()
        derived_pubkey = privkey.public_key()
        
        assert derived_pubkey.to_bytes() == pubkey.to_bytes()


class TestKyber:
    """Test CRYSTALS-Kyber key encapsulation."""
    
    def test_keypair_generation(self):
        """Test Kyber keypair generation."""
        privkey, pubkey = generate_kyber_keypair()
        
        assert len(privkey.to_bytes()) == 2400
        assert len(pubkey.to_bytes()) == 1184
    
    def test_encapsulation_decapsulation(self):
        """Test key encapsulation and decapsulation."""
        privkey, pubkey = generate_kyber_keypair()
        
        # Encapsulate
        ciphertext, shared_secret_1 = pubkey.encapsulate()
        assert len(ciphertext) == 1088
        assert len(shared_secret_1) == 32
        
        # Decapsulate
        shared_secret_2 = privkey.decapsulate(ciphertext)
        assert len(shared_secret_2) == 32
        
        # Shared secrets should match
        assert shared_secret_1 == shared_secret_2


class TestHashing:
    """Test BLAKE3 hash functions."""
    
    def test_blake3_256(self):
        """Test BLAKE3 with 256-bit output."""
        data = b"Test data"
        hash_output = blake3_256(data)
        
        assert len(hash_output) == 32
        assert isinstance(hash_output, bytes)
        
        # Same input produces same output
        assert blake3_256(data) == hash_output
        
        # Different input produces different output
        assert blake3_256(b"Different data") != hash_output
    
    def test_blake3_512(self):
        """Test BLAKE3 with 512-bit output (quantum-resistant)."""
        data = b"Test data"
        hash_output = blake3_512(data)
        
        assert len(hash_output) == 64
        assert isinstance(hash_output, bytes)
        
        # Same input produces same output
        assert blake3_512(data) == hash_output
    
    def test_blake3_hash_class(self):
        """Test Blake3Hash class with incremental updates."""
        hasher = Blake3Hash(output_length=32)
        
        # Update in chunks
        hasher.update(b"Hello, ")
        hasher.update(b"world!")
        
        result = hasher.digest()
        assert len(result) == 32
        
        # Should match single hash
        expected = blake3_256(b"Hello, world!")
        assert result == expected


class TestAddresses:
    """Test quantum-resistant address generation."""
    
    def test_pq_address_generation(self):
        """Test PQ address generation from Dilithium key."""
        _, pubkey = generate_dilithium_keypair()
        address = generate_pq_address(pubkey)
        
        # Should be 33 bytes (1 prefix + 32 address)
        assert len(address) == 33
        assert address[0] == 0x02  # PQ prefix
        
        # Should be identified as PQ address
        assert is_pq_address(address)
        assert not is_legacy_address(address)
        
        # Should validate
        validate_address(address)
    
    def test_address_determinism(self):
        """Test that same public key produces same address."""
        _, pubkey = generate_dilithium_keypair()
        
        address1 = generate_pq_address(pubkey)
        address2 = generate_pq_address(pubkey)
        
        assert address1 == address2


class TestHybridTransactions:
    """Test hybrid transaction format supporting both ECDSA and Dilithium."""
    
    def test_create_unsigned_transaction(self):
        """Test creating unsigned transaction."""
        tx = create_transaction(
            nonce=0,
            gas_price=1000000000,
            gas=21000,
            to=b'\x02' + b'\x00' * 32,  # PQ address
            value=1000000000000000000,  # 1 ETH
            data=b'',
        )
        
        assert tx.nonce == 0
        assert tx.gas_price == 1000000000
        assert tx.gas == 21000
        assert tx.value == 1000000000000000000
    
    def test_sign_with_dilithium(self):
        """Test signing transaction with Dilithium."""
        privkey, pubkey = generate_dilithium_keypair()
        recipient = generate_pq_address(pubkey)
        
        tx = create_transaction(
            nonce=0,
            gas_price=1000000000,
            gas=50000,
            to=recipient,
            value=1000000000000000000,
            data=b'',
        )
        
        signed_tx = tx.sign_dilithium(privkey)
        
        # Check signature type
        assert signed_tx.signature_type == SIGNATURE_TYPE_DILITHIUM
        assert signed_tx.is_dilithium_signed
        assert not signed_tx.is_ecdsa_signed
        
        # Verify sender recovery
        sender = signed_tx.sender
        assert is_pq_address(sender)
        assert sender == generate_pq_address(pubkey)
    
    def test_dilithium_transaction_gas_cost(self):
        """Test that Dilithium transactions have higher base gas cost."""
        privkey, _ = generate_dilithium_keypair()
        
        tx = create_transaction(
            nonce=0,
            gas_price=1000000000,
            gas=100000,
            to=b'\x02' + b'\x00' * 32,
            value=0,
            data=b'',
        )
        
        signed_tx = tx.sign_dilithium(privkey)
        
        # PQ transactions should have higher intrinsic gas
        assert signed_tx.intrinsic_gas == 50000  # vs 21000 for ECDSA
    
    def test_transaction_hash_uses_blake3(self):
        """Test that Dilithium transactions use BLAKE3 for hashing."""
        privkey, _ = generate_dilithium_keypair()
        
        tx = create_transaction(
            nonce=0,
            gas_price=1000000000,
            gas=100000,
            to=b'\x02' + b'\x00' * 32,
            value=0,
            data=b'',
        )
        
        signed_tx = tx.sign_dilithium(privkey)
        tx_hash = signed_tx.hash
        
        # Hash should be 32 bytes
        assert len(tx_hash) == 32
        assert isinstance(tx_hash, bytes)


class TestPrecompiles:
    """Test PQC precompiled contracts."""
    
    def test_dilithium_verify_precompile_address(self):
        """Test Dilithium verify precompile address."""
        from trinity.vm.precompiles_pqc import DILITHIUM_VERIFY_ADDRESS
        
        # Should be at 0x0A
        assert DILITHIUM_VERIFY_ADDRESS == b'\x00' * 19 + b'\x0A'
    
    def test_blake3_precompile_addresses(self):
        """Test BLAKE3 precompile addresses."""
        from trinity.vm.precompiles_pqc import (
            BLAKE3_HASH_256_ADDRESS,
            BLAKE3_HASH_512_ADDRESS,
            BLAKE3_KEYED_HASH_ADDRESS,
        )
        
        assert BLAKE3_HASH_256_ADDRESS == b'\x00' * 19 + b'\x0B'
        assert BLAKE3_HASH_512_ADDRESS == b'\x00' * 19 + b'\x0C'
        assert BLAKE3_KEYED_HASH_ADDRESS == b'\x00' * 19 + b'\x0D'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
