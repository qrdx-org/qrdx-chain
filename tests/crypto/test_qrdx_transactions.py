"""
Tests for QRDX quantum-resistant transactions.
"""

import pytest
import rlp
from eth_typing import Address

from eth.crypto import generate_keypair
from eth.rlp.qrdx_transactions import (
    QRDXTransaction,
    QRDXUnsignedTransaction,
    sign_qrdx_transaction,
    QRDX_TX_TYPE,
)
from eth.constants import CREATE_CONTRACT_ADDRESS


@pytest.fixture
def keypair():
    """Generate a test keypair."""
    return generate_keypair()


@pytest.fixture
def unsigned_transaction():
    """Create an unsigned test transaction."""
    return QRDXUnsignedTransaction(
        nonce=0,
        gas_price=1000000000,
        gas=21000,
        to=Address(b'\x01' * 20),
        value=1000000000000000000,
        data=b'',
        chain_id=1337,
    )


def test_unsigned_transaction_creation():
    """Test creating an unsigned transaction."""
    tx = QRDXUnsignedTransaction(
        nonce=5,
        gas_price=2000000000,
        gas=50000,
        to=Address(b'\xff' * 20),
        value=500000000000000000,
        data=b'\xde\xad\xbe\xef',
        chain_id=1337,
    )
    
    assert tx.nonce == 5
    assert tx.gas_price == 2000000000
    assert tx.gas == 50000
    assert tx.value == 500000000000000000
    assert tx.data == b'\xde\xad\xbe\xef'
    assert tx.chain_id == 1337


def test_unsigned_transaction_validation():
    """Test unsigned transaction validation."""
    # Valid transaction
    tx = QRDXUnsignedTransaction(
        nonce=0,
        gas_price=1000000000,
        gas=21000,
        to=Address(b'\x00' * 20),
        value=1000000000000000000,
        data=b'',
        chain_id=1337,
    )
    tx.validate()  # Should not raise
    
    # Invalid: gas too low
    with pytest.raises(Exception):
        tx = QRDXUnsignedTransaction(
            nonce=0,
            gas_price=1000000000,
            gas=10000,  # Too low
            to=Address(b'\x00' * 20),
            value=1000000000000000000,
            data=b'',
            chain_id=1337,
        )
        tx.validate()


def test_transaction_signing(keypair, unsigned_transaction):
    """Test signing an unsigned transaction."""
    private_key, public_key = keypair
    
    signed_tx = sign_qrdx_transaction(unsigned_transaction, private_key)
    
    assert signed_tx.nonce == unsigned_transaction.nonce
    assert signed_tx.gas_price == unsigned_transaction.gas_price
    assert signed_tx.gas == unsigned_transaction.gas
    assert signed_tx.to == unsigned_transaction.to
    assert signed_tx.value == unsigned_transaction.value
    assert signed_tx.data == unsigned_transaction.data
    assert signed_tx.chain_id == unsigned_transaction.chain_id
    assert len(signed_tx.public_key) == 1952  # Dilithium public key size
    assert len(signed_tx.signature) == 3309  # Dilithium signature size


def test_transaction_signature_validation(keypair, unsigned_transaction):
    """Test signature validation."""
    private_key, public_key = keypair
    
    signed_tx = sign_qrdx_transaction(unsigned_transaction, private_key)
    
    # Signature should be valid
    assert signed_tx.is_signature_valid
    signed_tx.check_signature_validity()  # Should not raise
    
    # Verify sender extraction
    sender = signed_tx.get_sender()
    assert isinstance(sender, bytes)
    assert len(sender) == 20


def test_transaction_encoding_decoding(keypair, unsigned_transaction):
    """Test RLP encoding and decoding."""
    private_key, public_key = keypair
    
    signed_tx = sign_qrdx_transaction(unsigned_transaction, private_key)
    
    # Encode
    encoded = signed_tx.encode()
    assert isinstance(encoded, bytes)
    assert len(encoded) > 5000  # Should be large due to PQ signature
    
    # Decode
    decoded_tx = QRDXTransaction.decode(encoded)
    
    # Verify fields match
    assert decoded_tx.nonce == signed_tx.nonce
    assert decoded_tx.gas_price == signed_tx.gas_price
    assert decoded_tx.gas == signed_tx.gas
    assert decoded_tx.to == signed_tx.to
    assert decoded_tx.value == signed_tx.value
    assert decoded_tx.data == signed_tx.data
    assert decoded_tx.chain_id == signed_tx.chain_id
    assert decoded_tx.public_key == signed_tx.public_key
    assert decoded_tx.signature == signed_tx.signature


def test_transaction_hash(keypair, unsigned_transaction):
    """Test transaction hash generation."""
    private_key, public_key = keypair
    
    signed_tx = sign_qrdx_transaction(unsigned_transaction, private_key)
    
    tx_hash = signed_tx.hash
    assert isinstance(tx_hash, bytes)
    assert len(tx_hash) == 32
    
    # Hash should be deterministic
    tx_hash2 = signed_tx.hash
    assert tx_hash == tx_hash2


def test_transaction_type_id():
    """Test transaction type ID."""
    assert QRDX_TX_TYPE == 0x7f
    assert QRDXTransaction.type_id == QRDX_TX_TYPE


def test_intrinsic_gas_calculation(keypair):
    """Test intrinsic gas calculation."""
    private_key, public_key = keypair
    
    # Simple transfer (no data)
    tx_simple = QRDXUnsignedTransaction(
        nonce=0,
        gas_price=1000000000,
        gas=30000,
        to=Address(b'\x01' * 20),
        value=1000000000000000000,
        data=b'',
        chain_id=1337,
    )
    
    signed_simple = sign_qrdx_transaction(tx_simple, private_key)
    assert signed_simple.intrinsic_gas == 30000  # Base cost for QRDX tx
    
    # With data
    tx_data = QRDXUnsignedTransaction(
        nonce=0,
        gas_price=1000000000,
        gas=50000,
        to=Address(b'\x01' * 20),
        value=1000000000000000000,
        data=b'\x00' * 10 + b'\xff' * 10,  # 10 zero bytes + 10 non-zero
        chain_id=1337,
    )
    
    signed_data = sign_qrdx_transaction(tx_data, private_key)
    # 30000 base + 10*4 (zeros) + 10*16 (non-zeros) = 30200
    assert signed_data.intrinsic_gas == 30200


def test_contract_creation_transaction(keypair):
    """Test contract creation transaction."""
    private_key, public_key = keypair
    
    bytecode = b'\x60\x60\x60\x40'  # Sample bytecode
    
    tx = QRDXUnsignedTransaction(
        nonce=0,
        gas_price=1000000000,
        gas=100000,
        to=CREATE_CONTRACT_ADDRESS,
        value=0,
        data=bytecode,
        chain_id=1337,
    )
    
    signed_tx = sign_qrdx_transaction(tx, private_key)
    
    assert signed_tx.to == CREATE_CONTRACT_ADDRESS
    assert signed_tx.data == bytecode
    assert signed_tx.is_signature_valid


def test_transaction_copy(keypair, unsigned_transaction):
    """Test copying a transaction with modified fields."""
    private_key, public_key = keypair
    
    signed_tx = sign_qrdx_transaction(unsigned_transaction, private_key)
    
    # Copy with modified nonce
    copied_tx = signed_tx.copy(nonce=10)
    
    assert copied_tx.nonce == 10
    assert copied_tx.gas_price == signed_tx.gas_price
    assert copied_tx.gas == signed_tx.gas
    assert copied_tx.to == signed_tx.to


def test_transaction_sender_consistency(keypair):
    """Test that sender is consistent across multiple transactions."""
    private_key, public_key = keypair
    
    # Create multiple transactions from same key
    transactions = []
    for i in range(3):
        tx = QRDXUnsignedTransaction(
            nonce=i,
            gas_price=1000000000,
            gas=21000,
            to=Address(b'\x01' * 20),
            value=1000000000000000000,
            data=b'',
            chain_id=1337,
        )
        signed = sign_qrdx_transaction(tx, private_key)
        transactions.append(signed)
    
    # All should have same sender
    senders = [tx.get_sender() for tx in transactions]
    assert len(set(senders)) == 1


def test_large_transaction():
    """Test transaction with large data payload."""
    private_key, public_key = generate_keypair()
    
    # 10 KB of data
    large_data = b'\xff' * 10240
    
    tx = QRDXUnsignedTransaction(
        nonce=0,
        gas_price=1000000000,
        gas=500000,
        to=Address(b'\x01' * 20),
        value=0,
        data=large_data,
        chain_id=1337,
    )
    
    signed_tx = sign_qrdx_transaction(tx, private_key)
    
    # Total size should be ~15 KB (10 KB data + 5 KB signature overhead)
    encoded = signed_tx.encode()
    assert len(encoded) > 15000
    assert signed_tx.is_signature_valid


def test_transaction_builder_api(keypair):
    """Test TransactionBuilderAPI implementation."""
    private_key, public_key = keypair
    
    # Test create_unsigned_transaction class method
    unsigned_tx = QRDXTransaction.create_unsigned_transaction(
        nonce=5,
        gas_price=2000000000,
        gas=50000,
        to=Address(b'\xff' * 20),
        value=500000000000000000,
        data=b'\xde\xad\xbe\xef',
        chain_id=1337,
    )
    
    assert unsigned_tx.nonce == 5
    assert unsigned_tx.gas_price == 2000000000
    assert unsigned_tx.gas == 50000
    
    # Test new_transaction class method
    signature = private_key.sign(b'test message')
    public_key_bytes = private_key.public_key().to_bytes()
    
    signed_tx = QRDXTransaction.new_transaction(
        nonce=5,
        gas_price=2000000000,
        gas=50000,
        to=Address(b'\xff' * 20),
        value=500000000000000000,
        data=b'\xde\xad\xbe\xef',
        chain_id=1337,
        public_key=public_key_bytes,
        signature=signature,
    )
    
    assert signed_tx.nonce == 5
    assert len(signed_tx.public_key) == 1952
    assert len(signed_tx.signature) == 3309


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
