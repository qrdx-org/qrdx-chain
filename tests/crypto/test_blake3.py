"""
Tests for BLAKE3 cryptographic hash function.

Tests hashing, KDF, Merkle roots, and utility functions.
"""

import pytest

from trinity.crypto.pq.blake3_hash import (
    blake3_hash,
    blake3_merkle_root,
    blake3_kdf,
    blake3_incremental,
    xor_bytes,
)


class TestBlake3Hashing:
    """Test basic BLAKE3 hashing"""
    
    def test_basic_hash(self):
        """Test basic hashing"""
        data = b"hello world"
        digest = blake3_hash(data)
        
        assert len(digest) == 64  # Default 512-bit output
        assert isinstance(digest, bytes)
    
    def test_deterministic(self):
        """Test that hashing is deterministic"""
        data = b"test data"
        
        digest1 = blake3_hash(data)
        digest2 = blake3_hash(data)
        
        assert digest1 == digest2
    
    def test_different_data_different_hash(self):
        """Test that different data produces different hashes"""
        digest1 = blake3_hash(b"data1")
        digest2 = blake3_hash(b"data2")
        
        assert digest1 != digest2
    
    def test_custom_digest_size(self):
        """Test custom output size"""
        data = b"test"
        
        digest32 = blake3_hash(data, digest_size=32)
        digest64 = blake3_hash(data, digest_size=64)
        digest128 = blake3_hash(data, digest_size=128)
        
        assert len(digest32) == 32
        assert len(digest64) == 64
        assert len(digest128) == 128
    
    def test_empty_data(self):
        """Test hashing empty data"""
        digest = blake3_hash(b"")
        
        assert len(digest) == 64
    
    def test_large_data(self):
        """Test hashing large data"""
        large_data = b"x" * 1_000_000  # 1 MB
        digest = blake3_hash(large_data)
        
        assert len(digest) == 64
    
    def test_minimum_digest_size(self):
        """Test that minimum digest size is enforced"""
        with pytest.raises(ValueError):
            blake3_hash(b"test", digest_size=16)  # Too small


class TestBlake3MerkleRoot:
    """Test BLAKE3 Merkle root computation"""
    
    def test_empty_list(self):
        """Test Merkle root of empty list"""
        root = blake3_merkle_root([])
        
        assert len(root) == 32
        # Should be hash of empty bytes
        assert root == blake3_hash(b'', digest_size=32)
    
    def test_single_leaf(self):
        """Test Merkle root with single leaf"""
        leaf = blake3_hash(b"leaf1")
        root = blake3_merkle_root([leaf])
        
        assert len(root) == 32
        assert root == leaf[:32]
    
    def test_two_leaves(self):
        """Test Merkle root with two leaves"""
        leaf1 = blake3_hash(b"leaf1")
        leaf2 = blake3_hash(b"leaf2")
        
        root = blake3_merkle_root([leaf1, leaf2])
        
        assert len(root) == 32
        # Root should be hash of concatenated leaves
        expected = blake3_hash(leaf1 + leaf2, digest_size=32)
        assert root == expected
    
    def test_four_leaves(self):
        """Test Merkle root with four leaves"""
        leaves = [blake3_hash(f"leaf{i}".encode()) for i in range(4)]
        root = blake3_merkle_root(leaves)
        
        assert len(root) == 32
    
    def test_odd_number_leaves(self):
        """Test Merkle root with odd number of leaves"""
        leaves = [blake3_hash(f"leaf{i}".encode()) for i in range(3)]
        root = blake3_merkle_root(leaves)
        
        assert len(root) == 32
    
    def test_deterministic_merkle(self):
        """Test that Merkle root is deterministic"""
        leaves = [blake3_hash(f"leaf{i}".encode()) for i in range(5)]
        
        root1 = blake3_merkle_root(leaves)
        root2 = blake3_merkle_root(leaves)
        
        assert root1 == root2


class TestBlake3KDF:
    """Test BLAKE3 key derivation function"""
    
    def test_basic_kdf(self):
        """Test basic KDF"""
        key_material = b"shared_secret"
        context = "encryption"
        
        derived_key = blake3_kdf(key_material, context)
        
        assert len(derived_key) == 32
        assert isinstance(derived_key, bytes)
    
    def test_different_contexts_different_keys(self):
        """Test that different contexts produce different keys"""
        key_material = b"shared_secret"
        
        key1 = blake3_kdf(key_material, "context1")
        key2 = blake3_kdf(key_material, "context2")
        
        assert key1 != key2
    
    def test_same_context_same_key(self):
        """Test that same context produces same key (deterministic)"""
        key_material = b"shared_secret"
        context = "encryption"
        
        key1 = blake3_kdf(key_material, context)
        key2 = blake3_kdf(key_material, context)
        
        assert key1 == key2
    
    def test_custom_output_length(self):
        """Test custom output length"""
        key_material = b"secret"
        context = "test"
        
        key16 = blake3_kdf(key_material, context, output_len=16)
        key32 = blake3_kdf(key_material, context, output_len=32)
        key64 = blake3_kdf(key_material, context, output_len=64)
        
        assert len(key16) == 16
        assert len(key32) == 32
        assert len(key64) == 64


class TestBlake3Incremental:
    """Test incremental BLAKE3 hashing"""
    
    def test_incremental_basic(self):
        """Test basic incremental hashing"""
        hasher = blake3_incremental()
        hasher.update(b"hello ")
        hasher.update(b"world")
        
        digest = hasher.digest(length=64)
        
        assert len(digest) == 64
    
    def test_incremental_matches_single(self):
        """Test that incremental hashing matches single hash"""
        data1 = b"hello "
        data2 = b"world"
        
        # Incremental
        hasher = blake3_incremental()
        hasher.update(data1)
        hasher.update(data2)
        digest_incremental = hasher.digest(length=64)
        
        # Single
        digest_single = blake3_hash(data1 + data2, digest_size=64)
        
        assert digest_incremental == digest_single
    
    def test_many_updates(self):
        """Test many incremental updates"""
        hasher = blake3_incremental()
        
        for i in range(100):
            hasher.update(f"chunk{i}".encode())
        
        digest = hasher.digest(length=32)
        assert len(digest) == 32


class TestXorBytes:
    """Test XOR utility function"""
    
    def test_basic_xor(self):
        """Test basic XOR"""
        a = b"\x00\x00\x00\x00"
        b = b"\xFF\xFF\xFF\xFF"
        
        result = xor_bytes(a, b)
        
        assert result == b"\xFF\xFF\xFF\xFF"
    
    def test_xor_identity(self):
        """Test XOR with zeros is identity"""
        data = b"hello world"
        zeros = b"\x00" * len(data)
        
        result = xor_bytes(data, zeros)
        
        assert result == data
    
    def test_xor_self_is_zero(self):
        """Test XOR with self is zero"""
        data = b"test data here"
        
        result = xor_bytes(data, data)
        
        assert result == b"\x00" * len(data)
    
    def test_xor_commutative(self):
        """Test that XOR is commutative"""
        a = b"aaaaa"
        b = b"bbbbb"
        
        result1 = xor_bytes(a, b)
        result2 = xor_bytes(b, a)
        
        assert result1 == result2
    
    def test_xor_different_lengths_fails(self):
        """Test that XOR with different lengths raises error"""
        a = b"short"
        b = b"much longer string"
        
        with pytest.raises(ValueError):
            xor_bytes(a, b)
    
    def test_xor_empty(self):
        """Test XOR with empty bytes"""
        result = xor_bytes(b"", b"")
        
        assert result == b""


class TestBlake3EdgeCases:
    """Test edge cases and error conditions"""
    
    def test_hash_null_bytes(self):
        """Test hashing null bytes"""
        data = b"\x00\x00\x00\x00"
        digest = blake3_hash(data)
        
        assert len(digest) == 64
    
    def test_hash_all_ones(self):
        """Test hashing all ones"""
        data = b"\xFF" * 100
        digest = blake3_hash(data)
        
        assert len(digest) == 64
    
    def test_kdf_empty_key_material(self):
        """Test KDF with empty key material"""
        key = blake3_kdf(b"", "context")
        
        assert len(key) == 32
    
    def test_kdf_empty_context(self):
        """Test KDF with empty context"""
        key = blake3_kdf(b"secret", "")
        
        assert len(key) == 32
