"""
Integration test to verify post-quantum cryptography works correctly.
This tests the full stack: key generation, signing, verification, and address derivation.
"""

import sys
import os

# Add py-evm to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../py-evm'))

from eth.crypto import (
    generate_keypair,
    derive_address,
    sign_message,
    verify_message,
)
from eth.crypto.blake3_hash import blake3_hash


def test_full_crypto_stack():
    """Test the complete crypto stack."""
    print("Testing QRDX Chain Post-Quantum Cryptography...")
    print("=" * 60)
    
    # Test 1: Key generation
    print("\n1. Generating quantum-resistant key pair...")
    private_key, public_key = generate_keypair()
    print(f"   ✓ Private key size: {len(private_key.to_bytes())} bytes")
    print(f"   ✓ Public key size: {len(public_key.to_bytes())} bytes")
    
    # Test 2: Address derivation
    print("\n2. Deriving QRDX address from public key...")
    address = derive_address(public_key)
    print(f"   ✓ Address: 0x{address.hex()}")
    print(f"   ✓ Address size: {len(address)} bytes")
    
    # Test 3: Message signing
    print("\n3. Signing a message...")
    message = b"Welcome to QRDX Chain - The Quantum-Resistant Future"
    signature = sign_message(private_key, message)
    print(f"   ✓ Message: {message.decode()}")
    print(f"   ✓ Signature size: {len(signature)} bytes")
    print(f"   ✓ Signature (hex): {signature.hex()[:64]}...")
    
    # Test 4: Signature verification
    print("\n4. Verifying signature...")
    is_valid = verify_message(public_key, message, signature)
    print(f"   ✓ Signature valid: {is_valid}")
    assert is_valid, "Signature verification failed!"
    
    # Test 5: Invalid signature detection
    print("\n5. Testing invalid signature detection...")
    tampered_message = b"Tampered message"
    is_valid_tampered = verify_message(public_key, tampered_message, signature)
    print(f"   ✓ Tampered message detected: {not is_valid_tampered}")
    assert not is_valid_tampered, "Should detect tampered message!"
    
    # Test 6: BLAKE3 hashing
    print("\n6. Testing BLAKE3 quantum-resistant hashing...")
    data = b"QRDX Chain blockchain data"
    hash_256 = blake3_hash(data, output_length=32)
    hash_512 = blake3_hash(data, output_length=64)
    print(f"   ✓ BLAKE3-256: {hash_256.hex()}")
    print(f"   ✓ BLAKE3-512: {hash_512.hex()[:64]}...")
    
    # Test 7: Multiple key pairs are unique
    print("\n7. Verifying key pair uniqueness...")
    _, public_key2 = generate_keypair()
    address2 = derive_address(public_key2)
    print(f"   ✓ Address 1: 0x{address.hex()}")
    print(f"   ✓ Address 2: 0x{address2.hex()}")
    assert address != address2, "Addresses should be unique!"
    print(f"   ✓ Addresses are unique")
    
    print("\n" + "=" * 60)
    print("✅ ALL TESTS PASSED!")
    print("\nQRDX Chain post-quantum cryptography is operational.")
    print("Ready to protect assets against quantum computer attacks.")
    return True


if __name__ == "__main__":
    try:
        success = test_full_crypto_stack()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
