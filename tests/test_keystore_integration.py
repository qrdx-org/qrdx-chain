#!/usr/bin/env python3
"""Test keystore integration with validator component."""

import os
import sys
from pathlib import Path

# Set environment variables
os.environ["QRDX_KEYSTORE_PASSWORD"] = "testnet-password-123"
os.environ["QRDX_KEYSTORE_DIR"] = "/tmp/qrdx-validator-keys"
os.environ["QRDX_NUM_VALIDATORS"] = "3"

print("Testing keystore integration...")
print(f"Keystore directory: {os.environ['QRDX_KEYSTORE_DIR']}")
print()

try:
    # Test loading keystores
    from trinity.keystore import load_dilithium_key_from_keystore
    from pathlib import Path
    import json
    
    keystore_dir = Path(os.environ["QRDX_KEYSTORE_DIR"])
    
    print("=" * 60)
    print("Testing keystore loading for each validator...")
    print("=" * 60)
    
    for validator_index in range(3):
        print(f"\nValidator {validator_index}:")
        
        # Find keystore by derivation path
        keystore_path = None
        for ks_file in keystore_dir.glob("*.json"):
            with open(ks_file) as f:
                ks_data = json.load(f)
                if ks_data.get("path") == f"m/12381/3600/{validator_index}/0/0":
                    keystore_path = ks_file
                    break
        
        if not keystore_path:
            print(f"  ✗ No keystore found for derivation path m/12381/3600/{validator_index}/0/0")
            sys.exit(1)
        
        print(f"  Keystore: {keystore_path.name}")
        
        # Load the key
        password = os.environ["QRDX_KEYSTORE_PASSWORD"]
        priv_bytes, pub_bytes = load_dilithium_key_from_keystore(keystore_path, password)
        
        print(f"  ✓ Loaded successfully")
        print(f"    Private key: {len(priv_bytes)} bytes")
        print(f"    Public key: {len(pub_bytes)} bytes")
        print(f"    Public key hex: {pub_bytes.hex()[:32]}...")
    
    print("\n" + "=" * 60)
    print("✅ All validator keystores loaded successfully!")
    print("=" * 60)
    print()
    
    # Test signature creation with loaded key
    print("Testing signature creation...")
    from eth.crypto import DilithiumPrivateKey, DilithiumPublicKey
    
    # Load validator 0 key
    for ks_file in keystore_dir.glob("*.json"):
        with open(ks_file) as f:
            ks_data = json.load(f)
            if ks_data.get("path") == "m/12381/3600/0/0/0":
                keystore_path = ks_file
                break
    
    priv_bytes, pub_bytes = load_dilithium_key_from_keystore(keystore_path, password)
    private_key = DilithiumPrivateKey(priv_bytes, pub_bytes)
    public_key = DilithiumPublicKey(pub_bytes)
    
    # Create and verify signature
    message = b"Test message for signing"
    signature = private_key.sign(message)
    
    print(f"  Message: {message.decode()}")
    print(f"  Signature size: {len(signature)} bytes")
    
    # Verify signature
    is_valid = public_key.verify(message, signature)
    
    if is_valid:
        print(f"  ✓ Signature verified successfully!")
    else:
        print(f"  ✗ Signature verification failed!")
        sys.exit(1)
    
    print()
    print("=" * 60)
    print("✅ KEYSTORE INTEGRATION TEST PASSED")
    print("=" * 60)
    print()
    print("Ready to start testnet with encrypted keystores!")
    
except Exception as e:
    print(f"\n❌ Error: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
