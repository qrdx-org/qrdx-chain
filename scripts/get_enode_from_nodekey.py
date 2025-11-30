#!/usr/bin/env python3
"""
Derive enode URI from a Trinity nodekey file.
"""

import sys
from pathlib import Path
from eth_keys import keys

def main():
    if len(sys.argv) != 2:
        print("Usage: get_enode_from_nodekey.py <nodekey_file>")
        sys.exit(1)
    
    nodekey_path = Path(sys.argv[1])
    
    if not nodekey_path.exists():
        print(f"Error: {nodekey_path} does not exist", file=sys.stderr)
        sys.exit(1)
    
    # Read raw 32-byte private key
    with open(nodekey_path, 'rb') as f:
        private_key_bytes = f.read()
    
    if len(private_key_bytes) != 32:
        print(f"Error: Invalid nodekey size: {len(private_key_bytes)} bytes (expected 32)", file=sys.stderr)
        sys.exit(1)
    
    # Create private key object
    private_key = keys.PrivateKey(private_key_bytes)
    
    # Get public key (uncompressed, 64 bytes without 0x04 prefix)
    public_key_bytes = private_key.public_key.to_bytes()
    
    # Public key for enode is the 64 bytes hex (without 0x04 prefix)
    enode_pubkey = public_key_bytes.hex()
    
    print(enode_pubkey)

if __name__ == '__main__':
    main()
