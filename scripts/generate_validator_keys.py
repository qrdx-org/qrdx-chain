#!/usr/bin/env python3
"""
Generate validator keys for QRDX QR-PoS consensus.

Generates Dilithium3 (ML-DSA-65) quantum-resistant key pairs for validators.
"""

import sys
import os
import argparse
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from eth.crypto import generate_dilithium_keypair


def generate_validator_key(validator_index: int, output_dir: Path) -> None:
    """Generate and save a validator key pair."""
    print(f"Generating validator {validator_index} keys...")
    
    # Generate key pair
    private_key, public_key = generate_dilithium_keypair()
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save private key (3,856 bytes)
    private_key_file = output_dir / f"validator_{validator_index}_private.key"
    with open(private_key_file, 'wb') as f:
        f.write(private_key.to_bytes())
    
    # Save public key (1,952 bytes)
    public_key_file = output_dir / f"validator_{validator_index}_public.key"
    with open(public_key_file, 'wb') as f:
        f.write(public_key.to_bytes())
    
    print(f"  Private key: {private_key_file}")
    print(f"  Public key:  {public_key_file}")
    print(f"  Private key size: {len(private_key.to_bytes())} bytes")
    print(f"  Public key size:  {len(public_key.to_bytes())} bytes")


def main():
    parser = argparse.ArgumentParser(
        description="Generate QRDX validator keys (Dilithium3/ML-DSA-65)"
    )
    parser.add_argument(
        'count',
        type=int,
        help='Number of validator keys to generate'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path.cwd() / 'validator_keys',
        help='Output directory for keys (default: ./validator_keys)'
    )
    parser.add_argument(
        '--start-index',
        type=int,
        default=0,
        help='Starting validator index (default: 0)'
    )
    
    args = parser.parse_args()
    
    print(f"Generating {args.count} validator key pairs...")
    print(f"Output directory: {args.output_dir}")
    print()
    
    for i in range(args.count):
        validator_index = args.start_index + i
        generate_validator_key(validator_index, args.output_dir)
        print()
    
    print(f"✓ Generated {args.count} validator key pairs in {args.output_dir}")
    print()
    print("Key sizes:")
    print("  Private key: 3,856 bytes (Dilithium3 secret key)")
    print("  Public key:  1,952 bytes (Dilithium3 public key)")
    print("  Signature:   3,309 bytes (Dilithium3 signature)")


if __name__ == '__main__':
    main()
