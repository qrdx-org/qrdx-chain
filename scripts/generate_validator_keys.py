#!/usr/bin/env python3
"""
QRDX Validator Key Generator

Generates Dilithium ML-DSA-65 keypairs and stores them in EIP-2335 encrypted keystores.
This is the SECURE version that replaces the old unencrypted key storage.

Usage:
    # Interactive password prompt (RECOMMENDED)
    python3 scripts/generate_validator_keys.py 3 --keystore-dir ./keystores
    
    # With environment variable password
    export QRDX_KEYSTORE_PASSWORD="mypassword"
    python3 scripts/generate_validator_keys.py 3 --keystore-dir ./keystores --password-env
"""

import argparse
import sys
import getpass
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from eth.crypto import generate_dilithium_keypair
from trinity.keystore import create_keystore_from_dilithium_key, save_keystore


def generate_keys(
    num_validators: int,
    keystore_dir: Path,
    password: str,
    start_index: int = 0
) -> None:
    """Generate validator keypairs and save to encrypted keystores."""
    keystore_dir = Path(keystore_dir)
    keystore_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Generating {num_validators} validator keypairs...")
    print(f"Keystore directory: {keystore_dir.absolute()}")
    print()
    
    keystores_created = []
    
    for i in range(start_index, start_index + num_validators):
        print(f"Generating validator {i}...", end=" ", flush=True)
        private_key, public_key = generate_dilithium_keypair()
        
        # Create encrypted keystore
        keystore = create_keystore_from_dilithium_key(
            private_key.to_bytes(),
            public_key.to_bytes(),
            password,
            path=f"m/12381/3600/{i}/0/0",
            description=f"QRDX validator {i} signing key"
        )
        
        keystore_path = save_keystore(keystore, keystore_dir)
        keystores_created.append((i, keystore_path, public_key.to_bytes()))
        print(f"✓ {keystore_path.name}")
    
    print()
    print("=" * 80)
    print("VALIDATOR KEYPAIRS GENERATED SUCCESSFULLY")
    print("=" * 80)
    print()
    
    for validator_idx, keystore_path, pubkey in keystores_created:
        pubkey_preview = pubkey[:16].hex() + "..."
        print(f"Validator {validator_idx}:")
        print(f"  Keystore: {keystore_path}")
        print(f"  Public Key: 0x{pubkey_preview}")
        print()
    
    print("=" * 80)
    print("⚠️  CRITICAL SECURITY REMINDERS")
    print("=" * 80)
    print("  1. BACK UP these keystore files to secure location")
    print("  2. REMEMBER your password - it CANNOT be recovered")
    print("  3. NEVER share keystores or password")
    print("  4. Store backups in multiple secure locations")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Generate Dilithium keypairs for QRDX validators (EIP-2335 encrypted)"
    )
    
    parser.add_argument(
        "count",
        type=int,
        help="Number of validator keypairs to generate"
    )
    
    parser.add_argument(
        "--keystore-dir",
        type=str,
        default="./keystores",
        help="Directory to save keystores (default: ./keystores)"
    )
    
    parser.add_argument(
        "--password",
        type=str,
        help="Password (NOT RECOMMENDED - use interactive prompt)"
    )
    
    parser.add_argument(
        "--password-env",
        action="store_true",
        help="Read password from QRDX_KEYSTORE_PASSWORD env var"
    )
    
    parser.add_argument(
        "--start-index",
        type=int,
        default=0,
        help="Starting validator index (default: 0)"
    )
    
    args = parser.parse_args()
    
    # Get password
    if args.password:
        password = args.password
        print("⚠️  WARNING: Command-line password is insecure")
        print()
    elif args.password_env:
        import os
        password = os.environ.get("QRDX_KEYSTORE_PASSWORD")
        if not password:
            print("ERROR: QRDX_KEYSTORE_PASSWORD not set")
            sys.exit(1)
    else:
        print("Enter password to encrypt validator keys:")
        print("⚠️  You will need this to run your validator")
        print()
        password = getpass.getpass("Password: ")
        password_confirm = getpass.getpass("Confirm: ")
        
        if password != password_confirm:
            print("ERROR: Passwords do not match")
            sys.exit(1)
        
        if len(password) < 12:
            print("WARNING: Password < 12 characters")
            if input("Continue? (yes/no): ").lower() != "yes":
                sys.exit(1)
        print()
    
    # Generate
    try:
        generate_keys(args.count, args.keystore_dir, password, args.start_index)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
