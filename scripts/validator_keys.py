#!/usr/bin/env python3
"""
Validator Key Management Utility

Load and manage validator keys for QR-PoS testnet.

Usage:
    # Load validator key
    python3 scripts/validator_keys.py load --keystore ./testnet/validators/validator_0.json
    
    # Sign a message
    python3 scripts/validator_keys.py sign --keystore ./testnet/validators/validator_0.json --message "Hello"
    
    # Verify signature
    python3 scripts/validator_keys.py verify --keystore ./testnet/validators/validator_0.json --message "Hello" --signature <hex>
    
    # Show validator info
    python3 scripts/validator_keys.py info --keystore ./testnet/validators/validator_0.json
"""

import argparse
import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from trinity.crypto.pq.dilithium import DilithiumPrivateKey, DilithiumPublicKey
from trinity.crypto.pq.addresses import generate_pq_address, encode_pq_address


def load_keystore(keystore_path: Path) -> dict:
    """Load keystore file"""
    with open(keystore_path, 'r') as f:
        return json.load(f)


def load_private_key(keystore_path: Path) -> DilithiumPrivateKey:
    """Load private key from keystore"""
    keystore = load_keystore(keystore_path)
    
    # Extract keys
    private_key_hex = keystore['crypto']['ciphertext']
    public_key_hex = keystore['public_key']
    
    private_key_bytes = bytes.fromhex(private_key_hex)
    public_key_bytes = bytes.fromhex(public_key_hex)
    
    # Create private key object
    return DilithiumPrivateKey.from_bytes(private_key_bytes, public_key_bytes)


def cmd_info(args):
    """Show validator information"""
    keystore = load_keystore(args.keystore)
    
    print("Validator Information")
    print("=" * 60)
    
    if 'validator_index' in keystore:
        print(f"Validator Index: {keystore['validator_index']}")
    elif 'account_index' in keystore:
        print(f"Account Index: {keystore['account_index']}")
    
    print(f"PQ Address: {keystore['pq_address']}")
    print(f"Public Key: {keystore['public_key'][:32]}...")
    print(f"Public Key Size: {len(keystore['public_key']) // 2} bytes")
    
    # Verify address derivation
    pubkey_bytes = bytes.fromhex(keystore['public_key'])
    pubkey = DilithiumPublicKey.from_bytes(pubkey_bytes)
    derived_address = generate_pq_address(pubkey)
    encoded_address = encode_pq_address(derived_address)
    
    print(f"\nDerived Address: {encoded_address}")
    print(f"Address Match: {encoded_address == keystore['pq_address']}")


def cmd_sign(args):
    """Sign a message"""
    privkey = load_private_key(args.keystore)
    
    message = args.message.encode('utf-8')
    signature = privkey.sign(message)
    
    print("Message signed successfully")
    print("=" * 60)
    print(f"Message: {args.message}")
    print(f"Signature (hex): {signature.hex()}")
    print(f"Signature size: {len(signature)} bytes")


def cmd_verify(args):
    """Verify a signature"""
    keystore = load_keystore(args.keystore)
    
    # Load public key
    public_key_bytes = bytes.fromhex(keystore['public_key'])
    pubkey = DilithiumPublicKey.from_bytes(public_key_bytes)
    
    # Verify
    message = args.message.encode('utf-8')
    signature = bytes.fromhex(args.signature)
    
    is_valid = pubkey.verify(message, signature)
    
    print("Signature Verification")
    print("=" * 60)
    print(f"Message: {args.message}")
    print(f"Signature: {args.signature[:32]}...")
    print(f"Valid: {is_valid}")
    
    if is_valid:
        print("\n✓ Signature is VALID")
        sys.exit(0)
    else:
        print("\n✗ Signature is INVALID")
        sys.exit(1)


def cmd_export(args):
    """Export keys in different formats"""
    keystore = load_keystore(args.keystore)
    privkey = load_private_key(args.keystore)
    
    output = {}
    
    if args.format == 'json':
        output = {
            'pq_address': keystore['pq_address'],
            'public_key': keystore['public_key'],
            'private_key': keystore['crypto']['ciphertext'],
        }
        print(json.dumps(output, indent=2))
    
    elif args.format == 'hex':
        print(f"Private Key: {keystore['crypto']['ciphertext']}")
        print(f"Public Key:  {keystore['public_key']}")
        print(f"PQ Address:  {keystore['pq_address']}")
    
    elif args.format == 'raw':
        # Write raw bytes to files
        output_dir = Path(args.output) if args.output else Path('.')
        output_dir.mkdir(parents=True, exist_ok=True)
        
        priv_file = output_dir / 'private_key.bin'
        pub_file = output_dir / 'public_key.bin'
        addr_file = output_dir / 'address.txt'
        
        with open(priv_file, 'wb') as f:
            f.write(bytes.fromhex(keystore['crypto']['ciphertext']))
        
        with open(pub_file, 'wb') as f:
            f.write(bytes.fromhex(keystore['public_key']))
        
        with open(addr_file, 'w') as f:
            f.write(keystore['pq_address'])
        
        print(f"Exported to {output_dir}/")
        print(f"  - private_key.bin ({priv_file.stat().st_size} bytes)")
        print(f"  - public_key.bin ({pub_file.stat().st_size} bytes)")
        print(f"  - address.txt")


def cmd_generate(args):
    """Generate a new validator key"""
    print("Generating new validator key...")
    
    # Generate key pair
    privkey = DilithiumPrivateKey.generate()
    pubkey = privkey.public_key()
    pq_address = generate_pq_address(pubkey)
    
    # Create keystore
    keystore = {
        "version": 1,
        "pq_address": encode_pq_address(pq_address),
        "public_key": privkey.public_key_bytes.hex(),
        "crypto": {
            "cipher": "plain",
            "ciphertext": privkey._key_bytes.hex(),
        }
    }
    
    # Save to file
    output_path = Path(args.output) if args.output else Path('validator_new.json')
    with open(output_path, 'w') as f:
        json.dump(keystore, f, indent=2)
    
    print("\n✓ Key generated successfully!")
    print("=" * 60)
    print(f"PQ Address: {keystore['pq_address']}")
    print(f"Saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Validator key management utility',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show validator information')
    info_parser.add_argument('--keystore', type=Path, required=True,
                            help='Path to validator keystore file')
    
    # Sign command
    sign_parser = subparsers.add_parser('sign', help='Sign a message')
    sign_parser.add_argument('--keystore', type=Path, required=True,
                            help='Path to validator keystore file')
    sign_parser.add_argument('--message', type=str, required=True,
                            help='Message to sign')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify a signature')
    verify_parser.add_argument('--keystore', type=Path, required=True,
                              help='Path to validator keystore file')
    verify_parser.add_argument('--message', type=str, required=True,
                              help='Original message')
    verify_parser.add_argument('--signature', type=str, required=True,
                              help='Signature to verify (hex)')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export keys')
    export_parser.add_argument('--keystore', type=Path, required=True,
                              help='Path to validator keystore file')
    export_parser.add_argument('--format', choices=['json', 'hex', 'raw'],
                              default='json', help='Export format')
    export_parser.add_argument('--output', type=str,
                              help='Output directory (for raw format)')
    
    # Generate command
    gen_parser = subparsers.add_parser('generate', help='Generate new validator key')
    gen_parser.add_argument('--output', type=str,
                           help='Output file path (default: validator_new.json)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Execute command
    if args.command == 'info':
        cmd_info(args)
    elif args.command == 'sign':
        cmd_sign(args)
    elif args.command == 'verify':
        cmd_verify(args)
    elif args.command == 'export':
        cmd_export(args)
    elif args.command == 'generate':
        cmd_generate(args)


if __name__ == '__main__':
    main()
