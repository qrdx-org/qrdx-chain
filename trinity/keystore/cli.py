"""
Trinity Keystore CLI Commands

Provides command-line interface for managing validator keystores.
"""

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Optional

from eth_utils import encode_hex

from trinity.keystore import (
    create_keystore_from_dilithium_key,
    load_dilithium_key_from_keystore,
    save_keystore,
    InvalidPassword,
    KeystoreError,
)


def configure_keystore_parser(subparser: argparse._SubParsersAction) -> None:
    """
    Configure the 'keystore' subcommand parser.
    
    Adds subcommands:
    - generate: Generate new validator keystores
    - list: List existing keystores
    - import: Import a keystore from another location
    - export-pubkey: Export public key from keystore
    """
    keystore_parser = subparser.add_parser(
        'keystore',
        help='Manage validator keystores'
    )
    
    keystore_subparsers = keystore_parser.add_subparsers(dest='keystore_command')
    
    # Generate keystores subcommand
    generate_parser = keystore_subparsers.add_parser(
        'generate',
        help='Generate new validator keystores'
    )
    generate_parser.add_argument(
        'num_validators',
        type=int,
        help='Number of validator keystores to generate'
    )
    generate_parser.add_argument(
        '--keystore-dir',
        type=Path,
        default=Path.home() / '.trinity' / 'keystores',
        help='Directory to store keystores (default: ~/.trinity/keystores)'
    )
    generate_parser.add_argument(
        '--password',
        type=str,
        help='Password to encrypt keystores (WARNING: Insecure! Use --password-env or interactive prompt)'
    )
    generate_parser.add_argument(
        '--password-env',
        action='store_true',
        help='Read password from QRDX_KEYSTORE_PASSWORD environment variable'
    )
    generate_parser.set_defaults(func=cmd_generate)
    
    # List keystores subcommand
    list_parser = keystore_subparsers.add_parser(
        'list',
        help='List existing validator keystores'
    )
    list_parser.add_argument(
        '--keystore-dir',
        type=Path,
        default=Path.home() / '.trinity' / 'keystores',
        help='Directory containing keystores (default: ~/.trinity/keystores)'
    )
    list_parser.set_defaults(func=cmd_list)
    
    # Import keystore subcommand
    import_parser = keystore_subparsers.add_parser(
        'import',
        help='Import a keystore from another location'
    )
    import_parser.add_argument(
        'source',
        type=Path,
        help='Source keystore file to import'
    )
    import_parser.add_argument(
        '--keystore-dir',
        type=Path,
        default=Path.home() / '.trinity' / 'keystores',
        help='Destination directory (default: ~/.trinity/keystores)'
    )
    import_parser.set_defaults(func=cmd_import)
    
    # Export public key subcommand
    export_pubkey_parser = keystore_subparsers.add_parser(
        'export-pubkey',
        help='Export public key from keystore (no password required)'
    )
    export_pubkey_parser.add_argument(
        'keystore_file',
        type=Path,
        help='Keystore file to export public key from'
    )
    export_pubkey_parser.add_argument(
        '--format',
        choices=['hex', 'raw'],
        default='hex',
        help='Output format (default: hex)'
    )
    export_pubkey_parser.set_defaults(func=cmd_export_pubkey)


def cmd_generate(args: argparse.Namespace, trinity_config: Optional[object] = None) -> None:
    """Generate new validator keystores."""
    from eth.crypto import generate_dilithium_keypair
    
    num_validators = args.num_validators
    keystore_dir = Path(args.keystore_dir)
    
    if num_validators < 1:
        print("Error: num_validators must be at least 1", file=sys.stderr)
        sys.exit(1)
    
    # Get password
    if args.password:
        print("⚠️  WARNING: Using --password flag is insecure! Password may be visible in process list.", file=sys.stderr)
        password = args.password
    elif args.password_env:
        password = os.environ.get("QRDX_KEYSTORE_PASSWORD")
        if not password:
            print("Error: QRDX_KEYSTORE_PASSWORD environment variable not set", file=sys.stderr)
            sys.exit(1)
    else:
        # Interactive password prompt
        print("Enter password to encrypt validator keys:")
        password = getpass.getpass("Password: ")
        password_confirm = getpass.getpass("Confirm password: ")
        
        if password != password_confirm:
            print("Error: Passwords do not match", file=sys.stderr)
            sys.exit(1)
        
        if len(password) < 12:
            print("Error: Password must be at least 12 characters", file=sys.stderr)
            sys.exit(1)
    
    # Create keystore directory
    keystore_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Generating {num_validators} validator keypairs...")
    print(f"Keystore directory: {keystore_dir}")
    print()
    
    keystores_created = []
    
    for i in range(num_validators):
        print(f"Generating validator {i}...", end=" ", flush=True)
        
        # Generate Dilithium keypair
        private_key, public_key = generate_dilithium_keypair()
        priv_bytes = private_key.to_bytes()
        pub_bytes = public_key.to_bytes()
        
        # Create keystore
        keystore = create_keystore_from_dilithium_key(
            priv_bytes,
            pub_bytes,
            password,
            path=f"m/12381/3600/{i}/0/0",  # EIP-2334 derivation path
            description=f"QRDX validator {i} signing key"
        )
        
        # Save keystore
        keystore_path = save_keystore(keystore, keystore_dir)
        
        keystores_created.append((i, keystore_path, encode_hex(pub_bytes[:16])))
        
        print(f"✓ {keystore_path.name}")
    
    print()
    print("=" * 80)
    print("VALIDATOR KEYPAIRS GENERATED SUCCESSFULLY")
    print("=" * 80)
    print()
    
    for validator_idx, keystore_path, pubkey_prefix in keystores_created:
        print(f"Validator {validator_idx}:")
        print(f"  Keystore: {keystore_path}")
        print(f"  Public Key: {pubkey_prefix}...")
        print()
    
    print("=" * 80)
    print("⚠️  CRITICAL SECURITY REMINDERS")
    print("=" * 80)
    print("  1. BACK UP these keystore files to secure location")
    print("  2. REMEMBER your password - it CANNOT be recovered")
    print("  3. NEVER share keystores or password")
    print("  4. Store backups in multiple secure locations")


def cmd_list(args: argparse.Namespace, trinity_config: Optional[object] = None) -> None:
    """List existing validator keystores."""
    keystore_dir = Path(args.keystore_dir)
    
    if not keystore_dir.exists():
        print(f"Keystore directory does not exist: {keystore_dir}", file=sys.stderr)
        sys.exit(1)
    
    keystores = sorted(keystore_dir.glob("*.json"))
    
    if not keystores:
        print(f"No keystores found in {keystore_dir}")
        return
    
    print(f"Found {len(keystores)} keystore(s) in {keystore_dir}")
    print()
    print("=" * 80)
    
    for ks_path in keystores:
        try:
            with open(ks_path) as f:
                keystore = json.load(f)
            
            uuid = keystore.get('uuid', 'N/A')
            pubkey = keystore.get('pubkey', 'N/A')
            path = keystore.get('path', 'N/A')
            description = keystore.get('description', 'N/A')
            version = keystore.get('version', 'N/A')
            
            # Get file size
            size = ks_path.stat().st_size
            
            print(f"Keystore: {ks_path.name}")
            print(f"  UUID: {uuid}")
            print(f"  Version: {version}")
            print(f"  Public Key: {pubkey[:32]}... (truncated)")
            print(f"  Path: {path}")
            print(f"  Description: {description}")
            print(f"  Size: {size:,} bytes")
            print()
            
        except Exception as e:
            print(f"Error reading {ks_path.name}: {e}", file=sys.stderr)
            print()


def cmd_import(args: argparse.Namespace, trinity_config: Optional[object] = None) -> None:
    """Import a keystore from another location."""
    import shutil
    
    source = Path(args.source)
    dest_dir = Path(args.keystore_dir)
    
    if not source.exists():
        print(f"Error: Source keystore not found: {source}", file=sys.stderr)
        sys.exit(1)
    
    if not source.is_file():
        print(f"Error: Source is not a file: {source}", file=sys.stderr)
        sys.exit(1)
    
    # Validate it's a valid keystore
    try:
        with open(source) as f:
            keystore = json.load(f)
        
        # Basic validation
        if 'version' not in keystore or 'crypto' not in keystore:
            print(f"Error: Invalid keystore format in {source}", file=sys.stderr)
            sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {source}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading {source}: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Create destination directory
    dest_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy file
    dest_path = dest_dir / source.name
    
    if dest_path.exists():
        print(f"Keystore already exists: {dest_path}")
        response = input("Overwrite? (yes/no): ")
        if response.lower() not in ('yes', 'y'):
            print("Import cancelled")
            return
    
    shutil.copy2(source, dest_path)
    
    # Set secure permissions
    os.chmod(dest_path, 0o600)
    
    print(f"✓ Keystore imported successfully")
    print(f"  Source: {source}")
    print(f"  Destination: {dest_path}")
    print(f"  UUID: {keystore.get('uuid', 'N/A')}")
    print(f"  Public Key: {keystore.get('pubkey', 'N/A')[:32]}...")


def cmd_export_pubkey(args: argparse.Namespace, trinity_config: Optional[object] = None) -> None:
    """Export public key from keystore (no password required)."""
    keystore_path = Path(args.keystore_file)
    
    if not keystore_path.exists():
        print(f"Error: Keystore not found: {keystore_path}", file=sys.stderr)
        sys.exit(1)
    
    try:
        with open(keystore_path) as f:
            keystore = json.load(f)
        
        pubkey_hex = keystore.get('pubkey')
        if not pubkey_hex:
            print(f"Error: No public key found in keystore", file=sys.stderr)
            sys.exit(1)
        
        if args.format == 'hex':
            print(f"0x{pubkey_hex}")
        else:  # raw
            pub_bytes = bytes.fromhex(pubkey_hex)
            sys.stdout.buffer.write(pub_bytes)
            
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {keystore_path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
