#!/usr/bin/env python3
"""
Migration script to convert old pickle-based validator keys to EIP-2335 keystores.

This script:
1. Scans for pickle files (validator-*.key) in a directory
2. Prompts for a password to encrypt the keystores
3. Creates encrypted EIP-2335 keystores for each validator
4. Optionally backs up the old pickle files

Usage:
    python3 scripts/migrate_validator_keys.py [options]

Example:
    python3 scripts/migrate_validator_keys.py \
        --pickle-dir /tmp/qrdx-validator-keys \
        --keystore-dir /tmp/qrdx-validator-keys \
        --backup
"""

import argparse
import getpass
import os
import pickle
import shutil
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path to import trinity modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from eth_utils import encode_hex
from trinity.keystore import create_keystore_from_dilithium_key, save_keystore


def find_pickle_keys(pickle_dir: Path) -> list:
    """Find all pickle key files in directory."""
    pickle_files = []
    
    for file in pickle_dir.glob("validator-*.key"):
        # Extract validator index from filename
        try:
            index = int(file.stem.split('-')[1])
            pickle_files.append((index, file))
        except (IndexError, ValueError):
            print(f"Warning: Skipping file with unexpected name format: {file.name}", file=sys.stderr)
    
    return sorted(pickle_files, key=lambda x: x[0])


def load_pickle_key(pickle_file: Path) -> tuple:
    """Load private and public keys from pickle file."""
    try:
        with open(pickle_file, 'rb') as f:
            priv_bytes, pub_bytes = pickle.load(f)
        return priv_bytes, pub_bytes
    except Exception as e:
        raise RuntimeError(f"Failed to load {pickle_file}: {e}")


def backup_pickle_file(pickle_file: Path, backup_dir: Path) -> Path:
    """Create a backup of the pickle file."""
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_dir / pickle_file.name
    shutil.copy2(pickle_file, backup_path)
    return backup_path


def migrate_keys(pickle_dir: Path, keystore_dir: Path, password: str, backup: bool = False) -> None:
    """Migrate all pickle keys to encrypted keystores."""
    
    # Find all pickle files
    pickle_files = find_pickle_keys(pickle_dir)
    
    if not pickle_files:
        print(f"No validator pickle files found in {pickle_dir}")
        print("Looking for files matching pattern: validator-*.key")
        sys.exit(1)
    
    print(f"Found {len(pickle_files)} validator key(s) to migrate")
    print()
    
    # Create keystore directory
    keystore_dir.mkdir(parents=True, exist_ok=True)
    
    # Create backup directory if requested
    if backup:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = pickle_dir / f"backup_{timestamp}"
        print(f"Backup directory: {backup_dir}")
    else:
        backup_dir = None
    
    print(f"Keystore directory: {keystore_dir}")
    print()
    print("=" * 80)
    print("STARTING MIGRATION")
    print("=" * 80)
    print()
    
    migrated = []
    errors = []
    
    for validator_index, pickle_file in pickle_files:
        try:
            print(f"Migrating validator {validator_index}...", end=" ", flush=True)
            
            # Load keys from pickle file
            priv_bytes, pub_bytes = load_pickle_key(pickle_file)
            
            # Create keystore
            keystore = create_keystore_from_dilithium_key(
                priv_bytes,
                pub_bytes,
                password,
                path=f"m/12381/3600/{validator_index}/0/0",
                description=f"QRDX validator {validator_index} signing key (migrated)"
            )
            
            # Save keystore
            keystore_path = save_keystore(keystore, keystore_dir)
            
            # Backup old pickle file if requested
            if backup_dir:
                backup_path = backup_pickle_file(pickle_file, backup_dir)
            
            migrated.append((validator_index, pickle_file, keystore_path))
            print(f"✓ {keystore_path.name}")
            
        except Exception as e:
            errors.append((validator_index, pickle_file, str(e)))
            print(f"✗ FAILED: {e}")
    
    print()
    print("=" * 80)
    print("MIGRATION SUMMARY")
    print("=" * 80)
    print()
    
    if migrated:
        print(f"✓ Successfully migrated {len(migrated)} validator(s):")
        print()
        for validator_index, pickle_file, keystore_path in migrated:
            print(f"  Validator {validator_index}:")
            print(f"    Source: {pickle_file}")
            print(f"    Keystore: {keystore_path}")
            print()
    
    if errors:
        print(f"✗ Failed to migrate {len(errors)} validator(s):")
        print()
        for validator_index, pickle_file, error in errors:
            print(f"  Validator {validator_index}:")
            print(f"    Source: {pickle_file}")
            print(f"    Error: {error}")
            print()
    
    if backup_dir and migrated:
        print("=" * 80)
        print("BACKUP INFORMATION")
        print("=" * 80)
        print()
        print(f"Original pickle files backed up to: {backup_dir}")
        print("You can delete the backup after verifying the migration succeeded.")
        print()
    
    if migrated and not errors:
        print("=" * 80)
        print("⚠️  NEXT STEPS")
        print("=" * 80)
        print()
        print("1. TEST the new keystores before deleting pickle files:")
        print(f"   trinity keystore list --keystore-dir {keystore_dir}")
        print()
        print("2. VERIFY validator startup works with new keystores:")
        print("   Set QRDX_KEYSTORE_PASSWORD environment variable")
        print("   Start testnet and verify blocks are signed")
        print()
        print("3. BACK UP the keystore directory to secure location")
        print()
        print("4. DELETE the old pickle files after successful testing")
        if not backup:
            print("   (Consider re-running with --backup flag first)")
        print()
    
    if errors:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Migrate validator keys from pickle files to EIP-2335 keystores",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Migrate keys in the same directory
  python3 scripts/migrate_validator_keys.py \\
      --pickle-dir /tmp/qrdx-validator-keys \\
      --keystore-dir /tmp/qrdx-validator-keys \\
      --backup

  # Migrate to a different directory
  python3 scripts/migrate_validator_keys.py \\
      --pickle-dir /tmp/old-keys \\
      --keystore-dir /home/validator/keystores \\
      --password-env

Security Notes:
  - Always use --backup flag to keep a copy of original keys
  - Test the new keystores before deleting pickle files
  - Store keystores and backups in multiple secure locations
  - Use a strong password (minimum 12 characters)
        """
    )
    
    parser.add_argument(
        '--pickle-dir',
        type=Path,
        default=Path('/tmp/qrdx-validator-keys'),
        help='Directory containing pickle key files (default: /tmp/qrdx-validator-keys)'
    )
    
    parser.add_argument(
        '--keystore-dir',
        type=Path,
        default=Path('/tmp/qrdx-validator-keys'),
        help='Directory to store encrypted keystores (default: /tmp/qrdx-validator-keys)'
    )
    
    parser.add_argument(
        '--password',
        type=str,
        help='Password to encrypt keystores (WARNING: Insecure! Use --password-env or interactive prompt)'
    )
    
    parser.add_argument(
        '--password-env',
        action='store_true',
        help='Read password from QRDX_KEYSTORE_PASSWORD environment variable'
    )
    
    parser.add_argument(
        '--backup',
        action='store_true',
        help='Create backup of original pickle files before migration'
    )
    
    args = parser.parse_args()
    
    # Validate directories
    if not args.pickle_dir.exists():
        print(f"Error: Pickle directory does not exist: {args.pickle_dir}", file=sys.stderr)
        sys.exit(1)
    
    # Get password
    if args.password:
        print("⚠️  WARNING: Using --password flag is insecure!", file=sys.stderr)
        print("Password may be visible in process list and shell history.", file=sys.stderr)
        print()
        password = args.password
    elif args.password_env:
        password = os.environ.get("QRDX_KEYSTORE_PASSWORD")
        if not password:
            print("Error: QRDX_KEYSTORE_PASSWORD environment variable not set", file=sys.stderr)
            sys.exit(1)
    else:
        # Interactive password prompt
        print("=" * 80)
        print("VALIDATOR KEY MIGRATION")
        print("=" * 80)
        print()
        print(f"Source directory: {args.pickle_dir}")
        print(f"Destination directory: {args.keystore_dir}")
        print(f"Backup enabled: {args.backup}")
        print()
        print("Enter password to encrypt validator keys:")
        print("(Password must be at least 12 characters)")
        print()
        
        password = getpass.getpass("Password: ")
        password_confirm = getpass.getpass("Confirm password: ")
        
        if password != password_confirm:
            print("Error: Passwords do not match", file=sys.stderr)
            sys.exit(1)
        
        if len(password) < 12:
            print("Error: Password must be at least 12 characters", file=sys.stderr)
            sys.exit(1)
        
        print()
    
    # Perform migration
    migrate_keys(args.pickle_dir, args.keystore_dir, password, args.backup)


if __name__ == '__main__':
    main()
