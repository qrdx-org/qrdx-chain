"""
EIP-2335 Compliant Keystore for Dilithium Quantum-Resistant Keys

This module implements the EIP-2335 BLS12-381 keystore standard adapted for
Dilithium ML-DSA-65 post-quantum cryptographic keys used in QRDX Chain.

Key Features:
- AES-128-CTR encryption
- Scrypt key derivation (memory-hard)
- Password protection
- JSON format with checksum
- UUID-based keystore identification

Note: While EIP-2335 was designed for BLS12-381 keys, the encryption and
serialization format is algorithm-agnostic and works well for Dilithium keys.
"""

import json
import uuid
import hashlib
import secrets
from typing import Dict, Any, Tuple
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util import Counter


# EIP-2335 Constants
CIPHER = "aes-128-ctr"
KDF = "scrypt"
SCRYPT_DKLEN = 32  # Derived key length
SCRYPT_N = 262144  # CPU/memory cost (2^18)
SCRYPT_R = 8       # Block size
SCRYPT_P = 1       # Parallelization

# Dilithium key sizes
DILITHIUM_PRIVATE_KEY_SIZE = 4000  # Approximate for ML-DSA-65
DILITHIUM_PUBLIC_KEY_SIZE = 1952   # Approximate for ML-DSA-65


class KeystoreError(Exception):
    """Base exception for keystore operations"""
    pass


class InvalidPassword(KeystoreError):
    """Raised when password verification fails"""
    pass


class InvalidKeystore(KeystoreError):
    """Raised when keystore format is invalid"""
    pass


def encrypt_key(
    private_key_bytes: bytes,
    password: str,
    kdf_salt: bytes = None,
    iv: bytes = None
) -> Dict[str, Any]:
    """
    Encrypt a Dilithium private key using EIP-2335 format.
    
    Args:
        private_key_bytes: Raw private key bytes (4000 bytes for ML-DSA-65)
        password: Password for encryption
        kdf_salt: Salt for key derivation (generated if None)
        iv: Initialization vector for AES (generated if None)
    
    Returns:
        Dictionary containing encrypted keystore data
    
    Raises:
        KeystoreError: If encryption fails
    """
    # Generate random salt and IV if not provided
    if kdf_salt is None:
        kdf_salt = secrets.token_bytes(32)
    if iv is None:
        iv = secrets.token_bytes(16)
    
    # Derive encryption key using Scrypt
    derived_key = scrypt(
        password.encode('utf-8'),
        salt=kdf_salt,
        key_len=SCRYPT_DKLEN,
        N=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P
    )
    
    # Split derived key: first 16 bytes for AES, last 16 bytes for checksum
    aes_key = derived_key[:16]
    checksum_key = derived_key[16:]
    
    # Encrypt private key with AES-128-CTR
    counter = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))
    cipher = AES.new(aes_key, AES.MODE_CTR, counter=counter)
    ciphertext = cipher.encrypt(private_key_bytes)
    
    # Compute checksum: SHA256(checksum_key || ciphertext)
    checksum_data = checksum_key + ciphertext
    checksum = hashlib.sha256(checksum_data).digest()
    
    # Build keystore structure
    keystore = {
        "crypto": {
            "kdf": {
                "function": KDF,
                "params": {
                    "dklen": SCRYPT_DKLEN,
                    "n": SCRYPT_N,
                    "r": SCRYPT_R,
                    "p": SCRYPT_P,
                    "salt": kdf_salt.hex()
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": checksum[:16].hex()  # First 16 bytes of checksum
            },
            "cipher": {
                "function": CIPHER,
                "params": {
                    "iv": iv.hex()
                },
                "message": ciphertext.hex()
            }
        },
        "description": "QRDX validator signing key (Dilithium ML-DSA-65)",
        "pubkey": "",  # To be filled by caller with public key hex
        "path": "",    # Optional: derivation path
        "uuid": str(uuid.uuid4()),
        "version": 4
    }
    
    return keystore


def decrypt_key(
    keystore: Dict[str, Any],
    password: str
) -> bytes:
    """
    Decrypt a Dilithium private key from EIP-2335 keystore.
    
    Args:
        keystore: Keystore dictionary
        password: Password for decryption
    
    Returns:
        Decrypted private key bytes
    
    Raises:
        InvalidPassword: If password is incorrect
        InvalidKeystore: If keystore format is invalid
    """
    try:
        crypto = keystore["crypto"]
        kdf_params = crypto["kdf"]["params"]
        cipher_params = crypto["cipher"]["params"]
        
        # Extract parameters
        kdf_salt = bytes.fromhex(kdf_params["salt"])
        iv = bytes.fromhex(cipher_params["iv"])
        ciphertext = bytes.fromhex(crypto["cipher"]["message"])
        expected_checksum = bytes.fromhex(crypto["checksum"]["message"])
        
        # Derive decryption key
        derived_key = scrypt(
            password.encode('utf-8'),
            salt=kdf_salt,
            key_len=kdf_params["dklen"],
            N=kdf_params["n"],
            r=kdf_params["r"],
            p=kdf_params["p"]
        )
        
        # Split derived key
        aes_key = derived_key[:16]
        checksum_key = derived_key[16:]
        
        # Verify checksum
        checksum_data = checksum_key + ciphertext
        computed_checksum = hashlib.sha256(checksum_data).digest()[:16]
        
        if computed_checksum != expected_checksum:
            raise InvalidPassword("Incorrect password or corrupted keystore")
        
        # Decrypt
        counter = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))
        cipher = AES.new(aes_key, AES.MODE_CTR, counter=counter)
        private_key_bytes = cipher.decrypt(ciphertext)
        
        return private_key_bytes
    
    except KeyError as e:
        raise InvalidKeystore(f"Missing required field: {e}")
    except ValueError as e:
        raise InvalidKeystore(f"Invalid keystore format: {e}")


def save_keystore(
    keystore: Dict[str, Any],
    keystore_path: Path,
    password: str = None
) -> Path:
    """
    Save keystore to JSON file.
    
    Args:
        keystore: Keystore dictionary
        keystore_path: Path to save keystore (directory or file)
        password: Optional password for verification
    
    Returns:
        Path to saved keystore file
    """
    # If directory provided, generate filename from UUID
    if keystore_path.is_dir():
        filename = f"keystore-{keystore['uuid']}.json"
        keystore_path = keystore_path / filename
    
    # Ensure parent directory exists
    keystore_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write keystore
    with open(keystore_path, 'w') as f:
        json.dump(keystore, f, indent=4)
    
    # Set restrictive permissions (owner read/write only)
    keystore_path.chmod(0o600)
    
    return keystore_path


def load_keystore(keystore_path: Path) -> Dict[str, Any]:
    """
    Load keystore from JSON file.
    
    Args:
        keystore_path: Path to keystore file
    
    Returns:
        Keystore dictionary
    
    Raises:
        InvalidKeystore: If file cannot be read or parsed
    """
    try:
        with open(keystore_path, 'r') as f:
            keystore = json.load(f)
        
        # Basic validation
        required_fields = ["crypto", "version", "uuid"]
        for field in required_fields:
            if field not in keystore:
                raise InvalidKeystore(f"Missing required field: {field}")
        
        if keystore["version"] != 4:
            raise InvalidKeystore(f"Unsupported keystore version: {keystore['version']}")
        
        return keystore
    
    except json.JSONDecodeError as e:
        raise InvalidKeystore(f"Invalid JSON: {e}")
    except FileNotFoundError:
        raise InvalidKeystore(f"Keystore file not found: {keystore_path}")


def create_keystore_from_dilithium_key(
    private_key_bytes: bytes,
    public_key_bytes: bytes,
    password: str,
    path: str = "",
    description: str = None
) -> Dict[str, Any]:
    """
    Create EIP-2335 keystore from Dilithium key pair.
    
    Args:
        private_key_bytes: Dilithium private key bytes
        public_key_bytes: Dilithium public key bytes
        password: Password for encryption
        path: Optional derivation path
        description: Optional description
    
    Returns:
        Complete keystore dictionary
    """
    # Encrypt private key
    keystore = encrypt_key(private_key_bytes, password)
    
    # Add public key and metadata
    keystore["pubkey"] = public_key_bytes.hex()
    keystore["path"] = path
    
    if description:
        keystore["description"] = description
    
    return keystore


def load_dilithium_key_from_keystore(
    keystore_path: Path,
    password: str
) -> Tuple[bytes, bytes]:
    """
    Load Dilithium key pair from keystore file.
    
    Args:
        keystore_path: Path to keystore file
        password: Password for decryption
    
    Returns:
        Tuple of (private_key_bytes, public_key_bytes)
    
    Raises:
        InvalidPassword: If password is incorrect
        InvalidKeystore: If keystore is invalid
    """
    # Load keystore
    keystore = load_keystore(keystore_path)
    
    # Decrypt private key
    private_key_bytes = decrypt_key(keystore, password)
    
    # Extract public key
    public_key_hex = keystore.get("pubkey", "")
    if not public_key_hex:
        raise InvalidKeystore("Keystore missing public key")
    
    public_key_bytes = bytes.fromhex(public_key_hex)
    
    return private_key_bytes, public_key_bytes
