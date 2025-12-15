"""
Trinity Keystore Module

Provides secure key management for QRDX validators using EIP-2335 compliant
encrypted keystores with Dilithium ML-DSA-65 post-quantum keys.
"""

from .eip2335 import (
    KeystoreError,
    InvalidPassword,
    InvalidKeystore,
    encrypt_key,
    decrypt_key,
    save_keystore,
    load_keystore,
    create_keystore_from_dilithium_key,
    load_dilithium_key_from_keystore,
)

__all__ = [
    "KeystoreError",
    "InvalidPassword",
    "InvalidKeystore",
    "encrypt_key",
    "decrypt_key",
    "save_keystore",
    "load_keystore",
    "create_keystore_from_dilithium_key",
    "load_dilithium_key_from_keystore",
]
