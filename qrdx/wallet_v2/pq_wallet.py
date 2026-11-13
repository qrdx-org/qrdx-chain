"""
QRDX Post-Quantum Wallet (ML-DSA-65)

Quantum-resistant wallet using ML-DSA-65 (FIPS 204) signatures.
"""

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ..crypto.pq import (
    PQPrivateKey,
    PQSignature,
    get_liboqs_error,
    is_available as pq_available,
)
from .base import (
    KEYSTORE_CIPHER,
    BaseWallet,
    WalletError,
    WalletMetadata,
    WalletType,
    decrypt_key,
    encrypt_key,
)

# Signed and verified on every restore: a keystore whose secret and public keys do not belong
# together is refused before its owner signs anything with it.
_KEYPAIR_CHECK = b"qrdx keystore keypair check"


def keystore_aad(address: str, public_key_hex: str) -> bytes:
    """What a PQ keystore's ciphertext is bound to: the identity the file says it holds."""
    return f"qrdx-pq-keystore-v2|{address}|{public_key_hex.lower()}".encode()


class PQWallet(BaseWallet):
    """
    Post-Quantum wallet using Dilithium3.

    Provides quantum-resistant signatures with NIST Level 3 security.
    Signatures are larger (~3309 bytes) but provide future-proof security.

    REQUIRES liboqs-python. There is NO fallback mode — nodes without
    liboqs cannot operate PQ wallets.

    Example:
        # Generate new PQ wallet
        wallet = PQWallet.generate()
        print(wallet.address)  # 0xPQ...

        # Sign a message
        message = b"Hello, quantum-safe QRDX!"
        signature = wallet.sign(message)

        # Save encrypted
        wallet.save(Path("pq_wallet.json"), "my-password")
    """

    def __init__(self, private_key: PQPrivateKey, metadata: Optional[WalletMetadata] = None):
        """
        Initialize PQ wallet.

        Args:
            private_key: Dilithium3 private key
            metadata: Optional wallet metadata
        """
        super().__init__(metadata)
        self._private_key = private_key
        self._public_key = private_key.public_key
        self._address = private_key.address

    @property
    def wallet_type(self) -> WalletType:
        return WalletType.POST_QUANTUM

    @property
    def address(self) -> str:
        return self._address

    @property
    def public_key(self) -> bytes:
        return self._public_key.to_bytes()

    @property
    def public_key_hex(self) -> str:
        """Get hex-encoded public key."""
        return self._public_key.to_hex()

    @property
    def public_key_fingerprint(self) -> str:
        """Get short public key fingerprint."""
        return self._public_key.fingerprint()

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message.

        Args:
            message: Message bytes to sign

        Returns:
            Signature bytes (~3293 bytes)
        """
        signature = self._private_key.sign(message)
        return signature.to_bytes()

    def sign_transaction(self, tx_hash: bytes) -> bytes:
        """
        Sign a transaction hash.

        Args:
            tx_hash: Transaction hash (typically 32 bytes)

        Returns:
            Signature bytes
        """
        return self.sign(tx_hash)

    def sign_with_prefix(self, message: bytes) -> bytes:
        """
        Sign with QRDX prefix (similar to EIP-191).

        Prefixes message with:
        "\\x19QRDX PQ Signed Message:\\n" + len(message)

        Args:
            message: Message to sign

        Returns:
            Signature bytes
        """
        prefix = f"\x19QRDX PQ Signed Message:\n{len(message)}".encode()
        prefixed = prefix + message
        return self.sign(prefixed)

    def export_private_key(self) -> bytes:
        """
        Export raw private key bytes.

        WARNING: Handle with extreme care!
        PQ private keys are larger (~4000 bytes).

        Returns:
            Private key bytes
        """
        return self._private_key.to_bytes()

    def to_keystore(self, password: str) -> Dict[str, Any]:
        """
        Export to encrypted keystore format.

        Args:
            password: Encryption password

        Returns:
            Keystore dictionary
        """
        encrypted = encrypt_key(
            self._private_key.to_bytes(),
            password,
            keystore_aad(self._address, self._public_key.to_hex()),
        )

        return {
            "version": 2,
            "id": os.urandom(16).hex(),
            "address": self._address,
            "public_key": self._public_key.to_hex(),  # Store public key for restoration
            "public_key_fingerprint": self.public_key_fingerprint,
            "crypto": encrypted,
            "wallet_type": self.wallet_type.value,
            "algorithm": "ML-DSA-65",
        }

    @classmethod
    def from_keystore(cls, keystore: Dict[str, Any], password: str) -> "PQWallet":
        """
        Load from encrypted keystore.

        Args:
            keystore: Keystore dictionary
            password: Decryption password

        Returns:
            PQWallet instance
        """
        # Verify wallet type
        wallet_type = keystore.get("wallet_type", "pq")
        if wallet_type != "pq":
            raise WalletError(f"Expected PQ wallet, got {wallet_type}")

        # The public key is not optional: an ML-DSA secret key cannot re-derive it, and
        # restoring without it would yield a different, random identity.
        public_key_hex = keystore.get("public_key")
        if not public_key_hex:
            raise WalletError("the keystore has no public key; it cannot be restored")
        address = keystore.get("address")
        crypto = keystore["crypto"]
        aad = b""
        if crypto.get("cipher") == KEYSTORE_CIPHER:
            if not address:
                raise WalletError("the keystore has no address")
            aad = keystore_aad(address, public_key_hex)
        key_bytes = decrypt_key(crypto, password, aad)

        from ..crypto.pq import PQPublicKey

        public_key = PQPublicKey.from_hex(public_key_hex)
        private_key = PQPrivateKey.from_bytes(key_bytes, public_key=public_key)
        wallet = cls(private_key)
        if address and wallet.address != address:
            raise WalletError(f"the keystore names {address}, its key is {wallet.address}")
        if not wallet.verify(_KEYPAIR_CHECK, wallet.sign(_KEYPAIR_CHECK)):
            raise WalletError("the keystore's secret key does not match its public key")
        return wallet

    @classmethod
    def generate(cls, name: str = "Post-Quantum Wallet") -> "PQWallet":
        """
        Generate a new random PQ wallet.

        Args:
            name: Wallet name for metadata

        Returns:
            New PQWallet instance
        """
        if not pq_available():
            raise WalletError(
                f"liboqs-python is required for PQ wallets but is not available: "
                f"{get_liboqs_error()}. Install with: pip install liboqs-python"
            )

        private_key = PQPrivateKey.generate()

        metadata = WalletMetadata(
            name=name,
            wallet_type=WalletType.POST_QUANTUM,
            created_at=datetime.now(timezone.utc).isoformat(),
            description="Dilithium3 post-quantum wallet",
        )

        return cls(private_key, metadata)

    @classmethod
    def from_private_key(cls, private_key: bytes) -> "PQWallet":
        """
        Create wallet from raw private key bytes.

        Args:
            private_key: Private key bytes

        Returns:
            PQWallet instance
        """
        pk = PQPrivateKey.from_bytes(private_key)
        return cls(pk)

    @classmethod
    def from_hex(cls, hex_key: str) -> "PQWallet":
        """
        Create wallet from hex-encoded private key.

        Args:
            hex_key: Hex private key (with or without 0x prefix)

        Returns:
            PQWallet instance
        """
        if hex_key.startswith("0x"):
            hex_key = hex_key[2:]
        return cls.from_private_key(bytes.fromhex(hex_key))

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature against this wallet's public key.

        Args:
            message: Original message
            signature: Signature bytes

        Returns:
            True if valid
        """
        from ..crypto.pq import verify

        sig = PQSignature.from_bytes(signature)
        return verify(self._public_key, message, sig)

    @staticmethod
    def is_pq_available() -> bool:
        """Check if liboqs is available."""
        return pq_available()
