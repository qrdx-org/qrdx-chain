"""
QRDX Threshold Dilithium Multisignatures

Implements m-of-n post-quantum multisignatures using ML-DSA-65 (Dilithium3)
at the protocol level, per Whitepaper §6.1.

Architecture:
  - Each of n signers holds a standard Dilithium keypair
  - Signing: each participant produces a standard Dilithium signature
  - Aggregation: m valid partial signatures are collected into a MultisigSignature
  - Verification: each partial sig is verified against its signer's public key;
    the keyset membership and threshold are enforced

Domain Separation:
  All messages are tagged with the multisig address before signing, preventing
  cross-wallet replay: tag = BLAKE3(DOMAIN_MULTISIG || keyset_address || message)

SECURITY: Requires liboqs-python. There is NO fallback mode.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .pq.dilithium import (
    PQPrivateKey,
    PQPublicKey,
    PQSignature,
    PQCryptoError,
    PQSignatureError,
    verify as dilithium_verify,
    generate_keypair as dilithium_generate_keypair,
    PUBLIC_KEY_SIZE,
    SIGNATURE_SIZE,
)

try:
    import blake3 as _blake3
    def _blake3_hash(data: bytes) -> bytes:
        return _blake3.blake3(data).digest()
except ImportError:
    def _blake3_hash(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()


# ═══════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════

# Multisig address prefix — derived from sorted public keys + threshold
MULTISIG_ADDRESS_PREFIX = "0xPQMS"

# Domain separator for threshold signing (prevents cross-wallet replays)
DOMAIN_MULTISIG = b"QRDX-THRESHOLD-DILITHIUM-v1"

# Limits
MAX_SIGNERS = 150      # Absolute maximum n
MAX_THRESHOLD = 100    # Absolute maximum m
MIN_THRESHOLD = 1      # Minimum threshold


# ═══════════════════════════════════════════════════════════════════════
# THRESHOLD CONFIG
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ThresholdConfig:
    """
    Defines the m-of-n threshold for a multisig keyset.

    Attributes:
        m: Minimum signers required (threshold)
        n: Total number of signers
    """
    m: int
    n: int

    def __post_init__(self):
        if not isinstance(self.m, int) or not isinstance(self.n, int):
            raise TypeError("m and n must be integers")
        if self.m < MIN_THRESHOLD:
            raise ValueError(f"Threshold m must be >= {MIN_THRESHOLD}, got {self.m}")
        if self.m > self.n:
            raise ValueError(f"Threshold m ({self.m}) cannot exceed n ({self.n})")
        if self.n > MAX_SIGNERS:
            raise ValueError(f"Total signers n ({self.n}) exceeds maximum {MAX_SIGNERS}")
        if self.m > MAX_THRESHOLD:
            raise ValueError(f"Threshold m ({self.m}) exceeds maximum {MAX_THRESHOLD}")
        if self.n < 1:
            raise ValueError(f"Total signers n must be >= 1, got {self.n}")

    def __repr__(self) -> str:
        return f"ThresholdConfig({self.m}-of-{self.n})"


# ═══════════════════════════════════════════════════════════════════════
# MULTISIG KEYSET
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class MultisigKeySet:
    """
    An immutable set of n Dilithium public keys bound to a threshold config.

    The keyset is deterministic: keys are sorted by raw bytes, and the
    multisig address is derived from the sorted keys + config.

    Attributes:
        config: ThresholdConfig (m-of-n)
        public_keys: Tuple of n PQPublicKey (sorted by key_bytes)
        address: Derived multisig address (0xPQMS...)
    """
    config: ThresholdConfig
    public_keys: Tuple[PQPublicKey, ...]
    address: str

    def __post_init__(self):
        if len(self.public_keys) != self.config.n:
            raise ValueError(
                f"Expected {self.config.n} public keys, got {len(self.public_keys)}"
            )

    def contains_key(self, pub: PQPublicKey) -> bool:
        """Check if a public key is a member of this keyset."""
        return pub in self.public_keys

    def key_index(self, pub: PQPublicKey) -> int:
        """Get the index of a public key in the sorted keyset."""
        try:
            return self.public_keys.index(pub)
        except ValueError:
            raise ValueError("Public key is not a member of this keyset")

    def to_dict(self) -> Dict:
        """Serialize to dictionary."""
        return {
            "m": self.config.m,
            "n": self.config.n,
            "address": self.address,
            "public_keys": [pk.to_hex() for pk in self.public_keys],
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'MultisigKeySet':
        """Deserialize from dictionary."""
        config = ThresholdConfig(m=data["m"], n=data["n"])
        pks = [PQPublicKey.from_hex(h) for h in data["public_keys"]]
        return create_multisig_keyset(config, pks)


# ═══════════════════════════════════════════════════════════════════════
# PARTIAL SIGNATURE
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class PartialSignature:
    """
    A single signer's contribution to a multisig signature.

    Attributes:
        signer_index: Index of the signer in the keyset (0-based)
        public_key: The signer's public key
        signature: Standard Dilithium signature over the domain-tagged message
    """
    signer_index: int
    public_key: PQPublicKey
    signature: PQSignature

    def to_dict(self) -> Dict:
        """Serialize."""
        return {
            "signer_index": self.signer_index,
            "public_key": self.public_key.to_hex(),
            "signature": self.signature.to_hex(),
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'PartialSignature':
        """Deserialize."""
        return cls(
            signer_index=data["signer_index"],
            public_key=PQPublicKey.from_hex(data["public_key"]),
            signature=PQSignature.from_hex(data["signature"]),
        )


# ═══════════════════════════════════════════════════════════════════════
# MULTISIG SIGNATURE
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class MultisigSignature:
    """
    Aggregated m-of-n threshold signature.

    Contains exactly m partial signatures from distinct signers,
    plus the signer bitmask for efficient on-chain verification.

    Attributes:
        config: ThresholdConfig this signature satisfies
        keyset_address: The multisig address this signature is bound to
        signer_mask: Bitmask indicating which signers contributed (bit i = signer i)
        partials: Tuple of m PartialSignature objects
    """
    config: ThresholdConfig
    keyset_address: str
    signer_mask: int
    partials: Tuple[PartialSignature, ...]

    def __post_init__(self):
        if len(self.partials) < self.config.m:
            raise ValueError(
                f"Need at least {self.config.m} partial signatures, "
                f"got {len(self.partials)}"
            )
        # Verify signer_mask matches partials
        expected_mask = 0
        for p in self.partials:
            expected_mask |= (1 << p.signer_index)
        if self.signer_mask != expected_mask:
            raise ValueError("signer_mask does not match partial signature indices")

    @property
    def signer_count(self) -> int:
        """Number of signers who contributed."""
        return len(self.partials)

    @property
    def signer_indices(self) -> List[int]:
        """Sorted list of signer indices."""
        return sorted(p.signer_index for p in self.partials)

    def to_dict(self) -> Dict:
        """Serialize."""
        return {
            "m": self.config.m,
            "n": self.config.n,
            "keyset_address": self.keyset_address,
            "signer_mask": self.signer_mask,
            "partials": [p.to_dict() for p in self.partials],
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'MultisigSignature':
        """Deserialize."""
        config = ThresholdConfig(m=data["m"], n=data["n"])
        partials = tuple(PartialSignature.from_dict(d) for d in data["partials"])
        return cls(
            config=config,
            keyset_address=data["keyset_address"],
            signer_mask=data["signer_mask"],
            partials=partials,
        )


# ═══════════════════════════════════════════════════════════════════════
# KEY CREATION
# ═══════════════════════════════════════════════════════════════════════

def derive_multisig_address(config: ThresholdConfig, sorted_keys: Tuple[PQPublicKey, ...]) -> str:
    """
    Derive deterministic multisig address from config + sorted public keys.

    Address = "0xPQMS" + first 35 hex chars of BLAKE3(m || n || key0 || key1 || ... || keyN-1)

    The address is always 44 characters: "0xPQMS" (6) + 38 hex (38) = 44.
    """
    hasher_input = (
        config.m.to_bytes(2, 'big') +
        config.n.to_bytes(2, 'big') +
        b''.join(pk.to_bytes() for pk in sorted_keys)
    )
    digest = _blake3_hash(DOMAIN_MULTISIG + hasher_input)
    return MULTISIG_ADDRESS_PREFIX + digest.hex()[:38]


def create_multisig_keyset(
    config: ThresholdConfig,
    public_keys: List[PQPublicKey],
) -> MultisigKeySet:
    """
    Create a MultisigKeySet from a threshold config and list of public keys.

    Keys are sorted by raw bytes to ensure deterministic address derivation.
    Duplicate keys are rejected.

    Args:
        config: ThresholdConfig (m-of-n)
        public_keys: List of n PQPublicKey objects

    Returns:
        MultisigKeySet with sorted keys and derived address

    Raises:
        ValueError: If key count != n, or duplicates found
    """
    if len(public_keys) != config.n:
        raise ValueError(
            f"Expected {config.n} public keys, got {len(public_keys)}"
        )

    # Check for duplicates
    key_bytes_set = {pk.to_bytes() for pk in public_keys}
    if len(key_bytes_set) != len(public_keys):
        raise ValueError("Duplicate public keys are not allowed in a multisig keyset")

    # Sort by raw bytes for determinism
    sorted_keys = tuple(sorted(public_keys, key=lambda pk: pk.to_bytes()))

    address = derive_multisig_address(config, sorted_keys)

    return MultisigKeySet(
        config=config,
        public_keys=sorted_keys,
        address=address,
    )


def generate_multisig_keyset(
    config: ThresholdConfig,
) -> Tuple[MultisigKeySet, List[PQPrivateKey]]:
    """
    Generate a fresh multisig keyset with n new Dilithium keypairs.

    Useful for testing and key ceremony initialization.

    Args:
        config: ThresholdConfig (m-of-n)

    Returns:
        Tuple of (MultisigKeySet, list of n PQPrivateKey)
    """
    private_keys = []
    public_keys = []
    for _ in range(config.n):
        priv, pub = dilithium_generate_keypair()
        private_keys.append(priv)
        public_keys.append(pub)

    keyset = create_multisig_keyset(config, public_keys)

    # Re-order private keys to match sorted public key order
    pk_to_priv = {pk.to_bytes(): priv for pk, priv in zip(public_keys, private_keys)}
    sorted_privs = [pk_to_priv[pk.to_bytes()] for pk in keyset.public_keys]

    return keyset, sorted_privs


# ═══════════════════════════════════════════════════════════════════════
# DOMAIN-TAGGED MESSAGE
# ═══════════════════════════════════════════════════════════════════════

def _domain_tag_message(keyset_address: str, message: bytes) -> bytes:
    """
    Apply domain separation to prevent cross-wallet replay.

    tagged = BLAKE3(DOMAIN_MULTISIG || keyset_address_bytes || message)
    """
    addr_bytes = keyset_address.encode('utf-8')
    return _blake3_hash(DOMAIN_MULTISIG + addr_bytes + message)


# ═══════════════════════════════════════════════════════════════════════
# SIGNING
# ═══════════════════════════════════════════════════════════════════════

def create_partial_signature(
    private_key: PQPrivateKey,
    keyset: MultisigKeySet,
    message: bytes,
) -> PartialSignature:
    """
    Create a partial signature for a multisig transaction.

    The signer must be a member of the keyset. The message is domain-tagged
    with the keyset address before signing.

    Args:
        private_key: Signer's PQPrivateKey
        keyset: The MultisigKeySet this signature belongs to
        message: Raw message bytes to sign

    Returns:
        PartialSignature

    Raises:
        ValueError: If signer is not in keyset
        PQSignatureError: If signing fails
    """
    pub = private_key.public_key
    if not keyset.contains_key(pub):
        raise ValueError("Signer's public key is not a member of this multisig keyset")

    signer_index = keyset.key_index(pub)
    tagged_message = _domain_tag_message(keyset.address, message)

    sig = private_key.sign(tagged_message)

    return PartialSignature(
        signer_index=signer_index,
        public_key=pub,
        signature=sig,
    )


def aggregate_partial_signatures(
    partials: List[PartialSignature],
    keyset: MultisigKeySet,
    message: bytes,
) -> MultisigSignature:
    """
    Aggregate m partial signatures into a MultisigSignature.

    Each partial is verified against the keyset before inclusion.
    Rejects: duplicates, non-members, invalid signatures, below-threshold.

    Args:
        partials: List of PartialSignature objects (at least m)
        keyset: The MultisigKeySet
        message: Original message (not domain-tagged)

    Returns:
        MultisigSignature

    Raises:
        ValueError: If below threshold, duplicates, or non-member
        PQSignatureError: If any partial signature is invalid
    """
    if len(partials) < keyset.config.m:
        raise ValueError(
            f"Need at least {keyset.config.m} partial signatures, "
            f"got {len(partials)}"
        )

    tagged_message = _domain_tag_message(keyset.address, message)

    seen_indices: Set[int] = set()
    verified_partials: List[PartialSignature] = []
    signer_mask = 0

    for partial in partials:
        # Check membership
        if not keyset.contains_key(partial.public_key):
            raise ValueError(
                f"Signer at index {partial.signer_index} is not a member of the keyset"
            )

        # Check index consistency
        expected_index = keyset.key_index(partial.public_key)
        if partial.signer_index != expected_index:
            raise ValueError(
                f"Signer index mismatch: partial says {partial.signer_index}, "
                f"keyset says {expected_index}"
            )

        # Check for duplicates
        if partial.signer_index in seen_indices:
            raise ValueError(f"Duplicate partial signature from signer {partial.signer_index}")

        # Verify the partial signature
        is_valid = dilithium_verify(
            partial.public_key, tagged_message, partial.signature
        )
        if not is_valid:
            raise PQSignatureError(
                f"Invalid partial signature from signer {partial.signer_index}"
            )

        seen_indices.add(partial.signer_index)
        verified_partials.append(partial)
        signer_mask |= (1 << partial.signer_index)

    # Sort by signer index for canonical ordering
    verified_partials.sort(key=lambda p: p.signer_index)

    return MultisigSignature(
        config=keyset.config,
        keyset_address=keyset.address,
        signer_mask=signer_mask,
        partials=tuple(verified_partials),
    )


# ═══════════════════════════════════════════════════════════════════════
# VERIFICATION
# ═══════════════════════════════════════════════════════════════════════

def verify_multisig(
    keyset: MultisigKeySet,
    message: bytes,
    signature: MultisigSignature,
) -> bool:
    """
    Verify a MultisigSignature against a keyset and message.

    Checks:
      1. Signature is bound to the correct keyset address
      2. At least m partial signatures are present
      3. All signers are members of the keyset
      4. No duplicate signers
      5. Each partial Dilithium signature is valid

    Args:
        keyset: The MultisigKeySet
        message: Original message (not domain-tagged)
        signature: MultisigSignature to verify

    Returns:
        True if valid, False otherwise
    """
    try:
        # Check keyset address binding
        if signature.keyset_address != keyset.address:
            return False

        # Check threshold
        if signature.signer_count < keyset.config.m:
            return False

        # Check config match
        if signature.config != keyset.config:
            return False

        tagged_message = _domain_tag_message(keyset.address, message)

        seen_indices: Set[int] = set()

        for partial in signature.partials:
            # Check membership
            if not keyset.contains_key(partial.public_key):
                return False

            # Check index
            expected_index = keyset.key_index(partial.public_key)
            if partial.signer_index != expected_index:
                return False

            # Check duplicates
            if partial.signer_index in seen_indices:
                return False
            seen_indices.add(partial.signer_index)

            # Verify Dilithium signature
            if not dilithium_verify(partial.public_key, tagged_message, partial.signature):
                return False

        return True

    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════════
# ADDRESS UTILITIES
# ═══════════════════════════════════════════════════════════════════════

def is_multisig_address(address: str) -> bool:
    """Check if an address is a multisig address (0xPQMS prefix)."""
    return isinstance(address, str) and address.startswith(MULTISIG_ADDRESS_PREFIX)
