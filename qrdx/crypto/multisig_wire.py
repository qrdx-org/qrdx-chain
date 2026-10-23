"""
Multisig signatures on transactions (docs/ACCOUNT_CONTROL.md).

A transaction signed by an m-of-n multisig (an ``0xPQMS…`` address, qrdx/crypto/threshold_dilithium.py)
carries, where a single-key transaction carries its public key and signature:

* ``public_key`` — the keyset: ``{"m", "n", "public_keys": [hex, …]}`` as canonical JSON. Told
  apart from a single key by its LENGTH: a Dilithium public key is exactly PUBLIC_KEY_SIZE raw
  bytes (which may begin with any byte, ``{`` included), and a keyset's JSON never is — one key
  in hex alone is twice that;
* ``signature`` — the aggregate: ``{"m", "n", "keyset_address", "signer_mask", "partials"}``,
  each partial a member's Dilithium signature over the domain-tagged message.

The address is derived from the keyset (sorted keys and threshold), never taken as sent, so a
keyset proves the address it signs for. Verification costs a Dilithium verification a partial:
keysets are capped at MAX_KEYS here, and callers charge gas per partial.

Exchange transactions (qrdx/exchange/transactions.py) and EVM type-0x51 transactions
(qrdx/transactions/pq_tx.py) both accept this form.
"""

from __future__ import annotations

import json
from typing import List, Optional, Sequence, Tuple

from .threshold_dilithium import (
    MultisigKeySet,
    MultisigSignature,
    ThresholdConfig,
    aggregate_partial_signatures,
    create_multisig_keyset,
    create_partial_signature,
    verify_multisig,
)

MAX_KEYS = 20  # the most keys a keyset that signs a transaction may hold


def is_multisig_material(public_key: bytes) -> bool:
    """A multisig keyset (not a single Dilithium key): never PUBLIC_KEY_SIZE long."""
    from .pq.dilithium import PUBLIC_KEY_SIZE

    return bool(public_key) and len(public_key) != PUBLIC_KEY_SIZE and public_key[:1] == b"{"


def encode_keyset(keyset: MultisigKeySet) -> bytes:
    data = keyset.to_dict()
    data.pop("address", None)  # derived, never sent
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def decode_keyset(material: bytes) -> MultisigKeySet:
    """The keyset in ``material`` (its address derived from its keys and threshold)."""
    data = json.loads(material.decode())
    if not isinstance(data, dict) or set(data) - {"m", "n", "public_keys"}:
        raise ValueError("a keyset is {m, n, public_keys}")
    if not isinstance(data.get("public_keys"), list) or len(data["public_keys"]) > MAX_KEYS:
        raise ValueError(f"a signing keyset holds at most {MAX_KEYS} keys")
    from .pq.dilithium import PQPublicKey

    config = ThresholdConfig(m=int(data["m"]), n=int(data["n"]))
    return create_multisig_keyset(config, [PQPublicKey.from_hex(h) for h in data["public_keys"]])


def encode_signature(signature: MultisigSignature) -> bytes:
    return json.dumps(signature.to_dict(), sort_keys=True, separators=(",", ":")).encode()


def decode_signature(material: bytes) -> MultisigSignature:
    data = json.loads(material.decode())
    if not isinstance(data, dict) or len(data.get("partials") or []) > MAX_KEYS:
        raise ValueError("malformed multisig signature")
    return MultisigSignature.from_dict(data)


def signer_count(signature: bytes) -> int:
    """How many partial signatures ``signature`` carries (0 if it is not a multisig one) —
    what its verification costs, in Dilithium verifications."""
    from .pq.dilithium import SIGNATURE_SIZE

    if len(signature or b"") == SIGNATURE_SIZE or signature[:1] != b"{":
        return 0  # a single key's (fixed length; it may begin with any byte)
    try:
        return len(json.loads(signature.decode()).get("partials") or [])
    except (ValueError, AttributeError):
        return 0


def verify(public_key: bytes, signature: bytes, message: bytes) -> Optional[str]:
    """The multisig address ``signature`` proves for ``message`` — or None if it does not."""
    try:
        keyset = decode_keyset(public_key)
        sig = decode_signature(signature)
    except Exception:
        return None
    return keyset.address if verify_multisig(keyset, message, sig) else None


def keyset_of(public_keys: Sequence, m: int) -> MultisigKeySet:
    return create_multisig_keyset(ThresholdConfig(m=m, n=len(public_keys)), list(public_keys))


def sign(keyset: MultisigKeySet, private_keys: List, message: bytes) -> Tuple[bytes, bytes]:
    """(public_key, signature) fields for ``message`` signed by ``private_keys`` (members of
    ``keyset``, at least m of them) — what a wallet coordinating the signers produces."""
    partials = [create_partial_signature(key, keyset, message) for key in private_keys]
    aggregate = aggregate_partial_signatures(partials, keyset, message)
    return encode_keyset(keyset), encode_signature(aggregate)
