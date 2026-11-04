"""
ML-DSA-65 verification by OpenSSL, through pyca/cryptography (docs/PQ_CRYPTO_BACKEND.md).

liboqs signs and verifies everything today. liboqs is a research library, and says so; OpenSSL
3.5 and later implement FIPS 204 too, in a library reviewed and deployed far more widely, and
the node image already ships one (pyca/cryptography 48 or later, whose wheels bundle it). Both
read the same encodings: a 1,952-byte public key and a 3,309-byte signature.

Verification decides what every node accepts, so the network must agree on it to the last
input. Before verification moves, nodes can run both (``QRDX_PQ_SHADOW_VERIFY``): liboqs still
decides, and any input on which the two disagree is logged and counted
(``qrdx_pq_verify_disagreements_total``). tests/test_pq_backends.py holds them to the same
answer on the known-answer vector and on fuzzed keys, messages and signatures.

Signing stays with liboqs: OpenSSL builds a key from its 32-byte seed, and liboqs stores the
expanded 4,032-byte key, from which no seed can be recovered.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

PUBLIC_KEY_SIZE = 1952
SIGNATURE_SIZE = 3309

_disagreements = 0


def available() -> bool:
    """Whether this process's cryptography can verify ML-DSA-65 (pyca/cryptography >= 48 with
    OpenSSL >= 3.5, or an AWS-LC / BoringSSL build)."""
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
    except ImportError:
        return False
    return True


def verify(public_key: bytes, message: bytes, signature: bytes) -> Optional[bool]:
    """OpenSSL's verdict on ``signature`` over ``message`` (pure ML-DSA-65, empty context), or
    None if this process cannot ask it."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError:
        return None
    try:
        key = mldsa.MLDSA65PublicKey.from_public_bytes(bytes(public_key))
    except (ValueError, TypeError):
        return False  # (not a public key: liboqs refuses it as well)
    try:
        key.verify(bytes(signature), bytes(message))
    except InvalidSignature:
        return False
    except (ValueError, TypeError):
        return False
    return True


def shadow_enabled() -> bool:
    return os.environ.get("QRDX_PQ_SHADOW_VERIFY", "").lower() in ("1", "true", "yes")


def disagreements() -> int:
    return _disagreements


def shadow(public_key: bytes, message: bytes, signature: bytes, liboqs_verdict: bool) -> None:
    """Ask OpenSSL too; count and log the input if it answers otherwise."""
    global _disagreements
    other = verify(public_key, message, signature)
    if other is None or other == liboqs_verdict:
        return
    _disagreements += 1
    try:
        from ...node.observability import record

        record("qrdx_pq_verify_disagreements_total")
    except Exception:  # noqa: BLE001 — a metric never breaks verification
        pass
    logger.error(
        "[PQ-VERIFY-DISAGREEMENT] liboqs says %s, OpenSSL says %s: key %s…, message %d bytes "
        "(%s…), signature %d bytes (%s…)",
        liboqs_verdict,
        other,
        bytes(public_key)[:8].hex(),
        len(message),
        bytes(message)[:16].hex(),
        len(signature),
        bytes(signature)[:16].hex(),
    )
