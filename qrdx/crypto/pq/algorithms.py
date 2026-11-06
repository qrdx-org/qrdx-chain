"""
The post-quantum algorithms QRDX runs, and the proof that the installed liboqs computes them.

QRDX signs with ML-DSA-65 (FIPS 204) and agrees keys with ML-KEM-768 (FIPS 203), and with nothing
else. liboqs has offered other things under nearby names: the round-3 "Dilithium3" and "Kyber768",
and in some releases draft versions of ML-DSA under the final name. None of them is compatible.
A node on one would sign what the network rejects and reject what it signs, splitting from the
chain without an error.

So the names are fixed here and nowhere else, and :func:`require` proves, before any key is used,
that the installed library computes the standards. It checks the sizes, verifies a signature
made by an independent implementation (and refuses a tampered one), and decapsulates a ciphertext
made by an independent implementation to the expected secret (qrdx/crypto/pq/kat_vectors.py).
Any failure stops the node.
"""

from __future__ import annotations

import threading

SIG_ALGORITHM = "ML-DSA-65"
KEM_ALGORITHM = "ML-KEM-768"

# FIPS 204 ML-DSA-65 and FIPS 203 ML-KEM-768 sizes, in bytes.
SIG_PUBLIC_KEY_SIZE = 1952
SIG_SECRET_KEY_SIZE = 4032
SIG_SIGNATURE_SIZE = 3309
KEM_PUBLIC_KEY_SIZE = 1184
KEM_SECRET_KEY_SIZE = 2400
KEM_CIPHERTEXT_SIZE = 1088
KEM_SHARED_SECRET_SIZE = 32


class PQAlgorithmError(RuntimeError):
    """The installed liboqs does not compute ML-DSA-65 / ML-KEM-768 as the standards define."""


_lock = threading.Lock()
_verified = False


def _sizes(details: dict, expected: dict, name: str) -> None:
    for key, want in expected.items():
        got = details.get(key)
        if got != want:
            raise PQAlgorithmError(f"{name}: liboqs reports {key}={got}, the standard is {want}")


def self_test() -> None:
    """Run the known-answer tests against the installed liboqs, raising on any difference."""
    try:
        import oqs
    except ImportError as exc:  # pragma: no cover - the crypto modules fail first
        raise PQAlgorithmError(f"liboqs-python is not installed: {exc}") from exc

    from . import kat_vectors as kat

    try:
        verifier = oqs.Signature(SIG_ALGORITHM)
    except Exception as exc:
        raise PQAlgorithmError(
            f"the installed liboqs does not offer {SIG_ALGORITHM} (FIPS 204); QRDX runs nothing else"
        ) from exc
    _sizes(
        dict(verifier.details),
        {
            "length_public_key": SIG_PUBLIC_KEY_SIZE,
            "length_secret_key": SIG_SECRET_KEY_SIZE,
            "length_signature": SIG_SIGNATURE_SIZE,
        },
        SIG_ALGORITHM,
    )
    public_key = bytes.fromhex(kat.ML_DSA_65_PUBLIC_KEY)
    message = bytes.fromhex(kat.ML_DSA_65_MESSAGE)
    signature = bytes.fromhex(kat.ML_DSA_65_SIGNATURE)
    if not verifier.verify(message, signature, public_key):
        raise PQAlgorithmError(
            f"the installed liboqs rejects the {SIG_ALGORITHM} known-answer signature: "
            "it does not compute FIPS 204"
        )
    tampered = bytes([signature[0] ^ 1]) + signature[1:]
    if oqs.Signature(SIG_ALGORITHM).verify(message, tampered, public_key):
        raise PQAlgorithmError(f"the installed liboqs accepts a tampered {SIG_ALGORITHM} signature")

    try:
        kem = oqs.KeyEncapsulation(KEM_ALGORITHM, bytes.fromhex(kat.ML_KEM_768_SECRET_KEY))
    except Exception as exc:
        raise PQAlgorithmError(
            f"the installed liboqs does not offer {KEM_ALGORITHM} (FIPS 203); QRDX runs nothing else"
        ) from exc
    _sizes(
        dict(kem.details),
        {
            "length_public_key": KEM_PUBLIC_KEY_SIZE,
            "length_secret_key": KEM_SECRET_KEY_SIZE,
            "length_ciphertext": KEM_CIPHERTEXT_SIZE,
            "length_shared_secret": KEM_SHARED_SECRET_SIZE,
        },
        KEM_ALGORITHM,
    )
    if kem.decap_secret(bytes.fromhex(kat.ML_KEM_768_CIPHERTEXT)) != bytes.fromhex(
        kat.ML_KEM_768_SHARED_SECRET
    ):
        raise PQAlgorithmError(
            f"the installed liboqs decapsulates the {KEM_ALGORITHM} known answer differently: "
            "it does not compute FIPS 203"
        )


def require() -> None:
    """Prove once per process that liboqs computes the standards (see the module docstring)."""
    global _verified
    if _verified:
        return
    with _lock:
        if not _verified:
            self_test()
            _verified = True
