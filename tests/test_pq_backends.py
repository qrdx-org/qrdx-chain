"""
liboqs and OpenSSL give the same verdict on every ML-DSA-65 verification (qrdx/crypto/pq/
openssl_backend.py, docs/PQ_CRYPTO_BACKEND.md).

Verification decides what every node accepts, so moving it from liboqs to OpenSSL is safe only
if the two never disagree: on the known-answer vector from an independent implementation, on
each other's signatures, and on every malformed key, message and signature a peer could send.
"""

import os

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from qrdx.crypto.pq import openssl_backend as ossl
from qrdx.crypto.pq.dilithium import PQPrivateKey, PQPublicKey, PQSignature, sign, verify

pytestmark = pytest.mark.skipif(not ossl.available(),
                                reason="needs pyca/cryptography >= 48 with OpenSSL >= 3.5")

_DEEP = int(os.environ.get("QRDX_FUZZ_EXAMPLES", "0"))
FUZZ = settings(max_examples=_DEEP or 150, derandomize=not _DEEP, deadline=None, database=None,
                suppress_health_check=list(HealthCheck))

KEY = PQPrivateKey.generate()
PUB = KEY.public_key.to_bytes()
MSG = b"QRDX differential verification"
SIG = sign(KEY, MSG).to_bytes()


def _liboqs(pub: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        return verify(PQPublicKey.from_bytes(pub), msg, PQSignature.from_bytes(sig))
    except Exception:  # (a malformed key or signature that will not even construct)
        return False


def test_the_known_answer_signature_verifies_under_both():
    from qrdx.crypto.pq import kat_vectors as kat

    pub = bytes.fromhex(kat.ML_DSA_65_PUBLIC_KEY)
    msg = bytes.fromhex(kat.ML_DSA_65_MESSAGE)
    sig = bytes.fromhex(kat.ML_DSA_65_SIGNATURE)
    assert _liboqs(pub, msg, sig) is True
    assert ossl.verify(pub, msg, sig) is True
    assert ossl.verify(pub, msg + b"x", sig) is False


def test_each_verifies_the_others_signatures():
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import mldsa

    assert ossl.verify(PUB, MSG, SIG) is True
    other = mldsa.MLDSA65PrivateKey.generate()
    pub = other.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    assert _liboqs(pub, MSG, other.sign(MSG)) is True


@st.composite
def mutated(draw, data: bytes):
    out = bytearray(data)
    kind = draw(st.sampled_from(["flip", "truncate", "extend", "zero", "byte"]))
    at = draw(st.integers(0, len(out) - 1))
    if kind == "flip":
        out[at] ^= 1 << draw(st.integers(0, 7))
    elif kind == "truncate":
        del out[at:]
    elif kind == "extend":
        out += draw(st.binary(min_size=1, max_size=8))
    elif kind == "zero":
        out[at:at + draw(st.integers(1, 64))] = bytes(min(64, len(out) - at))
    else:
        out[at] = draw(st.integers(0, 255))
    return bytes(out)


@FUZZ
@given(st.one_of(
    st.tuples(st.just(PUB), st.just(MSG), mutated(SIG)),
    st.tuples(mutated(PUB), st.just(MSG), st.just(SIG)),
    st.tuples(st.just(PUB), st.binary(max_size=80), st.just(SIG)),
    st.tuples(st.binary(max_size=64), st.just(MSG), st.binary(max_size=64)),
))
def test_they_agree_on_any_key_message_and_signature(case):
    pub, msg, sig = case
    assert _liboqs(pub, msg, sig) == ossl.verify(pub, msg, sig)


def test_the_shadow_counts_a_disagreement_and_liboqs_still_decides(monkeypatch):
    monkeypatch.setenv("QRDX_PQ_SHADOW_VERIFY", "1")
    before = ossl.disagreements()
    assert verify(KEY.public_key, MSG, PQSignature.from_bytes(SIG)) is True
    assert ossl.disagreements() == before                      # they agree: nothing counted
    monkeypatch.setattr(ossl, "verify", lambda *a: False)      # an OpenSSL that disagrees
    assert verify(KEY.public_key, MSG, PQSignature.from_bytes(SIG)) is True
    assert ossl.disagreements() == before + 1
