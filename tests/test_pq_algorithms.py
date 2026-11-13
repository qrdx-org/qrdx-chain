"""
QRDX runs exactly ML-DSA-65 and ML-KEM-768, and proves the installed liboqs computes them
(qrdx/crypto/pq/algorithms.py). A node on the round-3 "Dilithium3" or a draft ML-DSA would sign
what the network rejects and reject what it signs: a silent split. So there is no fallback, and a
known-answer test from an independent implementation gates every key.
"""

import ast
from pathlib import Path

import oqs
import pytest

from qrdx.config.loader import P2PSecurityConfig
from qrdx.crypto.pq import algorithms as A, kat_vectors as kat
from qrdx.crypto.pq.dilithium import ALGORITHM as SIGNING, PQPrivateKey, verify
from qrdx.crypto.pq.kyber import ALGORITHM as KEM

ROOT = Path(__file__).resolve().parents[1] / "qrdx"


def test_the_installed_liboqs_computes_the_standards():
    A.self_test()
    assert (SIGNING, KEM) == ("ML-DSA-65", "ML-KEM-768")


def test_a_key_made_here_verifies_against_the_known_answer_scheme():
    key = PQPrivateKey.generate()
    sig = key.sign(b"x")
    assert len(sig.to_bytes()) == A.SIG_SIGNATURE_SIZE
    assert verify(key.public_key, b"x", sig)


def test_a_library_without_ml_dsa_is_refused_not_downgraded(monkeypatch):
    real = oqs.Signature

    def no_ml_dsa(name, *args, **kwargs):
        if name == "ML-DSA-65":
            raise oqs.MechanismNotSupportedError(name)
        return real(name, *args, **kwargs)

    monkeypatch.setattr(oqs, "Signature", no_ml_dsa)
    with pytest.raises(A.PQAlgorithmError, match="does not offer ML-DSA-65"):
        A.self_test()


def test_a_library_computing_something_else_is_refused(monkeypatch):
    # A signature the standard does not produce for this key and message (e.g. a draft scheme's).
    sig = bytearray(bytes.fromhex(kat.ML_DSA_65_SIGNATURE))
    sig[100] ^= 0x40
    monkeypatch.setattr(kat, "ML_DSA_65_SIGNATURE", sig.hex())
    with pytest.raises(A.PQAlgorithmError, match="does not compute FIPS 204"):
        A.self_test()


def test_a_library_that_accepts_anything_is_refused(monkeypatch):
    real = oqs.Signature

    class Lenient:
        def __init__(self, name, *args):
            self.details = dict(real(name).details)

        def verify(self, *args):
            return True

    monkeypatch.setattr(oqs, "Signature", Lenient)
    with pytest.raises(A.PQAlgorithmError, match="accepts a tampered"):
        A.self_test()


def test_wrong_sizes_and_a_wrong_kem_answer_are_refused(monkeypatch):
    real_sig = oqs.Signature

    class Draft:
        def __init__(self, name, *args):
            self.details = {**dict(real_sig(name).details), "length_signature": 3293}

    monkeypatch.setattr(oqs, "Signature", Draft)
    with pytest.raises(A.PQAlgorithmError, match="length_signature=3293"):
        A.self_test()
    monkeypatch.setattr(oqs, "Signature", real_sig)

    secret = bytearray(bytes.fromhex(kat.ML_KEM_768_SHARED_SECRET))
    secret[0] ^= 1
    monkeypatch.setattr(kat, "ML_KEM_768_SHARED_SECRET", secret.hex())
    with pytest.raises(A.PQAlgorithmError, match="does not compute FIPS 203"):
        A.self_test()


def test_no_module_names_another_algorithm_to_liboqs():
    """Every liboqs call takes the fixed name, never a literal another release might map."""
    offenders = []
    for path in ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("Signature", "KeyEncapsulation")
                and isinstance(getattr(node.func, "value", None), ast.Name)
                and node.func.value.id == "oqs"
                and node.args
                and isinstance(node.args[0], ast.Constant)
            ):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert offenders == []


def test_a_config_naming_another_algorithm_is_refused():
    assert P2PSecurityConfig.from_dict({}).pq_sig_algorithm == "ML-DSA-65"
    with pytest.raises(ValueError, match="QRDX runs only"):
        P2PSecurityConfig.from_dict({"pq_sig_algorithm": "Dilithium3"})
    with pytest.raises(ValueError, match="QRDX runs only"):
        P2PSecurityConfig.from_dict({"pq_kem_algorithm": "Kyber768"})
