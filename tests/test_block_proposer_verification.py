"""
PoS block proposer authentication on import.

`verify_pos_block_proposer` is the check the import paths were missing: it proves
a block was produced by the validator it claims (Dilithium signature over the
signed header) and that the carried public key actually derives to that address
(identity binding, closing the impersonation vector).

These tests build a REAL Dilithium-signed block and pin: a genuine block passes;
a tampered signed field, a forged signature, a swapped public key, and a
missing-field block all fail.
"""

import hashlib

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.validator.block_verification import (
    verify_pos_block_proposer,
    reconstruct_signing_root,
)


def _signed_block(key: PQPrivateKey, **overrides):
    """Build a str(to_dict())-shaped signed PoS block content for `key`."""
    addr = key.public_key.to_address()
    bc = {
        "number": 7,
        "parent_hash": "ab" * 32,
        "state_root": "cd" * 32,
        "transactions_root": "ef" * 32,
        "timestamp": 1700000000,
        "proposer_address": addr,
        "proposer_public_key": key.public_key.to_bytes().hex(),
        "slot": 7,
        "epoch": 0,
        "randao_reveal": "11" * 32,
        "attestations": [],
        "graffiti": "",
    }
    bc.update(overrides)
    signing_root = reconstruct_signing_root(bc)
    bc["proposer_signature"] = key.sign(signing_root).to_bytes().hex()
    bc["hash"] = hashlib.sha256(b"whatever").hexdigest()
    return bc, addr


def test_genuine_block_passes():
    key = PQPrivateKey.generate()
    bc, addr = _signed_block(key)
    ok, err = verify_pos_block_proposer(str(bc), addr)
    assert ok, err
    # Also accepts the dict form directly.
    ok2, _ = verify_pos_block_proposer(bc, addr)
    assert ok2


def test_tampered_signed_field_fails():
    key = PQPrivateKey.generate()
    bc, addr = _signed_block(key)
    bc["state_root"] = "00" * 32  # mutate a signed field after signing
    ok, err = verify_pos_block_proposer(str(bc), addr)
    assert not ok and "signature" in err


def test_forged_signature_fails():
    key = PQPrivateKey.generate()
    bc, addr = _signed_block(key)
    bc["proposer_signature"] = "00" * (len(bc["proposer_signature"]) // 2)
    ok, err = verify_pos_block_proposer(str(bc), addr)
    assert not ok


def test_impersonation_pubkey_address_mismatch_fails():
    """Attacker signs with their own key but claims a victim's address."""
    victim = PQPrivateKey.generate()
    attacker = PQPrivateKey.generate()
    victim_addr = victim.public_key.to_address()
    # Attacker's block: their pubkey + valid self-signature, victim's address.
    bc, _ = _signed_block(attacker, proposer_address=victim_addr)
    ok, err = verify_pos_block_proposer(str(bc), victim_addr)
    assert not ok and "does not match address" in err


def test_missing_fields_fail():
    key = PQPrivateKey.generate()
    bc, addr = _signed_block(key)
    no_sig = dict(bc); no_sig.pop("proposer_signature")
    ok, err = verify_pos_block_proposer(str(no_sig), addr)
    assert not ok and "proposer_public_key/proposer_signature" in err

    no_field = dict(bc); no_field.pop("epoch")
    ok2, err2 = verify_pos_block_proposer(str(no_field), addr)
    assert not ok2 and "epoch" in err2


def test_garbage_content_fails():
    ok, err = verify_pos_block_proposer("not a dict", "0xPQabc")
    assert not ok
