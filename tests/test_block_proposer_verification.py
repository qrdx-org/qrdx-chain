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


from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.validator.block_verification import (
    body_root,
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
        "randao_reveal": "",  # none unless RANDAO selection is scheduled
        "attestations": [],
        "graffiti": "",
        "base_fee": 10 ** 9,
        "exchange_base_fee": 10 ** 9,
    }
    bc.update(overrides)
    bc.setdefault("body_root", body_root(bc))
    signing_root = reconstruct_signing_root(bc)
    bc["proposer_signature"] = key.sign(signing_root).to_bytes().hex()
    bc["hash"] = signing_root.hex()
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
    assert not ok and "proposer_signature" in err

    no_field = dict(bc); no_field.pop("epoch")
    ok2, err2 = verify_pos_block_proposer(str(no_field), addr)
    assert not ok2 and "epoch" in err2


def test_garbage_content_fails():
    ok, err = verify_pos_block_proposer("not a dict", "0xPQabc")
    assert not ok



# ── A block body no longer carries the proposer's key; the reveal only when RANDAO is near ──

def test_a_block_without_its_key_verifies_against_the_registry_key():
    """The 3.9 KB key is gone from every block; importers pass the key the chain registered."""
    key = PQPrivateKey.generate()
    bc, addr = _signed_block(key)
    del bc["proposer_public_key"]
    assert not verify_pos_block_proposer(str(bc), addr)[0]          # no key at all
    ok, err = verify_pos_block_proposer(str(bc), addr, key.public_key.to_bytes())
    assert ok, err
    other = PQPrivateKey.generate().public_key.to_bytes()
    ok, err = verify_pos_block_proposer(str(bc), addr, other)        # a key not the proposer's
    assert not ok and "does not match address" in err


def test_a_reveal_is_refused_unless_randao_selection_is_near(monkeypatch):
    from qrdx.validator import randao
    from qrdx.validator.randao import randao_reveal_message

    key = PQPrivateKey.generate()
    reveal = key.sign(randao_reveal_message(7)).to_bytes().hex()
    bc, addr = _signed_block(key, randao_reveal=reveal)
    ok, err = verify_pos_block_proposer(str(bc), addr)
    assert not ok and "not scheduled" in err                         # 3.3 KB nothing reads

    monkeypatch.setattr(randao, "randao_reveal_required", lambda number: True)
    assert verify_pos_block_proposer(str(bc), addr)[0]               # a real reveal
    missing, _ = _signed_block(key)
    ok, err = verify_pos_block_proposer(str(missing), addr)
    assert not ok and "missing RANDAO reveal" in err
    forged, _ = _signed_block(key, randao_reveal=key.sign(b"another message").to_bytes().hex())
    ok, err = verify_pos_block_proposer(str(forged), addr)
    assert not ok and "invalid RANDAO reveal" in err                 # chosen bytes, not a reveal
    wrong_slot, _ = _signed_block(key, randao_reveal=key.sign(randao_reveal_message(8)).to_bytes().hex())
    assert not verify_pos_block_proposer(str(wrong_slot), addr)[0]


def test_reveals_start_ahead_of_randao_selection(monkeypatch):
    from qrdx.validator import randao

    monkeypatch.setattr(randao, "randao_selection_active", lambda h: h >= 10_000)
    lead = randao.RANDAO_REVEAL_LEAD_BLOCKS
    assert not randao.randao_reveal_required(10_000 - lead - 1)
    assert randao.randao_reveal_required(10_000 - lead)
    assert randao.randao_reveal_required(20_000)
