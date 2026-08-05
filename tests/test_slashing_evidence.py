"""
Self-validating DOUBLE_SIGN slashing evidence (slashing_block) — the proof that rides in
block bodies so every node holds identical evidence and the finalized-epoch penalty can be
ENFORCED deterministically.

Security-critical: a proof is slashable ONLY if it carries two blocks each validly signed by
the SAME proposer for the SAME slot with different hashes. A malicious proposer must not be
able to fabricate a slash for an honest validator (it would need that validator's signature
over two blocks), and the benign equal-height race (distinct proposers) must never validate.
"""
import hashlib
import os
import tempfile

import pytest

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator.block_verification import reconstruct_signing_root
from qrdx.validator.slashing_block import (
    make_double_sign_evidence, verify_double_sign_evidence,
    extract_slashing_evidence_from_dict, record_block_slashing_evidence, BLOCK_SLASHING_KEY,
)


@pytest.fixture
async def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database = await DatabaseSQLite.create(path)
    yield database
    await database.connection.close()
    for p in (path, path + "-wal", path + "-shm"):
        try:
            os.remove(p)
        except OSError:
            pass


def _signed_header(key: PQPrivateKey, slot=7, **overrides):
    """A str(to_dict())-shaped signed PoS block header for `key` (mirrors the proposer)."""
    addr = key.public_key.to_address()
    bc = {
        "number": 7, "parent_hash": "ab" * 32, "state_root": "cd" * 32,
        "transactions_root": "ef" * 32, "timestamp": 1700000000,
        "proposer_address": addr, "proposer_public_key": key.public_key.to_bytes().hex(),
        "slot": slot, "epoch": 0, "randao_reveal": "11" * 32,
    }
    bc.update(overrides)
    bc["proposer_signature"] = key.sign(reconstruct_signing_root(bc)).to_bytes().hex()
    # hash is derived from content (distinct content → distinct hash); make it explicit.
    bc["hash"] = hashlib.sha256(repr(sorted(bc.items())).encode()).hexdigest()
    return bc, addr


def test_genuine_double_sign_validates():
    key = PQPrivateKey.generate()
    # SAME proposer, SAME slot, DIFFERENT state_root → two validly-signed conflicting blocks.
    h1, _ = _signed_header(key, slot=9, state_root="11" * 32)
    h2, _ = _signed_header(key, slot=9, state_root="22" * 32)
    ev = make_double_sign_evidence(h1, h2)
    ok, err = verify_double_sign_evidence(ev)
    assert ok, err
    assert ev["condition"] == "double_sign" and ev["slot"] == 9


def test_evidence_is_canonical_regardless_of_order():
    key = PQPrivateKey.generate()
    h1, _ = _signed_header(key, slot=3, state_root="aa" * 32)
    h2, _ = _signed_header(key, slot=3, state_root="bb" * 32)
    assert make_double_sign_evidence(h1, h2) == make_double_sign_evidence(h2, h1)


def test_distinct_proposers_not_a_double_sign():
    """The benign equal-height race — two DIFFERENT proposers at the same slot — must NOT be
    slashable."""
    k1, k2 = PQPrivateKey.generate(), PQPrivateKey.generate()
    h1, _ = _signed_header(k1, slot=5)
    h2, _ = _signed_header(k2, slot=5)
    # Construct evidence manually (make_* would key off h1's proposer); verify must reject.
    ev = {"header_a": h1, "header_b": h2}
    ok, err = verify_double_sign_evidence(ev)
    assert not ok and "proposer" in err


def test_same_block_twice_not_conflicting():
    key = PQPrivateKey.generate()
    h1, _ = _signed_header(key, slot=5, state_root="cd" * 32)
    ev = {"header_a": h1, "header_b": dict(h1)}
    ok, err = verify_double_sign_evidence(ev)
    assert not ok and "hash" in err


def test_forged_signature_rejected():
    """A fabricated slash for an honest validator (attacker forges the victim's signature over
    a second block) must fail — the signature check is the security boundary."""
    victim = PQPrivateKey.generate()
    h1, _ = _signed_header(victim, slot=8, state_root="11" * 32)
    h2, _ = _signed_header(victim, slot=8, state_root="22" * 32)
    # Attacker tampers header_b's signed content AFTER signing → signature no longer valid.
    h2["state_root"] = "99" * 32
    ev = make_double_sign_evidence(h1, h2)
    ok, err = verify_double_sign_evidence(ev)
    assert not ok and "signature invalid" in err


def test_different_slots_not_a_double_sign():
    key = PQPrivateKey.generate()
    h1, _ = _signed_header(key, slot=1)
    h2, _ = _signed_header(key, slot=2)
    ev = {"header_a": h1, "header_b": h2}
    ok, err = verify_double_sign_evidence(ev)
    assert not ok and "slot" in err


def test_extract_from_block_dict():
    key = PQPrivateKey.generate()
    h1, _ = _signed_header(key, slot=4, state_root="11" * 32)
    h2, _ = _signed_header(key, slot=4, state_root="22" * 32)
    ev = make_double_sign_evidence(h1, h2)
    assert extract_slashing_evidence_from_dict({BLOCK_SLASHING_KEY: [ev]}) == [ev]
    assert extract_slashing_evidence_from_dict({}) == []
    assert extract_slashing_evidence_from_dict({BLOCK_SLASHING_KEY: "junk"}) == []


async def test_record_block_evidence_is_deterministic(db):
    """The RECEIVING side: recording a block's evidence is a pure function of the block, so every
    node ends with the SAME slashing_events (the determinism the finalized-epoch slash needs).
    A forged proof in the same block is skipped (never records a slash for an honest validator)."""
    victim = PQPrivateKey.generate()
    h1, addr = _signed_header(victim, slot=12, state_root="11" * 32)
    h2, _ = _signed_header(victim, slot=12, state_root="22" * 32)
    good = make_double_sign_evidence(h1, h2)
    # A forged proof: distinct proposers (benign race) — must not record.
    other = PQPrivateKey.generate()
    ho, _ = _signed_header(other, slot=13)
    forged = {"proposer": addr, "slot": 13, "header_a": h1, "header_b": ho}
    block = {BLOCK_SLASHING_KEY: [good, forged]}

    recorded = await record_block_slashing_evidence(db, block)
    await db.connection.commit()
    assert recorded == 1  # only the genuine double-sign
    events = await db.get_slashing_events(addr)
    assert len(events) == 1 and events[0]["slot"] == 12

    # Idempotent: re-recording the same block (e.g. re-included in a later block) is a no-op.
    again = await record_block_slashing_evidence(db, block)
    assert again == 0
    assert len(await db.get_slashing_events(addr)) == 1
