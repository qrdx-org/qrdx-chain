"""
Self-validating attestation-equivocation slashing evidence (Casper FFG double-vote / surround-
vote) — the second slashing condition wired to evidence-in-blocks, mirroring DOUBLE_SIGN.

Security-critical: a proof is slashable ONLY if it carries two attestations each validly signed
by the SAME validator (whose pubkey — carried in the evidence, since attestations don't include
one — derives to their address) that form a double or surround vote. A malicious proposer must
not be able to fabricate one for an honest validator (would need that validator's signature over
two conflicting attestations), and honest voting (one attestation per target, never surrounding)
must never validate.
"""
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.validator.attestation import Attestation
from qrdx.validator.slashing_block import (
    attestation_equivocation, make_attestation_evidence, verify_attestation_evidence,
)


def _signed_att(key, slot, epoch, block_hash, source, target, idx=0):
    addr = key.public_key.to_address()
    att = Attestation(slot=slot, epoch=epoch, block_hash=block_hash, validator_address=addr,
                      validator_index=idx, signature=b"", source_epoch=source, target_epoch=target)
    att.signature = key.sign(att.signing_root).to_bytes()
    return att.to_dict()


def _pub(key):
    return key.public_key.to_bytes().hex()


def test_double_vote_validates():
    """Two attestations for the SAME SLOT but DIFFERENT blocks → double vote (the validator
    signed two heads for one slot; the attestation analog of DOUBLE_SIGN)."""
    key = PQPrivateKey.generate()
    a = _signed_att(key, slot=32, epoch=1, block_hash="aa" * 32, source=0, target=1)
    b = _signed_att(key, slot=32, epoch=1, block_hash="bb" * 32, source=0, target=1)
    assert attestation_equivocation(a, b) == "double_vote"
    ok, err = verify_attestation_evidence(make_attestation_evidence(a, b, _pub(key)))
    assert ok, err


def test_honest_per_slot_votes_not_slashable():
    """REGRESSION: this chain attests PER SLOT, so one honest validator casts many attestations
    sharing a target epoch but pointing at the advancing head (DIFFERENT slot + block). That MUST
    NOT be a double vote — else honest validators are slashable and anyone could harvest two of
    their public per-slot attestations to forge a slash."""
    key = PQPrivateKey.generate()
    a = _signed_att(key, slot=8, epoch=1, block_hash="aa" * 32, source=0, target=1)
    b = _signed_att(key, slot=9, epoch=1, block_hash="bb" * 32, source=0, target=1)  # same target, next slot/head
    assert attestation_equivocation(a, b) is None
    ok, err = verify_attestation_evidence({"att_a": a, "att_b": b, "public_key": _pub(key)})
    assert not ok and "not a double/surround" in err


def test_surround_vote_validates():
    """Attestation A (source 0, target 5) STRICTLY surrounds B (source 2, target 3)."""
    key = PQPrivateKey.generate()
    a = _signed_att(key, slot=10, epoch=5, block_hash="aa" * 32, source=0, target=5)
    b = _signed_att(key, slot=20, epoch=3, block_hash="bb" * 32, source=2, target=3)
    assert attestation_equivocation(a, b) == "surround_vote"
    ok, err = verify_attestation_evidence(make_attestation_evidence(a, b, _pub(key)))
    assert ok, err


def test_honest_non_conflicting_not_slashable():
    """Sequential, non-surrounding attestations (the honest pattern) are NOT slashable."""
    key = PQPrivateKey.generate()
    a = _signed_att(key, slot=10, epoch=1, block_hash="aa" * 32, source=0, target=1)
    b = _signed_att(key, slot=42, epoch=2, block_hash="bb" * 32, source=1, target=2)
    assert attestation_equivocation(a, b) is None
    ok, err = verify_attestation_evidence(
        {"att_a": a, "att_b": b, "public_key": _pub(key)})
    assert not ok and "not a double/surround" in err


def test_same_target_same_block_not_double_vote():
    """Re-attesting the SAME block for a target is not equivocation (identical vote)."""
    key = PQPrivateKey.generate()
    a = _signed_att(key, slot=10, epoch=1, block_hash="aa" * 32, source=0, target=1)
    assert attestation_equivocation(a, dict(a)) is None


def test_different_validators_not_slashable():
    k1, k2 = PQPrivateKey.generate(), PQPrivateKey.generate()
    a = _signed_att(k1, slot=10, epoch=1, block_hash="aa" * 32, source=0, target=1)
    b = _signed_att(k2, slot=11, epoch=1, block_hash="bb" * 32, source=0, target=1)
    ok, err = verify_attestation_evidence({"att_a": a, "att_b": b, "public_key": _pub(k1)})
    assert not ok and "different/absent validators" in err


def test_forged_signature_rejected():
    """Fabricating a slash for an honest victim: attacker tampers a signed attestation's fields
    after signing → signature no longer valid → rejected (the security boundary)."""
    victim = PQPrivateKey.generate()
    a = _signed_att(victim, slot=10, epoch=1, block_hash="aa" * 32, source=0, target=1)
    b = _signed_att(victim, slot=10, epoch=1, block_hash="bb" * 32, source=0, target=1)  # same slot → double vote
    b["block_hash"] = "cc" * 32  # tamper after signing
    ok, err = verify_attestation_evidence(make_attestation_evidence(a, b, _pub(victim)))
    assert not ok and "signature invalid" in err


def test_pubkey_address_mismatch_rejected():
    """An evidence whose carried pubkey doesn't derive to the attestations' validator is invalid."""
    victim, attacker = PQPrivateKey.generate(), PQPrivateKey.generate()
    a = _signed_att(victim, slot=10, epoch=1, block_hash="aa" * 32, source=0, target=1)
    b = _signed_att(victim, slot=10, epoch=1, block_hash="bb" * 32, source=0, target=1)  # same slot → double vote
    ev = make_attestation_evidence(a, b, _pub(attacker))  # wrong pubkey
    ok, err = verify_attestation_evidence(ev)
    assert not ok and "does not derive" in err


async def test_surround_vote_records_and_enforces_50pct():
    """Full path: a surround-vote proof in a block is recorded (verified) as a SURROUND_VOTE
    slashing_event → the enforced finalized-epoch slash penalises 50% + ejects. Mirrors the
    DOUBLE_SIGN enforce path (both ride the same evidence-in-blocks transport)."""
    import os
    import tempfile
    from decimal import Decimal
    from qrdx.database_sqlite import DatabaseSQLite
    from qrdx.validator.slashing_block import record_block_slashing_evidence, BLOCK_SLASHING_KEY
    from qrdx.validator.epoch_loop import apply_epoch_slashings

    key = PQPrivateKey.generate()
    addr = key.public_key.to_address()
    a = _signed_att(key, slot=10, epoch=5, block_hash="aa" * 32, source=0, target=5)
    b = _signed_att(key, slot=20, epoch=3, block_hash="bb" * 32, source=2, target=3)  # surrounded
    ev = make_attestation_evidence(a, b, _pub(key))
    assert ev["condition"] == "surround_vote"

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = await DatabaseSQLite.create(path)
    try:
        await db.connection.execute(
            "INSERT INTO validators (address, public_key, stake, effective_stake, status, "
            "activation_epoch) VALUES (?, 'pk', '100000', '100000', 'active', 0)", (addr,))
        await db.connection.commit()
        assert await record_block_slashing_evidence(db, {BLOCK_SLASHING_KEY: [ev]}) == 1
        await db.connection.commit()
        await apply_epoch_slashings(db, epoch=6, enforce=True)  # offence epoch 3 <= 6
        await db.connection.commit()
        c = await db.connection.execute(
            "SELECT status, effective_stake FROM validators WHERE address = ?", (addr,))
        status, eff = await c.fetchone()
        assert status == "slashed" and Decimal(eff) == Decimal("50000")  # 50% slash + eject
    finally:
        await db.connection.close()
        os.remove(path)
