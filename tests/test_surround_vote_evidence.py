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


def _root(epoch):
    """A checkpoint root per epoch (one honest chain)."""
    import hashlib

    return hashlib.sha256(f"checkpoint {epoch}".encode()).hexdigest()


def _signed_att(key, slot, epoch, block_hash, source, target, idx=0):
    addr = key.public_key.to_address()
    att = Attestation(slot=slot, epoch=epoch, block_hash=block_hash, validator_address=addr,
                      validator_index=idx, signature=b"", source_epoch=source, target_epoch=target,
                      source_root=_root(source), target_root=_root(target))
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


def test_two_votes_for_one_target_are_a_double_vote():
    """Casper FFG: a validator casts one vote per target epoch, so two DIFFERENT signed votes for
    the same target — even at different slots, as per-slot voting used to produce — are a double
    vote. (Re-sending one vote is not: the data is identical.)"""
    key = PQPrivateKey.generate()
    a = _signed_att(key, slot=8, epoch=1, block_hash="aa" * 32, source=0, target=1)
    b = _signed_att(key, slot=9, epoch=1, block_hash="bb" * 32, source=0, target=1)
    assert attestation_equivocation(a, b) == "double_vote"
    ok, err = verify_attestation_evidence(make_attestation_evidence(a, b, _pub(key)))
    assert ok, err
    assert attestation_equivocation(a, dict(a)) is None
    ok, err = verify_attestation_evidence({"att_a": a, "att_b": dict(a), "public_key": _pub(key)})
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
    """Full path: a surround-vote proof in a block is verified, recorded, and slashes the
    offender in the validator set of the next epoch — half its stake, and out. Mirrors the
    DOUBLE_SIGN path (both ride the same evidence-in-blocks transport)."""
    import os
    import tempfile
    from decimal import Decimal
    from qrdx.constants import SLOTS_PER_EPOCH
    from qrdx.database_sqlite import DatabaseSQLite
    from qrdx.validator import epoch_state as ES
    from qrdx.validator.slashing_block import record_block_slashing_evidence, BLOCK_SLASHING_KEY

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
        others = [f"0xPQ{c * 64}" for c in "abc"]
        await db.record_genesis_validators(
            [{"address": x, "public_key": "", "stake": "100000"} for x in [addr, *others]])
        for h, slot, extra in ((0, 0, {}), (1, SLOTS_PER_EPOCH + 1, {BLOCK_SLASHING_KEY: [ev]})):
            content = {"number": h, "slot": slot, "epoch": slot // SLOTS_PER_EPOCH, **extra}
            await db.connection.execute(
                "INSERT INTO blocks (block_hash, block_height, content, timestamp) "
                "VALUES (?, ?, ?, 0)", (f"{h:064x}", h, repr(content)))
        assert await record_block_slashing_evidence(db, {BLOCK_SLASHING_KEY: [ev]}) == 1
        await db.connection.commit()
        state = await ES.state_at(db, 2)
        assert state[addr].status == "slashed" and state[addr].effective_stake == Decimal("50000")
    finally:
        await db.connection.close()
        os.remove(path)
