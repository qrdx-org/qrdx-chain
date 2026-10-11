"""
LIVE surround/double-vote DETECTION — the node retains signed attestations and, on import,
compares each verified vote against the validator's retained votes, turning an observed
double/surround conflict into self-validating evidence (mirrors the DOUBLE_SIGN p2p detection).

Security boundary: detection fires ONLY on a genuine Casper-FFG conflict (same-target/different-
block, or a surrounding source/target span). Honest voting — one attestation per target, never
surrounding — must produce zero detections (a false positive would slash an honest validator).
Detection is OBSERVE-gated (`_ENFORCE_SURROUND_DETECTION`): it records evidence only when the flag
is on, so an honest soak can prove no false positives before enabling. Once recorded, the evidence
is surfaced by `get_pending_slashing_evidence` so it rides the chain to every node.
"""
import json
import os
import tempfile

import pytest

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator import finality as F
from qrdx.validator.attestation import Attestation
from qrdx.validator.attestation_block import BLOCK_ATTESTATIONS_KEY
from qrdx.validator.slashing_block import verify_attestation_evidence


def _root(epoch):
    """A checkpoint root per epoch (one honest chain)."""
    import hashlib

    return hashlib.sha256(f"checkpoint {epoch}".encode()).hexdigest()


def _signed_att(key, slot, epoch, block_hash, source, target, idx=0):
    att = Attestation(slot=slot, epoch=epoch, block_hash=block_hash,
                      validator_address=key.public_key.to_address(), validator_index=idx,
                      signature=b"", source_epoch=source, target_epoch=target,
                      source_root=_root(source), target_root=_root(target))
    att.signature = key.sign(att.signing_root).to_bytes()
    return att


async def _fresh_db_with_validator(key):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = await DatabaseSQLite.create(path)
    await db.connection.execute(
        "INSERT INTO validators (address, public_key, stake, effective_stake, status, "
        "activation_epoch) VALUES (?, ?, '100000', '100000', 'active', 0)",
        (key.public_key.to_address(), key.public_key.to_bytes().hex()))
    await db.connection.commit()
    return db, path


def _block(atts):
    return {BLOCK_ATTESTATIONS_KEY: [a.to_dict() for a in atts]}


async def _events(db):
    cur = await db.connection.execute(
        "SELECT condition, evidence FROM slashing_events")
    return await cur.fetchall()


@pytest.mark.asyncio
async def test_honest_sequential_votes_no_detection():
    """The honest pattern (one vote per target, incrementing source+target) → zero events even
    with enforce ON — the false-positive gate."""
    key = PQPrivateKey.generate()
    db, path = await _fresh_db_with_validator(key)
    F._ENFORCE_SURROUND_DETECTION = True
    try:
        atts = [_signed_att(key, slot=32 * e, epoch=e, block_hash=f"{e:02x}" * 32,
                            source=e - 1, target=e) for e in range(1, 5)]
        for a in atts:
            await F.record_block_attestations(db, _block([a]))
        assert await _events(db) == []
    finally:
        F._ENFORCE_SURROUND_DETECTION = True
        await db.connection.close()
        os.remove(path)


@pytest.mark.asyncio
async def test_honest_per_slot_same_target_no_detection():
    """An honest validator casts ONE vote per epoch (qrdx/validator/ffg.py) and may see it carried
    by several blocks (re-included after a reorg, or by two proposers): the same signed vote
    again is never a conflict. (Under the old per-slot voting, a validator signed many votes per
    target; that is what let a validator switching forks support both branches, and it is now a
    double vote — see test_surround_vote_evidence.)"""
    key = PQPrivateKey.generate()
    db, path = await _fresh_db_with_validator(key)
    F._ENFORCE_SURROUND_DETECTION = True
    try:
        a = _signed_att(key, slot=10, epoch=1, block_hash="a1" * 32, source=0, target=1)
        for _ in range(3):
            await F.record_block_attestations(db, _block([a]))
        b = _signed_att(key, slot=18, epoch=2, block_hash="b2" * 32, source=1, target=2)
        await F.record_block_attestations(db, _block([b]))  # the next epoch's vote
        assert await _events(db) == []
    finally:
        F._ENFORCE_SURROUND_DETECTION = True
        await db.connection.close()
        os.remove(path)


@pytest.mark.asyncio
async def test_double_vote_detected_and_recorded_when_enforced():
    """Two verified votes for the SAME SLOT but different blocks → a SURROUND_VOTE event whose
    recorded evidence self-validates and is surfaced for block inclusion."""
    key = PQPrivateKey.generate()
    db, path = await _fresh_db_with_validator(key)
    F._ENFORCE_SURROUND_DETECTION = True
    try:
        a = _signed_att(key, slot=32, epoch=1, block_hash="aa" * 32, source=0, target=1)
        b = _signed_att(key, slot=32, epoch=1, block_hash="bb" * 32, source=0, target=1)
        await F.record_block_attestations(db, _block([a]))
        await F.record_block_attestations(db, _block([b]))  # conflict caught here
        rows = await _events(db)
        assert len(rows) == 1 and rows[0][0] == "surround_vote"
        ok, err = verify_attestation_evidence(json.loads(rows[0][1]))
        assert ok, err
        pending = await db.get_pending_slashing_evidence()
        assert len(pending) == 1 and pending[0].get("att_a") and pending[0].get("att_b")
    finally:
        F._ENFORCE_SURROUND_DETECTION = True
        await db.connection.close()
        os.remove(path)


@pytest.mark.asyncio
async def test_surround_vote_detected_across_targets():
    """A later vote whose (source,target) span surrounds an earlier retained one is detected."""
    key = PQPrivateKey.generate()
    db, path = await _fresh_db_with_validator(key)
    F._ENFORCE_SURROUND_DETECTION = True
    try:
        inner = _signed_att(key, slot=20, epoch=3, block_hash="bb" * 32, source=2, target=3)
        outer = _signed_att(key, slot=40, epoch=5, block_hash="aa" * 32, source=0, target=5)
        await F.record_block_attestations(db, _block([inner]))
        await F.record_block_attestations(db, _block([outer]))
        rows = await _events(db)
        assert len(rows) == 1 and rows[0][0] == "surround_vote"
        ok, err = verify_attestation_evidence(json.loads(rows[0][1]))
        assert ok, err
    finally:
        F._ENFORCE_SURROUND_DETECTION = True
        await db.connection.close()
        os.remove(path)


@pytest.mark.asyncio
async def test_observe_gate_detects_but_does_not_record():
    """With the gate OFF (default), a real conflict is detected (logged) but NO event is recorded —
    the observe-first posture that lets an honest soak run before enforcing."""
    key = PQPrivateKey.generate()
    db, path = await _fresh_db_with_validator(key)
    F._ENFORCE_SURROUND_DETECTION = False  # explicit observe posture (enabled by default now)
    try:
        a = _signed_att(key, slot=32, epoch=1, block_hash="aa" * 32, source=0, target=1)
        b = _signed_att(key, slot=32, epoch=1, block_hash="bb" * 32, source=0, target=1)
        assert await F._detect_attestation_equivocation(
            db, b, key.public_key.to_bytes()) is False  # no retained vote yet
        await F.record_block_attestations(db, _block([a]))
        await F.record_block_attestations(db, _block([b]))
        assert await _events(db) == []  # detected but observe-gated → not recorded
    finally:
        F._ENFORCE_SURROUND_DETECTION = True
        await db.connection.close()
        os.remove(path)


@pytest.mark.asyncio
async def test_an_honest_vote_seen_in_two_blocks_is_never_a_slash():
    """REGRESSION (all three testnet validators were slashed): the node's vote store did not keep
    a vote's checkpoint roots, so the copy it compared a re-included vote against lacked them,
    differed, and was flagged as a double vote — and the detector recorded the slash without
    checking the evidence. The roots are kept now, and evidence must verify before it is
    recorded."""
    key = PQPrivateKey.generate()
    db, path = await _fresh_db_with_validator(key)
    F._ENFORCE_SURROUND_DETECTION = True
    try:
        a = _signed_att(key, slot=10, epoch=1, block_hash="a1" * 32, source=0, target=1)
        await F.record_block_attestations(db, _block([a]))
        await db.connection.execute("UPDATE attestation_votes SET source_root = '', "
                                    "target_root = ''")  # a store that dropped the roots
        await F.record_block_attestations(db, _block([a]))   # the same vote, another block
        assert await _events(db) == []
    finally:
        await db.connection.close()
        os.remove(path)
