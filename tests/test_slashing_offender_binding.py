"""
A slashing proof convicts whoever SIGNED it — never a name written next to it.

Evidence carries a top-level ``proposer`` field for convenience, but neither verifier
checks it, and the recorder used to take the offender from it. So any proposer could sign
two conflicting headers (or attestations) with its OWN key, set ``proposer`` to an honest
validator, and include that in its block: the proof verified, the honest validator was
recorded as the offender, and the finalized-epoch penalty then cut its stake by half and
ejected it — while the attacker lost nothing.

The offender, condition, slot and epoch now all come from the verified content
(``slashing_block.verified_offence``).
"""
import os
import tempfile

import pytest

from qrdx.constants import SLOTS_PER_EPOCH
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator.slashing_block import (
    BLOCK_SLASHING_KEY, make_attestation_evidence, make_double_sign_evidence,
    record_block_slashing_evidence, verified_offence,
)

from test_slashing_evidence import _signed_header
from test_surround_vote_evidence import _pub, _signed_att


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


def _double_sign(key, slot=5):
    h1, addr = _signed_header(key, slot=slot, state_root="11" * 32)
    h2, _ = _signed_header(key, slot=slot, state_root="22" * 32)
    return make_double_sign_evidence(h1, h2), addr


def _double_vote(key, slot=40):
    epoch = slot // SLOTS_PER_EPOCH
    a = _signed_att(key, slot=slot, epoch=epoch, block_hash="aa" * 32, source=0, target=epoch)
    b = _signed_att(key, slot=slot, epoch=epoch, block_hash="bb" * 32, source=0, target=epoch)
    return make_attestation_evidence(a, b, _pub(key)), key.public_key.to_address()


async def _offenders(db):
    return {r["validator_address"] for r in await db.get_slashing_events()}


@pytest.mark.parametrize("make", [_double_sign, _double_vote], ids=["double_sign", "double_vote"])
async def test_a_forged_offender_name_convicts_the_signer_not_the_victim(db, make):
    attacker, victim = PQPrivateKey.generate(), PQPrivateKey.generate()
    victim_addr = victim.public_key.to_address()
    ev, attacker_addr = make(attacker)
    ev["proposer"] = victim_addr

    await record_block_slashing_evidence(db, {BLOCK_SLASHING_KEY: [ev]})

    offenders = await _offenders(db)
    assert victim_addr not in offenders, "an honest validator was slashed by a forged name"
    assert offenders == {attacker_addr}, "the signer of the conflicting messages is the offender"


def test_the_epoch_comes_from_the_slot_not_a_free_field():
    """A free ``epoch`` could be pushed out so the penalty never finalizes."""
    ev, _ = _double_sign(PQPrivateKey.generate(), slot=3 * SLOTS_PER_EPOCH + 1)
    ev["epoch"] = 10 ** 9
    _offender, _cond, slot, epoch = verified_offence(ev)
    assert (slot, epoch) == (3 * SLOTS_PER_EPOCH + 1, 3)


def test_a_mislabelled_condition_does_not_verify():
    ev, _ = _double_sign(PQPrivateKey.generate())
    ev["condition"] = "surround_vote"        # routes to the attestation verifier, which fails
    assert verified_offence(ev) is None
    ev2, _ = _double_vote(PQPrivateKey.generate())
    ev2["condition"] = "double_sign"
    assert verified_offence(ev2) is None


def test_the_recorded_condition_is_canonical():
    ev, _ = _double_vote(PQPrivateKey.generate())
    ev["condition"] = "double_vote"
    assert verified_offence(ev)[1] == "surround_vote"
