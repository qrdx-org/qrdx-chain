"""
Slashing ENFORCE convergence — the decisive safety property behind flipping
``_ENFORCE_SLASHING``.

The reason slashing enforce was gated: a slash EJECTS a validator + mutates the
validators-table hash, so if two nodes disagreed on the evidence they would disagree on the
eligible set → a divergent-set halt. The evidence-in-blocks transport makes the evidence a
pure function of the canonical chain; this test proves the CONSEQUENCE end-to-end: two
independent node DBs that import the SAME double-sign-evidence block and run the enforced
finalized-epoch slash reach a BYTE-IDENTICAL validators table (the offender slashed + ejected
identically on both). No malicious live node needed — the determinism is proven directly.

The honest integration testnet never double-signs, so this function-level convergence proof
is the appropriate validation for the flip; a live malicious-node harness would additionally
exercise detection + gossip under load, but the halt risk (divergent eligibility) is settled
here.
"""
import hashlib
import os
import tempfile

import pytest

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator.block_verification import reconstruct_signing_root
from qrdx.validator.slashing_block import make_double_sign_evidence, record_block_slashing_evidence, BLOCK_SLASHING_KEY
from qrdx.validator.epoch_loop import apply_epoch_slashings


async def _make_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return await DatabaseSQLite.create(path), path


async def _seed_validators(db, entries):
    """Seed an identical active validator set (address, pubkey_hex, stake)."""
    for addr, pub, stake in entries:
        await db.connection.execute(
            "INSERT INTO validators (address, public_key, stake, effective_stake, status, activation_epoch) "
            "VALUES (?, ?, ?, ?, 'active', 0)", (addr, pub, stake, stake))
    await db.connection.commit()


def _signed_header(key: PQPrivateKey, slot, **overrides):
    addr = key.public_key.to_address()
    bc = {
        "number": slot, "parent_hash": "ab" * 32, "state_root": "cd" * 32,
        "transactions_root": "ef" * 32, "timestamp": 1700000000,
        "proposer_address": addr, "proposer_public_key": key.public_key.to_bytes().hex(),
        "slot": slot, "epoch": 0, "randao_reveal": "11" * 32,
    }
    bc.update(overrides)
    bc["proposer_signature"] = key.sign(reconstruct_signing_root(bc)).to_bytes().hex()
    bc["hash"] = hashlib.sha256(repr(sorted(bc.items())).encode()).hexdigest()
    return bc


@pytest.mark.asyncio
async def test_enforce_slash_converges_byte_identical_across_nodes():
    offender = PQPrivateKey.generate()
    v_addr = offender.public_key.to_address()
    v_pub = offender.public_key.to_bytes().hex()
    others = [("0xPQhonest1", "pk1", "100000"), ("0xPQhonest2", "pk2", "100000")]
    validators = [(v_addr, v_pub, "100000")] + others

    (db_a, pa), (db_b, pb) = await _make_db(), await _make_db()
    try:
        # Two nodes, IDENTICAL validator set.
        await _seed_validators(db_a, validators)
        await _seed_validators(db_b, validators)
        assert await db_a.get_validators_table_hash() == await db_b.get_validators_table_hash()

        # A DOUBLE_SIGN by the offender (two validly-signed conflicting blocks, slot 9).
        h1 = _signed_header(offender, slot=9, state_root="11" * 32)
        h2 = _signed_header(offender, slot=9, state_root="22" * 32)
        block = {BLOCK_SLASHING_KEY: [make_double_sign_evidence(h1, h2)]}

        # Both nodes import the SAME evidence block → both record identical slashing_events.
        assert await record_block_slashing_evidence(db_a, block) == 1
        assert await record_block_slashing_evidence(db_b, block) == 1
        await db_a.connection.commit()
        await db_b.connection.commit()

        # Both nodes apply the ENFORCED finalized-epoch slash (offence epoch 0 ≤ finalized 5).
        await apply_epoch_slashings(db_a, epoch=5, enforce=True)
        await apply_epoch_slashings(db_b, epoch=5, enforce=True)
        await db_a.connection.commit()
        await db_b.connection.commit()

        # DECISIVE: the validators tables are byte-identical → no eligible-set divergence → no halt.
        ha, hb = await db_a.get_validators_table_hash(), await db_b.get_validators_table_hash()
        assert ha == hb, "enforce diverged the validators table across nodes (would halt)"

        # And the offender is slashed + ejected identically (50% of 100000 → 50000, status='slashed').
        for db in (db_a, db_b):
            cur = await db.connection.execute(
                "SELECT status, effective_stake FROM validators WHERE address = ?", (v_addr,))
            status, eff = await cur.fetchone()
            assert status == "slashed"
            from decimal import Decimal
            assert Decimal(eff) == Decimal("50000")
    finally:
        for db, p in ((db_a, pa), (db_b, pb)):
            await db.connection.close()
            for x in (p, p + "-wal", p + "-shm"):
                try:
                    os.remove(x)
                except OSError:
                    pass


@pytest.mark.asyncio
async def test_enforce_is_idempotent_no_double_slash():
    """Re-running the finalized-epoch slash must not double-penalise (evidence marked processed)."""
    offender = PQPrivateKey.generate()
    v_addr = offender.public_key.to_address()
    db, p = await _make_db()
    try:
        await _seed_validators(db, [(v_addr, offender.public_key.to_bytes().hex(), "100000")])
        h1 = _signed_header(offender, slot=3, state_root="11" * 32)
        h2 = _signed_header(offender, slot=3, state_root="22" * 32)
        await record_block_slashing_evidence(db, {BLOCK_SLASHING_KEY: [make_double_sign_evidence(h1, h2)]})
        await db.connection.commit()
        await apply_epoch_slashings(db, epoch=5, enforce=True)
        await apply_epoch_slashings(db, epoch=6, enforce=True)  # again — must be a no-op
        await db.connection.commit()
        cur = await db.connection.execute(
            "SELECT effective_stake FROM validators WHERE address = ?", (v_addr,))
        from decimal import Decimal
        assert Decimal((await cur.fetchone())[0]) == Decimal("50000")  # slashed once, not twice
    finally:
        await db.connection.close()
        for x in (p, p + "-wal", p + "-shm"):
            try:
                os.remove(x)
            except OSError:
                pass
