"""
Vote history is bounded (DatabaseSQLite.prune_attestation_votes, called by ffg.update).

Each node kept every vote it ever saw, with its 3.3 KB signature, in attestation_votes: ~0.5 KB a
block at 250 ms slots, for rows the slashing detector (a validator's 128 latest votes) never read
again. Rows more than ffg.VOTE_HISTORY_EPOCHS below the finalized epoch are dropped.
"""
import inspect
import os
import tempfile

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator import ffg


async def test_old_votes_are_pruned_recent_ones_kept():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = await DatabaseSQLite.create(path)
    try:
        for target in range(1, 41):
            db.store["attestation_votes"].put(
                validator_address="0xPQv", target_epoch=target, source_epoch=target - 1,
                slot=target * 32, block_hash=f"{target:064x}", epoch=target,
                signature="ab" * 3309)
        await db.connection.commit()
        assert await db.prune_attestation_votes(30) == 29
        kept = db.store["attestation_votes"].scan()
        assert (min(r.target_epoch for r in kept), len(kept)) == (30, 11)
        assert len(await db.get_validator_votes("0xPQv")) == 11
        assert await db.prune_attestation_votes(-5) == 0   # nothing finalized far enough yet
    finally:
        await db.connection.close()
        os.remove(path)


def test_finality_prunes_the_history_behind_it():
    src = inspect.getsource(ffg.update)
    assert "prune_attestation_votes(fin_epoch - VOTE_HISTORY_EPOCHS)" in src
    assert ffg.VOTE_HISTORY_EPOCHS > 128   # more than the detector reads per validator
