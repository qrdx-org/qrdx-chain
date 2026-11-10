"""
History pruning (qrdx/history_pruning.py): a full node drops the proposer signatures, vote
signatures and sections of blocks far below finality. Their hashes still verify, the chain index
still reads their votes, and what needs the dropped bodies refuses rather than misbehaving.
"""

import os
import tempfile

import pytest

from qrdx import block_codec
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.history_pruning import (
    ENV,
    HistoryPruned,
    min_retention,
    prune,
    pruned_below,
    require_history,
    retention,
    strip,
)
from qrdx.validator.attestation_block import extract_attestations_from_dict
from qrdx.validator.block_verification import _parse_block_content
from chain_rows import block_content, put_block

VOTE = {"slot": 9, "epoch": 0, "block_hash": "bh", "validator_address": "0xPQ" + "a" * 64,
        "validator_index": 0, "signature": "ab" * 1600, "source_epoch": 0, "target_epoch": 1,
        "source_root": "", "target_root": "cd" * 32, "created_at": "2026-01-01T00:00:00"}


@pytest.fixture
async def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    d = await DatabaseSQLite.create(path)
    try:
        for h in range(1, 31):
            content = {"number": h, "parent_hash": "00" * 32, "proposer_signature": "ef" * 1650,
                       "attestations": [VOTE], "slashing_evidence": [], "graffiti": "", "slot": h}
            put_block(d, h, f"{h:064x}", repr(content), validator_signature="ef" * 1650)
            d.store["exchange_sections"].put(f"{h:064x}", b'["' + b"x" * 5000 + b'"]')
        await d.connection.commit()
        yield d
    finally:
        await d.close()
        for p in (path, path + "-wal", path + "-shm"):
            if os.path.exists(p):
                os.remove(p)


def test_an_archive_is_the_default_and_a_short_window_is_refused():
    assert retention({}) == 0 and retention({ENV: "0"}) == 0
    assert retention({ENV: str(min_retention())}) == min_retention()
    with pytest.raises(ValueError, match="minimum"):
        retention({ENV: str(min_retention() - 1)})
    with pytest.raises(ValueError, match="number"):
        retention({ENV: "a week"})


def test_a_stripped_block_keeps_its_header_and_its_votes():
    bc = {"number": 3, "proposer_signature": "ef" * 10, "attestations": [VOTE], "body_root": "aa"}
    out = strip(bc)
    assert "proposer_signature" not in out and out["pruned"] and out["body_root"] == "aa"
    (vote,) = extract_attestations_from_dict(out)                     # still decodes
    assert vote.target_epoch == 1 and vote.validator_address == VOTE["validator_address"]
    assert vote.signature == b""


async def test_pruning_runs_behind_finality_in_batches(db):
    assert await pruned_below(db) == 0
    assert await prune(db, finalized_height=25, window=10) == 14        # blocks 1..14
    assert await pruned_below(db) == 15
    assert await prune(db, finalized_height=25, window=10) == 0         # nothing new
    for row in db.store["blocks"].scan():
        height, signature = row.block_height, row.validator_signature
        bc = _parse_block_content(block_content(db, height))
        assert bool(bc.get("pruned")) == (height < 15), height
        assert (signature is None) == (height < 15)
    assert db.store["exchange_sections"].count() == 16                  # 15..30 keep sections
    assert await prune(db, finalized_height=25, window=0) == 0          # an archive node


async def test_what_needs_the_pruned_bodies_refuses(db):
    from qrdx.derived_state_rebuild import rebuild_derived_state_interleaved
    from qrdx.rpc.modules.p2p import blocks_for_transfer

    await prune(db, finalized_height=25, window=10)
    await require_history(db, 15, "x")                                   # above: fine
    with pytest.raises(HistoryPruned, match="below block 15"):
        await require_history(db, 3, "serving these blocks")
    with pytest.raises(HistoryPruned):
        await blocks_for_transfer(db, 1, 10)
    assert len(await blocks_for_transfer(db, 15, 10)) == 10
    with pytest.raises(HistoryPruned, match="replay from genesis"):
        await rebuild_derived_state_interleaved(db)
    assert db.store["blocks"].count() == 30                             # nothing was reset
