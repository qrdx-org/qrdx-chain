"""
The validators' state in the signed root (qrdx/validator/validator_root.py, chain-spec feature
``validator_state_root``): ``S_E`` of the block's epoch on its parent chain, and a hash chain of
the staking logs block application writes. A snapshot's validator state can then be verified
against a signed root (docs/CHECKPOINT_SYNC.md). The root must be a function of the chain:
never of row ids, of a node's reorg history, or of how an amount happened to be spelled.
"""

import os
import tempfile

import pytest
from test_epoch_state import G, J, Chain, chain  # noqa: F401  (fixture)

from qrdx import chain_spec
from qrdx.constants import SLOTS_PER_EPOCH
from qrdx.crypto.hashing import unified_state_root
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator import epoch_state as ES
from qrdx.validator import validator_root as VR


@pytest.fixture(autouse=True)
def _fresh_memo():
    VR.clear_memo()
    yield
    VR.clear_memo()


async def _db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return await DatabaseSQLite.create(path), path


async def _close(db, path):
    await db.connection.close()
    for p in (path, path + "-wal", path + "-shm"):
        if os.path.exists(p):
            os.remove(p)


def test_it_is_a_rule_of_new_networks():
    assert "validator_state_root" in chain_spec.FEATURES
    assert "validator_state_root" in chain_spec.GENESIS_DEFAULT_FEATURES
    base = unified_state_root("1" * 64, "2" * 128, "3" * 128, "4" * 128, "5" * 128)
    assert unified_state_root("1" * 64, "2" * 128, "3" * 128, "4" * 128, "5" * 128, None) == base
    assert unified_state_root("1" * 64, "2" * 128, "3" * 128, "4" * 128, "5" * 128, "6" * 128) != base


def test_the_log_chain_binds_order_and_not_spelling():
    a = [["staking_ops", [["delegate", "x", "v", "5"], ["undelegate", "x", "v", None]]]]
    b = [["staking_ops", [["undelegate", "x", "v", None], ["delegate", "x", "v", "5"]]]]
    assert VR.fold(VR.EMPTY, 7, a) != VR.fold(VR.EMPTY, 7, b)            # the order counts
    assert VR.fold(VR.EMPTY, 7, a) != VR.fold(VR.EMPTY, 8, a)            # and the block
    assert VR.fold(VR.EMPTY, 7, []) == VR.EMPTY                          # nothing logged
    assert VR._number("1000.0") == VR._number("1E+3") == "1000"
    assert VR._number("0E-18") == "0" and VR._number("0.50") == "0.5"


async def test_the_root_is_a_function_of_the_chain_not_of_row_ids_or_history():
    """Node B logs a deposit on a branch it then abandons for A's chain: its AUTOINCREMENT ids
    have moved on and it memoized roots of the orphaned blocks, yet every root equals A's."""
    (da, pa), (db_, pb) = await _db(), await _db()
    try:
        a, b = Chain(da, "a"), Chain(db_, "a")
        for c in (a, b):
            await c.genesis()
            await c.epoch(1)
            await c.epoch(2, deposits=[(G[0], "5")])
        b.tag = "x"
        await b.epoch(3, deposits=[(J, "500000"), (J, "1")])
        await b.epoch(4, exits=[G[1]])
        await VR.log_root(b.db, b.height)                                  # memoized there
        await b.rollback(2)
        b.tag = "a"
        for c in (a, b):
            await c.epoch(3, deposits=[(J, "500000.0")])                    # (spelled apart)
            await c.epoch(4, exits=[G[2]])
            for e in range(5, 9):
                await c.epoch(e)
        b_ids = await (await db_.connection.execute("SELECT MAX(id) FROM validator_deposits")).fetchone()
        a_ids = await (await da.connection.execute("SELECT MAX(id) FROM validator_deposits")).fetchone()
        assert b_ids[0] > a_ids[0]                                         # the ids differ
        for h in range(a.height + 1):
            assert await VR.log_root(a.db, h) == await VR.log_root(b.db, h), h
        slot = 9 * SLOTS_PER_EPOCH + 1
        ra = await VR.compute(a.db, a.height + 1, slot)
        VR.clear_memo()
        assert await VR.compute(b.db, b.height + 1, slot) == ra
        assert len(ra) == 128
    finally:
        await _close(da, pa)
        await _close(db_, pb)


async def test_the_root_moves_with_the_blocks_own_logs_and_with_the_set(chain):
    await chain.epoch(1)
    slot = 2 * SLOTS_PER_EPOCH + 1
    before = await VR.compute(chain.db, chain.height + 1, slot)
    await chain.db.log_validator_deposit(J, "", "500000", chain.height + 1, "pending")
    with_deposit = await VR.compute(chain.db, chain.height + 1, slot)
    assert with_deposit != before                                          # its own rows count
    await chain.db.connection.execute("DELETE FROM validator_deposits WHERE address = ?", (J,))
    assert await VR.compute(chain.db, chain.height + 1, slot) == before
    await chain.epoch(2, deposits=[(J, "500000")])
    s3 = await ES.state_at(chain.db, 3)
    s9 = await ES.state_at(chain.db, 9)
    assert ES.state_hash(s3) != ES.state_hash(s9)                          # J has activated
    r3 = await VR.compute(chain.db, chain.height + 1, 3 * SLOTS_PER_EPOCH + 1)
    r9 = await VR.compute(chain.db, chain.height + 1, 9 * SLOTS_PER_EPOCH + 1)
    assert r3 != r9                                                         # the epoch's set


async def _from_rows(db, height):
    """The log root recomputed from the rows alone (no memo, no stored entry)."""
    VR.clear_memo()
    await db.connection.execute(VR._SCHEMA)
    await db.connection.execute("DELETE FROM validator_log_roots")
    return await VR.log_root(db, height)


async def test_withdrawals_payouts_and_fee_income_are_committed(chain):
    await chain.epoch(1)
    h = chain.height
    before = await _from_rows(chain.db, h)
    conn = chain.db.connection
    await conn.execute("INSERT INTO validator_withdrawals (address, exit_epoch, amount, block_height) "
                       "VALUES (?, 3, '100', ?)", (G[0], h))
    after_withdrawal = await _from_rows(chain.db, h)
    assert after_withdrawal != before
    await conn.execute("INSERT INTO staking_payouts (payout_id, address, amount, kind, block_height) "
                       "VALUES (1, ?, '2.5', 'reward', ?)", (G[1], h))
    with_payout = await _from_rows(chain.db, h)
    await chain.db.log_staker_fee_income(h, 7)
    assert len({before, after_withdrawal, with_payout, await _from_rows(chain.db, h)}) == 4


async def test_a_reorg_never_reuses_a_stale_root(chain, monkeypatch):
    monkeypatch.setattr(VR, "STORE_EVERY", 2)
    await chain.epoch(1)
    chain.tag = "x"
    await chain.epoch(2, deposits=[(J, "500000")])
    await chain.epoch(3)
    stale = await VR.log_root(chain.db, chain.height)                      # memoized and stored
    stored = await (await chain.db.connection.execute(
        "SELECT COUNT(*) FROM validator_log_roots")).fetchone()
    assert stored[0] >= 1
    await chain.rollback(1)
    chain.tag = "a"
    await chain.epoch(2)
    await chain.epoch(3)
    fresh = await VR.log_root(chain.db, chain.height)
    assert fresh != stale
    VR.clear_memo()
    await chain.db.connection.execute("DELETE FROM validator_log_roots")
    assert await VR.log_root(chain.db, chain.height) == fresh               # computed from rows


async def test_a_restart_resumes_from_a_stored_root(chain, monkeypatch):
    monkeypatch.setattr(VR, "STORE_EVERY", 2)
    for e in range(1, 6):
        await chain.epoch(e, deposits=[(G[0], str(e))])
    await VR.log_root(chain.db, 3)                                          # stored at 3
    want = await _from_rows(chain.db, chain.height)
    await _from_rows(chain.db, 3)
    VR.clear_memo()                                                         # (a restart)
    seen = []
    real = VR.logs_between

    async def spy(db, low, high):
        seen.append((low, high))
        return await real(db, low, high)

    monkeypatch.setattr(VR, "logs_between", spy)
    assert await VR.log_root(chain.db, chain.height) == want
    assert seen == [(4, chain.height)]                                      # from block 3 on
