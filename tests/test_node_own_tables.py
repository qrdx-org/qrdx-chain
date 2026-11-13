"""
The node's own tables, in its store (docs/STORAGE.md, S4 and S5): its validator's stake records
(validator/stake.py), the validator set it displays, the votes the explorer lists, and the
legacy mempool, which never held anything.
"""
import os
import tempfile
from decimal import Decimal

import pytest

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator.stake import StakeManager, WithdrawalStatus


@pytest.fixture
async def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)
    d = await DatabaseSQLite.create(path)
    try:
        yield d
    finally:
        await d.close()


async def test_a_validators_stake_records_survive_a_restart(db):
    """Deposits, a withdrawal and a slashing are stored, and a new manager loads them back:
    the stake, the withdrawal still pending, the deposit history and the counter."""
    m = StakeManager(database=db)
    await m.deposit("v1", Decimal("150000"), "tx1", 10, 1)
    await m.deposit("v1", Decimal("50000"), "tx2", 11, 1)
    w = await m.request_withdrawal("v1", Decimal("20000"), current_epoch=2)
    await m.slash("v1", Decimal("0.1"), "test")

    again = StakeManager(database=db)
    await again.load_from_database()
    assert again._stakes["v1"] == m._stakes["v1"]
    assert [d.tx_hash for d in again._deposits] == ["tx1", "tx2"]
    pending = again._pending_withdrawals["v1"]
    assert [(p.id, p.amount, p.status) for p in pending] == [
        (w.id, Decimal("20000"), WithdrawalStatus.PENDING)
    ]
    assert db.store["validator_stakes"].get("v1").slashed == 1
    # The slashing's record took the next id from the same counter: a later request does not
    # overwrite it.
    assert again._withdrawal_counter == w.id + 1
    later = await again.request_withdrawal("v1", Decimal("1000"), current_epoch=3)
    assert later.id == w.id + 2
    statuses = {r.id: r.status for r in db.store["stake_withdrawals"].scan()}
    assert statuses == {w.id: "pending", w.id + 1: "completed", later.id: "pending"}


async def test_cancelling_a_withdrawal_updates_its_own_record(db):
    m = StakeManager(database=db)
    await m.deposit("v1", Decimal("300000"), "tx1", 10, 1)
    first = await m.request_withdrawal("v1", Decimal("1000"), current_epoch=2)
    second = await m.request_withdrawal("v1", Decimal("2000"), current_epoch=2)
    assert await m.cancel_withdrawal(first.id)
    rows = {r.id: r for r in db.store["stake_withdrawals"].scan()}
    assert rows[first.id].status == "cancelled" and rows[first.id].completed_at
    assert rows[second.id].status == "pending" and rows[second.id].completed_at is None


async def test_the_displayed_set_is_ordered_by_effective_stake(db):
    shown = db.store["validators"]
    for address, stake, status in (("a", "100", "active"), ("b", "1e3", "active"),
                                   ("c", "250.5", "exited"), ("d", "x", "active")):
        shown.put(address=address, public_key="pk", stake=stake, effective_stake=stake,
                  status=status, activation_epoch=0, slashed=0)
    assert [v["address"] for v in await db.get_validators()] == ["b", "c", "a", "d"]
    assert [v["address"] for v in await db.get_validators(status="active")] == ["b", "a", "d"]
    assert (await db.get_validator_info("c"))["status"] == "exited"
    assert await db.get_validator_info("nobody") is None


async def test_the_explorer_lists_the_votes_blocks_carried(db):
    """(They were read from an attestations table nothing wrote: always empty.)"""
    db.store["validators"].put(address="v1", public_key="pk", stake="5", effective_stake="5",
                               status="active")
    for v, slot, index in (("v1", 9, 0), ("v2", 9, 1), ("v1", 17, 0)):
        await db.record_attestation_vote(
            validator_address=v, target_epoch=slot // 8, source_epoch=slot // 8 - 1, slot=slot,
            block_hash=f"h{slot}", epoch=slot // 8, validator_index=index, signature="s",
        )
    rows = await db.get_attestations_filtered({}, limit=10, offset=0)
    assert [(r["validator_address"], r["slot"]) for r in rows] == [
        ("v1", 17), ("v1", 9), ("v2", 9)
    ]
    assert rows[0]["stake"] == "5" and rows[2]["stake"] is None
    by = await db.get_attestations_filtered({"validator_address": "v1"}, 10, 0)
    assert [r["slot"] for r in by] == [17, 9]
    assert [r["slot"] for r in await db.get_attestations_filtered({"epoch": 1}, 10, 0)] == [9, 9]
    assert len(await db.get_attestations_filtered({"slot": 9, "block_hash": "h9"}, 1, 1)) == 1


async def test_the_legacy_mempool_holds_nothing(db):
    """Its insert never stored a transaction (it named columns its table did not have), and the
    proposer reads it: it stays empty, so no legacy transaction reaches a block."""
    assert await db.add_pending_transaction("ab" * 40) is True
    assert await db.get_pending_transaction_count() == 0
    assert await db.get_all_pending_transaction_hashes() == []
    assert await db.get_need_propagate_transactions() == []
    assert await db.get_pending_transactions_limit(1024) == []
