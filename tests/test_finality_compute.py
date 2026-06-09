"""
Finality computation (links 3–4, observe-only): justified/finalized from votes.

Rules pinned:
  - justified(E): ≥ 2/3 of total validator stake target epoch E.
  - finalized(E): E justified AND E+1 justified.
Computed from the DB (validators table + attestation_votes) so any node derives it.
"""

import os
import tempfile

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator.finality import update_finality, finalized_block_height


async def _db_with_validators(n=3, stake="100000"):
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    addrs = []
    for i in range(n):
        a = f"0xPQ{i:02d}" + "00" * 16
        addrs.append(a)
        await db.connection.execute(
            "INSERT INTO validators (address, public_key, stake, effective_stake, status, activation_epoch) "
            "VALUES (?, '', ?, ?, 'active', 0)",
            (a, stake, stake),
        )
    await db.connection.commit()
    return db, path, addrs


async def _vote(db, addr, target, source=0, slot=0):
    await db.record_attestation_vote(addr, target, source, slot, "h")


async def test_supermajority_justifies_epoch():
    db, path, addrs = await _db_with_validators(4)
    try:
        # 3 of 4 (75%) target epoch 1 → clears the 0.667 (>2/3) threshold.
        await _vote(db, addrs[0], target=1)
        await _vote(db, addrs[1], target=1)
        await _vote(db, addrs[2], target=1)
        res = await update_finality(db)
        assert res["justified_epoch"] == 1
        assert res["finalized_epoch"] == -1  # epoch 2 not justified yet
    finally:
        await db.close(); os.remove(path)


async def test_exactly_two_thirds_does_not_justify():
    """0.667 means strictly more than 2/3: 2-of-3 (0.6667) must NOT justify."""
    db, path, addrs = await _db_with_validators(3)
    try:
        await _vote(db, addrs[0], target=1)
        await _vote(db, addrs[1], target=1)
        res = await update_finality(db)
        assert res["justified_epoch"] == -1
    finally:
        await db.close(); os.remove(path)


async def test_below_threshold_not_justified():
    db, path, addrs = await _db_with_validators(4)
    try:
        # 2 of 4 (50%) — below 2/3.
        await _vote(db, addrs[0], target=1)
        await _vote(db, addrs[1], target=1)
        res = await update_finality(db)
        assert res["justified_epoch"] == -1
    finally:
        await db.close(); os.remove(path)


async def test_consecutive_justification_finalizes_earlier_epoch():
    db, path, addrs = await _db_with_validators(4)
    try:
        # Epoch 1 and 2 both justified (3/4 each) ⇒ epoch 1 finalizes.
        for t in (1, 2):
            await _vote(db, addrs[0], target=t)
            await _vote(db, addrs[1], target=t)
            await _vote(db, addrs[2], target=t)
        res = await update_finality(db)
        assert res["justified_epoch"] == 2
        assert res["finalized_epoch"] == 1
        # Persisted to the epochs table.
        cur = await db.connection.execute("SELECT finalized FROM epochs WHERE epoch = 1")
        assert bool((await cur.fetchone())[0]) is True
    finally:
        await db.close(); os.remove(path)


async def _add_block(db, h, bh):
    await db.add_block(block_hash=bh, block_height=h, block_content="",
                       validator_address="0xPQ" + "00" * 32, timestamp=1)


async def test_finalized_block_height_requires_supermajority_on_the_block():
    db, path, addrs = await _db_with_validators(4)
    try:
        await _add_block(db, 10, "blkA")
        await _add_block(db, 11, "blkB")
        # 3 of 4 (75%) attest specifically to blkA (height 10) → finalized.
        for a in addrs[:3]:
            await db.record_attestation_vote(a, target_epoch=1, source_epoch=0, slot=10, block_hash="blkA")
        # Only 1 of 4 attests blkB → not finalized.
        await db.record_attestation_vote(addrs[3], target_epoch=1, source_epoch=0, slot=11, block_hash="blkB")
        assert await finalized_block_height(db) == 10
    finally:
        await db.close(); os.remove(path)


async def test_finalized_block_height_none_below_threshold():
    db, path, addrs = await _db_with_validators(4)
    try:
        await _add_block(db, 5, "blkX")
        for a in addrs[:2]:  # 2 of 4 = 50%
            await db.record_attestation_vote(a, target_epoch=1, source_epoch=0, slot=5, block_hash="blkX")
        assert await finalized_block_height(db) == -1
    finally:
        await db.close(); os.remove(path)


async def test_no_validators_or_votes_is_safe():
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(db_path=path)
    try:
        res = await update_finality(db)
        assert res == {"justified_epoch": -1, "finalized_epoch": -1}
    finally:
        await db.close(); os.remove(path)
