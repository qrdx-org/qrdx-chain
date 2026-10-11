"""
Casper FFG finality (qrdx/validator/ffg.py; docs/KNOWN_ISSUES.md "Finality was not bound to a
branch").

Finality used to justify an epoch on 2/3 of ANY votes for it, whichever branch they were for, and
validators voted every slot — so a validator switching forks supported both, and a long fork
finalized on both sides (seen at 250 ms slots: a permanent network split). What must hold now:

  * checkpoint *t* is justified when ≥ the threshold of stake voted (source → t) with the target
    root THIS chain's checkpoint and a source justified on this chain;
  * justified *t−1* is finalized when the threshold voted exactly the link t−1 → t;
  * votes for another branch's checkpoint, or from an unjustified source, never count — so two
    branches finalize conflicting checkpoints only if a third of the stake double-votes;
  * finality is computed from the votes canonical blocks carry, so every node with the chain
    agrees; it resumes from the stored finalized checkpoint, and justification above it follows a
    reorg;
  * import accepts a block only if every carried vote is valid for its chain
    (verify_block_votes); the honest validator never signs a double or surround vote
    (SigningRecord); the proposer includes only votes valid for, and not yet on, its chain.
"""
import hashlib
import os
import tempfile

import pytest

from qrdx.constants import SLOTS_PER_EPOCH as S
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator import ffg
from qrdx.validator.attestation import Attestation
from qrdx.validator.finality import finalized_block_height, update_finality


@pytest.fixture(scope="module")
def keys():
    return [PQPrivateKey.generate() for _ in range(4)]


def _addr(key):
    return key.public_key.to_address()


class Chain:
    """A canonical chain in a fresh database, with a validator set of real keys."""

    def __init__(self, db, keys, stakes=None):
        self.db, self.keys = db, keys
        self.stakes = stakes or ["100000"] * len(keys)
        self.height = -1
        self.hashes = []  # by height
        self.slots = []

    @classmethod
    async def create(cls, keys, stakes=None):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db = await DatabaseSQLite.create(path)
        c = cls(db, keys, stakes)
        c.path = path
        for k, stake in zip(keys, c.stakes, strict=True):
            await db.connection.execute(
                "INSERT INTO validators (address, public_key, stake, effective_stake, status, "
                "activation_epoch) VALUES (?, ?, ?, ?, 'active', 0)",
                (_addr(k), k.public_key.to_bytes().hex(), stake, stake),
            )
        await db.record_genesis_validators(
            [{"address": _addr(k), "public_key": k.public_key.to_bytes().hex(), "stake": st}
             for k, st in zip(keys, c.stakes, strict=True)])
        await db.connection.commit()
        await c.block(0)  # genesis
        return c

    async def close(self):
        await self.db.connection.close()
        os.remove(self.path)

    async def block(self, slot, votes=(), tag="a"):
        self.height += 1
        h = hashlib.sha256(f"{tag}:{self.height}:{slot}".encode()).hexdigest()
        content = {"number": self.height, "slot": slot, "epoch": slot // S,
                   "parent_hash": self.hashes[-1] if self.hashes else "0" * 64,
                   "attestations": [v.to_dict() for v in votes]}
        await self.db.connection.execute(
            "INSERT INTO blocks (block_hash, block_height, content, timestamp) VALUES (?, ?, ?, 0)",
            (h, self.height, repr(content)),
        )
        await self.db.connection.commit()
        self.hashes.append(h)
        self.slots.append(slot)
        return h

    async def truncate(self, height):
        """Drop blocks above ``height`` (a reorg's rollback)."""
        await self.db.connection.execute("DELETE FROM blocks WHERE block_height > ?", (height,))
        await self.db.connection.commit()
        self.height = height
        del self.hashes[height + 1:]
        del self.slots[height + 1:]

    def checkpoint(self, epoch):
        best = 0
        for h, s in enumerate(self.slots):
            if h > 0 and s < epoch * S:
                best = h
        return self.hashes[best]

    def vote(self, i, source, target, target_root=None, source_root=None, slot=None):
        key = self.keys[i]
        att = Attestation(
            slot=slot if slot is not None else target * S + 1, epoch=target,
            block_hash=self.hashes[-1], validator_address=_addr(key), validator_index=i,
            signature=b"", source_epoch=source, target_epoch=target,
            source_root=source_root or self.checkpoint(source),
            target_root=target_root or self.checkpoint(target),
        )
        att.signature = key.sign(att.signing_root).to_bytes()
        return att

    async def epochs(self, first, last, voters, tag="a"):
        """For each epoch: its first block, then (two slots in) a block carrying every voter's
        vote from the previous epoch to this one."""
        for e in range(first, last + 1):
            await self.block(e * S, tag=tag)
            await self.block(e * S + 2, [self.vote(i, e - 1, e) for i in voters], tag=tag)


async def test_votes_justify_and_a_link_finalizes(keys):
    c = await Chain.create(keys)
    try:
        await c.epochs(1, 1, voters=[0, 1, 2])          # 3 of 4: justifies 1, finalizes 0 (genesis)
        res = await update_finality(c.db)
        assert res == {"justified_epoch": 1, "finalized_epoch": 0}
        await c.epochs(2, 3, voters=[0, 1, 2])
        res = await update_finality(c.db)
        assert res == {"justified_epoch": 3, "finalized_epoch": 2}
        cur = await c.db.connection.execute("SELECT finalized FROM epochs WHERE epoch = 2")
        assert bool((await cur.fetchone())[0])
    finally:
        await c.close()


async def test_the_finalized_height_is_the_checkpoints_block(keys):
    c = await Chain.create(keys)
    try:
        await c.epochs(1, 3, voters=[0, 1, 2])
        await update_finality(c.db)
        # epoch 2's checkpoint: the last block before slot 2*S — epoch 1's vote-carrying block
        assert c.hashes[await finalized_block_height(c.db)] == c.checkpoint(2)
    finally:
        await c.close()


async def test_two_thirds_exactly_does_not_justify(keys):
    c = await Chain.create(keys[:3])
    try:
        await c.epochs(1, 2, voters=[0, 1])  # 2 of 3 = 0.6667 < 0.667
        assert (await update_finality(c.db))["justified_epoch"] == 0
    finally:
        await c.close()


async def test_votes_for_another_branchs_checkpoint_do_not_count(keys):
    c = await Chain.create(keys)
    try:
        await c.block(S)
        other = hashlib.sha256(b"another branch").hexdigest()
        await c.block(S + 2, [c.vote(i, 0, 1, target_root=other) for i in range(4)])
        assert (await update_finality(c.db))["justified_epoch"] == 0
    finally:
        await c.close()


async def test_votes_from_an_unjustified_source_do_not_count(keys):
    c = await Chain.create(keys)
    try:
        await c.epochs(1, 1, voters=[0])                     # epoch 1 NOT justified
        await c.block(2 * S)
        await c.block(2 * S + 2, [c.vote(i, 1, 2) for i in range(4)])   # source 1: unjustified
        assert (await update_finality(c.db))["justified_epoch"] == 0
    finally:
        await c.close()


async def test_a_skipped_link_justifies_but_does_not_finalize(keys):
    c = await Chain.create(keys)
    try:
        await c.epochs(1, 1, voters=[0, 1, 2])               # justify 1 (finalizes genesis)
        await c.block(2 * S)
        await c.block(3 * S)
        await c.block(3 * S + 2, [c.vote(i, 1, 3) for i in range(4)])  # 1 → 3: no direct link
        res = await update_finality(c.db)
        assert res == {"justified_epoch": 3, "finalized_epoch": 0}
    finally:
        await c.close()


async def test_honest_validators_cannot_finalize_two_branches(keys):
    """The split that happened at 250 ms: a fork outliving the finality lag. Each validator votes
    once per epoch, on the branch it sees; a branch's blocks carry only votes valid for it. With
    3 of 4 validators on branch A, A finalizes and B cannot even justify."""
    a = await Chain.create(keys)
    b = await Chain.create(keys)
    try:
        for c in (a, b):
            await c.epochs(1, 1, voters=[0, 1, 2, 3])        # common history, epoch 1 justified
        await a.epochs(2, 4, voters=[0, 1, 2], tag="A")
        await b.epochs(2, 4, voters=[3], tag="B")
        ra, rb = await update_finality(a.db), await update_finality(b.db)
        assert ra["finalized_epoch"] == 3 and rb["finalized_epoch"] == 0
        assert rb["justified_epoch"] == 1
    finally:
        await a.close()
        await b.close()


async def test_justification_above_finality_follows_a_reorg(keys):
    c = await Chain.create(keys)
    try:
        await c.epochs(1, 2, voters=[0, 1, 2])
        assert await update_finality(c.db) == {"justified_epoch": 2, "finalized_epoch": 1}
        fork = c.height - 2                                  # drop epoch 2's two blocks
        await c.truncate(fork)
        await c.block(2 * S + 1, tag="B")                    # epoch 2 on another branch, no votes
        res = await update_finality(c.db)
        assert res == {"justified_epoch": 1, "finalized_epoch": 1}
        cur = await c.db.connection.execute("SELECT justified FROM epochs WHERE epoch = 2")
        assert not bool((await cur.fetchone())[0])
    finally:
        await c.close()


async def test_finality_resumes_from_the_stored_checkpoint(keys, monkeypatch):
    c = await Chain.create(keys)
    try:
        await c.epochs(1, 4, voters=[0, 1, 2])
        await update_finality(c.db)
        seen = []
        from qrdx import chain_index

        real = chain_index.ffg_votes

        async def spy(db, from_target_epoch, *rest):
            seen.append(from_target_epoch)
            return await real(db, from_target_epoch, *rest)

        monkeypatch.setattr(chain_index, "ffg_votes", spy)
        assert (await update_finality(c.db))["finalized_epoch"] == 3
        assert seen == [4]  # only votes above the finalized checkpoint are read
    finally:
        await c.close()


# ── import validity ──────────────────────────────────────────────────────────────────────


async def _check(c, votes, slot):
    return await ffg.verify_block_votes(
        c.db, {"slot": slot, "attestations": [v.to_dict() for v in votes]}, c.height + 1, slot // S)


async def test_import_accepts_valid_votes_and_rejects_every_kind_of_bad_one(keys):
    c = await Chain.create(keys)
    try:
        await c.block(S)
        slot = S + 2
        assert await _check(c, [c.vote(0, 0, 1), c.vote(1, 0, 1)], slot) == (True, "")
        bad_sig = c.vote(0, 0, 1)
        bad_sig.signature = c.vote(1, 0, 1).signature
        malformed = c.vote(0, 0, 1)
        malformed.source_root = "zz"
        cases = {
            "bad signature": bad_sig,
            "not this chain's checkpoint": c.vote(0, 0, 1, target_root="ab" * 32),
            "source epoch": c.vote(0, 1, 1),
            "target epoch outside": c.vote(0, 0, 2),
            "malformed checkpoint roots": malformed,
        }
        for reason, vote in cases.items():
            ok, err = await _check(c, [vote], slot)
            assert not ok and reason in err, (reason, err)
        stranger = PQPrivateKey.generate()
        c.keys.append(stranger)
        ok, err = await _check(c, [c.vote(len(c.keys) - 1, 0, 1)], slot)
        assert not ok and "no key" in err
        ok, err = await _check(c, [c.vote(0, 0, 1), c.vote(0, 0, 1)], slot)
        assert not ok and "two votes" in err
    finally:
        c.keys[:] = c.keys[:4]
        await c.close()


async def test_a_deposited_validators_key_comes_from_its_deposit(keys):
    """Keys are read from the chain (genesis, then STAKE_DEPOSITs) so every node verifies votes
    with the same key; a deposit naming someone else's key gives the depositor no key."""
    import json

    c = await Chain.create(keys[:3])
    try:
        newcomer, impostor = keys[3], PQPrivateKey.generate()
        await c.block(1)
        from qrdx import chain_index

        await chain_index.sync(c.db)  # (creates the index tables)
        for who, key in ((_addr(newcomer), newcomer), (_addr(impostor), newcomer)):
            await c.db.connection.execute(
                "INSERT INTO chain_index_ops (height, epoch, position, op) VALUES (?, 0, 0, ?)",
                (c.height, json.dumps({"type": "deposit", "address": who,
                                       "public_key": key.public_key.to_bytes().hex()})))
        await c.db.connection.commit()
        assert await ffg.validator_key(c.db, _addr(newcomer), c.height + 1) == \
            newcomer.public_key.to_bytes()
        assert await ffg.validator_key(c.db, _addr(impostor), c.height + 1) is None
    finally:
        await c.close()


# ── the honest validator and the proposer ────────────────────────────────────────────────


async def test_the_signing_record_refuses_double_and_surround_votes(keys):
    c = await Chain.create(keys)
    try:
        rec, v = ffg.SigningRecord(c.db), _addr(keys[0])
        first = (1, "aa" * 32, 3, "bb" * 32)
        assert await rec.may_sign(v, first)
        await rec.record(v, first)
        assert await rec.may_sign(v, first)                           # the same vote again
        assert not await rec.may_sign(v, (1, "aa" * 32, 3, "cc" * 32))  # double
        assert not await rec.may_sign(v, (0, "aa" * 32, 4, "dd" * 32))  # surrounds it
        assert await rec.may_sign(v, (3, "bb" * 32, 4, "dd" * 32))     # the next honest vote
        assert not await ffg.SigningRecord(c.db).may_sign(v, (1, "aa" * 32, 3, "ee" * 32))
    finally:
        await c.close()


async def test_the_proposer_includes_only_votes_valid_for_and_missing_from_its_chain(keys):
    c = await Chain.create(keys)
    try:
        await c.block(S)
        carried = c.vote(0, 0, 1)
        await c.block(S + 1, [carried])
        pool = [carried, c.vote(1, 0, 1), c.vote(2, 0, 1, target_root="ab" * 32),
                c.vote(3, 0, 1)]
        pool[3].signature = pool[1].signature                          # forged
        chosen = await ffg.votes_to_include(c.db, pool, 1, 64)
        assert [a.validator_address for a in chosen] == [_addr(keys[1])]
    finally:
        await c.close()


async def test_an_honest_validators_vote_is_from_its_latest_justified_checkpoint(keys):
    c = await Chain.create(keys)
    try:
        await c.epochs(1, 2, voters=[0, 1, 2])
        await c.block(3 * S)
        vote = await ffg.vote_for(c.db, 3)
        assert vote == (2, c.checkpoint(2), 3, c.checkpoint(3))
        assert ffg.vote_slot(3) == 3 * S + ffg.VOTE_OFFSET_SLOTS
    finally:
        await c.close()
