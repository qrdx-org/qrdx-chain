"""
A node refuses to start on a database that does not belong to its chain spec
(qrdx/node/main.py: _verify_chain_identity).

The restart rebuild replays the whole chain under the node's CURRENT rules, so starting under a
different spec would silently re-judge history: the database must record the spec it was
created under, and forks that have passed can never be changed, removed or inserted behind the
chain.
"""
import json
import os
import tempfile
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from qrdx import chain_spec as cs
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.node import main as node_main
from qrdx.validator.genesis_init import initialize_genesis_if_needed


@pytest.fixture
def features(monkeypatch):
    feats = dict(cs.FEATURES)
    feats.update({"test_rule_a": "test", "test_rule_b": "test"})
    monkeypatch.setattr(cs, "FEATURES", feats)


def _spec(forks=(), **params):
    return cs.build_spec("qrdx-dev", 88888, {"SLOTS_PER_EPOCH": 4, **params}, dev=True,
                         forks=forks)


@pytest.fixture
async def db():
    path = tempfile.mktemp(suffix=".db")
    database = await DatabaseSQLite.create(db_path=path)
    yield database
    await database.close()          # an open aiosqlite connection keeps the process alive
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(path + suffix):
            os.remove(path + suffix)


async def _chain(monkeypatch, db, spec, tip=0):
    """``db`` with a genesis created under ``spec`` and blocks up to ``tip``."""
    assert await initialize_genesis_if_needed(db, genesis_file=None, chain_spec=spec)
    for h in range(1, tip + 1):
        await db.add_block(block_id=h, block_hash=f"{h:064x}", block_content="{}",
                           address="test", random_value=0, difficulty=Decimal(0),
                           reward=Decimal(0), timestamp=datetime.now(timezone.utc))
    monkeypatch.setattr(node_main, "db", db)
    return db


async def _start(monkeypatch, spec):
    monkeypatch.setattr(node_main, "CHAIN_SPEC", spec)
    return await node_main._verify_chain_identity()


async def test_the_database_of_this_spec_starts(monkeypatch, db):
    spec = _spec()
    await _chain(monkeypatch, db, spec)
    genesis = await db.get_block_by_id(0)
    assert await _start(monkeypatch, spec) == (genesis.get("hash") or genesis.get("block_hash"))


async def test_a_different_spec_refuses_to_start(monkeypatch, db):
    await _chain(monkeypatch, db, _spec())
    with pytest.raises(node_main.ChainIdentityError, match="created under chain spec"):
        await _start(monkeypatch, _spec(SLOTS_PER_EPOCH=8))


async def test_a_database_from_before_chain_specs_refuses_to_start(monkeypatch, db):
    await _chain(monkeypatch, db, _spec())
    content = {"type": "genesis", "chain_id": 88888}                 # no chain_spec_hash
    await db.connection.execute("UPDATE blocks SET content = ? WHERE block_height = 0",
                                (json.dumps(content),))
    await db.connection.commit()
    with pytest.raises(node_main.ChainIdentityError, match="before chain specs"):
        await _start(monkeypatch, _spec())


async def test_a_pinned_network_must_hold_its_published_genesis(monkeypatch, db):
    spec = _spec()
    await _chain(monkeypatch, db, spec)
    monkeypatch.setitem(cs.PINNED_NETWORKS, spec.network, "00" * 32)
    with pytest.raises(node_main.ChainIdentityError, match="pinned"):
        await _start(monkeypatch, spec)


async def test_passed_forks_are_append_only(monkeypatch, db, features):
    f1 = {"name": "f1", "height": 5, "features": ["test_rule_a"]}
    original = _spec(forks=[f1])
    await _chain(monkeypatch, db, original, tip=10)
    await _start(monkeypatch, original)                      # records f1 as passed (tip 10)

    changed = _spec(forks=[{**f1, "features": ["test_rule_b"]}])
    with pytest.raises(node_main.ChainIdentityError, match="defines it differently"):
        await _start(monkeypatch, changed)
    removed = _spec()
    with pytest.raises(node_main.ChainIdentityError, match="omits it"):
        await _start(monkeypatch, removed)
    behind = _spec(forks=[f1, {"name": "f2", "height": 8, "features": ["test_rule_b"]}])
    with pytest.raises(node_main.ChainIdentityError, match="passed that height"):
        await _start(monkeypatch, behind)

    # Scheduling ahead of the chain is how an upgrade is meant to arrive.
    ahead = _spec(forks=[f1, {"name": "f2", "height": 50, "features": ["test_rule_b"]}])
    await _start(monkeypatch, ahead)


async def test_a_fork_cannot_be_slipped_in_below_the_height_reached(monkeypatch, db, features):
    """No fork had passed yet, but the chain had reached height 10: a fork scheduled at 3 would
    re-judge blocks 3..10 on the next replay."""
    await _chain(monkeypatch, db, _spec(), tip=10)
    await _start(monkeypatch, _spec())
    with pytest.raises(node_main.ChainIdentityError, match="passed that height"):
        await _start(monkeypatch, _spec(forks=[{"name": "f1", "height": 3,
                                                "features": ["test_rule_a"]}]))


async def test_identity_and_peer_check_follow_the_verified_genesis(monkeypatch, db, features):
    spec = _spec(forks=[{"name": "f1", "height": 5, "features": ["test_rule_a"]}])
    await _chain(monkeypatch, db, spec, tip=7)
    genesis_hash = await _start(monkeypatch, spec)
    monkeypatch.setattr(node_main, "GENESIS_BLOCK_HASH", genesis_hash)
    ident = await node_main._local_network_identity()
    assert ident["genesis_hash"] == genesis_hash and ident["fork_next"] == 0
    assert (await node_main._check_peer_identity(ident))[0]
    stale = cs.network_identity(_spec(), genesis_hash, 7, "old")
    ok, reason = await node_main._check_peer_identity(stale)
    assert not ok and "5" in reason
