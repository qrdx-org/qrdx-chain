"""
QRDX is proof of stake: no path appends a proof-of-work block (docs/KNOWN_ISSUES.md, "A mined
block could be appended to the proof-of-stake chain").

The inherited miner path judged a block by the proof-of-work rules alone. On a proof-of-stake
chain those expect difficulty 1.0 after every 512th block — a hash in about sixteen tries — so a
block mined against the tip passed all of them; only a type error writing it stopped it.
"""
import hashlib
import os
import tempfile
import time

import pytest

from qrdx import manager
from qrdx.database_sqlite import DatabaseSQLite

# P-256's generator in the legacy compressed format (parity byte 42/43, x little-endian).
MINER = bytes([43]) + (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
).to_bytes(32, "little")


@pytest.fixture
async def pos_chain():
    """513 proof-of-stake blocks (0..512): proposers, no difficulty, as the node stores them."""
    path = tempfile.mktemp(suffix=".db")
    db = await DatabaseSQLite.create(path)
    previous = DatabaseSQLite.instance
    DatabaseSQLite.instance = db
    now = int(time.time())
    try:
        prev = "00" * 32
        for h in range(513):
            bh = hashlib.sha256(f"pos-{h}".encode()).hexdigest()
            await db.connection.execute(
                "INSERT INTO blocks (block_hash, block_height, prev_block_hash, timestamp, "
                "validator_address, content) VALUES (?, ?, ?, ?, ?, ?)",
                (bh, h, prev, now - 600 + h, "0xPQ" + "ab" * 32, "{}"))
            prev = bh
        await db.connection.commit()
        yield db, prev
    finally:
        DatabaseSQLite.instance = previous
        await db.connection.close()
        for p in (path, path + "-wal", path + "-shm"):
            if os.path.exists(p):
                os.remove(p)


def _mine(tip_hash: str) -> str:
    rules = manager.CONSENSUS_ENGINE.get_rules(513)
    head = (2).to_bytes(1, "little") + bytes.fromhex(tip_hash) + MINER + bytes.fromhex(
        rules.calculate_merkle_tree([]))
    stamp = int(time.time()).to_bytes(4, "little")
    for r in range(1, 10_000):
        content = head + stamp + (10).to_bytes(2, "little") + r.to_bytes(4, "little")
        if hashlib.sha256(content).hexdigest().startswith(tip_hash[-1:]):  # difficulty 1.0
            return content.hex()
    raise AssertionError("not mined")


async def test_the_inherited_rules_would_take_a_cheaply_mined_block_and_nothing_appends_it(
    pos_chain, monkeypatch
):
    import sqlite3
    from decimal import Decimal

    # The type error that stopped the old path's write, fixed — as any change could have.
    monkeypatch.setitem(sqlite3.adapters, (Decimal, sqlite3.PrepareProtocol), str)
    db, tip = pos_chain
    block = _mine(tip)
    difficulty, last = await manager.calculate_difficulty()
    assert await manager.check_block(block, [], mining_info=(difficulty, last))  # the hole
    assert await manager.create_block(block, []) is False
    assert await db.get_next_block_id() == 513                       # nothing was appended


async def test_a_sync_peer_cannot_hand_over_a_block_without_a_proposer(pos_chain):
    from qrdx.node import main

    _db, tip = pos_chain
    assert await main.process_and_create_block({"block": {"id": 513, "content": _mine(tip)}}) is False


def test_the_miners_endpoint_is_gone(monkeypatch):
    from fastapi.testclient import TestClient

    from qrdx.node import main

    class _NodeDB:  # (the app's middleware asks the node's database for old transactions)
        async def get_need_propagate_transactions(self):
            return []

    monkeypatch.setattr(main, "db", _NodeDB())
    r = TestClient(main.app).post("/push_block", json={"block_content": "00" * 108, "id": 1, "txs": []})
    assert r.status_code == 410 and "proof of stake" in r.json()["error"]
