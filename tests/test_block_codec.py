"""
Block bodies are stored compressed (qrdx/block_codec.py, DatabaseSQLite.add_block).

A body was ~18 KB of mostly hex (signatures, the proposer's key, the RANDAO reveal) stored as
text: about 7 GB a day at 250 ms slots. Every reader must see exactly the text that was signed
and sent; only the stored form changes.
"""
import os
import tempfile

from qrdx import block_codec
from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.database_sqlite import DatabaseSQLite
from qrdx.validator.block_verification import _parse_block_content


def _body():
    key = PQPrivateKey.generate()
    return str({
        "number": 7, "parent_hash": "ab" * 32, "state_root": "cd" * 64,
        "transactions_root": "ef" * 32, "timestamp": 1_700_000_000,
        "proposer_address": key.public_key.to_address(),
        "proposer_signature": key.sign(b"x").to_bytes().hex(), "slot": 7, "epoch": 0,
        "randao_reveal": "", "attestations": [], "slashing_evidence": [], "graffiti": "",
        "hash": "12" * 32,
    })


def test_round_trip_and_size():
    body = _body()
    stored = block_codec.encode(body)
    assert isinstance(stored, bytes) and block_codec.decode(stored) == body
    assert len(stored) < 0.6 * len(body)            # hex compresses to about half
    assert block_codec.decode(body) == body          # a body stored as text reads unchanged
    assert _parse_block_content(stored) == _parse_block_content(body)


async def test_the_database_stores_compressed_and_hands_out_text():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = await DatabaseSQLite.create(path)
    try:
        body = _body()
        await db.add_block(block_hash="aa" * 32, block_height=0, block_content=body,
                           validator_address="0xPQ" + "00" * 32, timestamp=1)
        cur = await db.connection.execute("SELECT content FROM blocks WHERE block_height = 0")
        raw = (await cur.fetchone())[0]
        assert isinstance(raw, bytes) and len(raw) < len(body)
        for got in (await db.get_block_by_id(0), await db.get_block("aa" * 32),
                    await db.get_latest_block(), (await db.get_blocks(0, 5))[0]):
            assert got["content"] == body
    finally:
        await db.connection.close()
        os.remove(path)
