"""
Nodes publishing snapshots (qrdx/snapshot_publisher.py; docs/CHECKPOINT_SYNC.md "Publishing").

A node with QRDX_SNAPSHOT_DIR writes a snapshot of its database at each newer exchange
checkpoint, keeps the newest, serves it at /snapshot/ (resumable) and advertises it in its
status; ``snapshot.py fetch --peer`` finds the newest one among the nodes it is given. A
published snapshot leaves out what a restore discards — the node's own tables among them — and
overwrites them rather than only unlinking them.
"""
import hashlib
import json
import os
import sqlite3

import pytest

from qrdx import snapshot, snapshot_publisher
from qrdx.snapshot import SnapshotError, create, discover, fetch

PEER_IP = "10.9.8.7"


def _node_db(path, checkpoint=100):
    """A node database in miniature: chain, state and journal rows a restore needs, and the
    node's own rows it does not."""
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.executescript("""
        CREATE TABLE blocks (block_hash TEXT, block_height INTEGER, content TEXT);
        CREATE TABLE exchange_checkpoint (id INTEGER PRIMARY KEY, height INTEGER,
                                          block_hash TEXT, state BLOB, journal BLOB);
        CREATE TABLE undo_log (id INTEGER PRIMARY KEY, height INTEGER, op TEXT);
        CREATE TABLE account_state (address TEXT, balance TEXT);
        CREATE TABLE peers (id TEXT, address TEXT);
        CREATE TABLE pending_transactions (tx_hash TEXT, tx_hex TEXT);
        CREATE TABLE tx_index (tx_hash TEXT, block_height INTEGER);
        CREATE TABLE tx_participants (account TEXT, block_height INTEGER);
        CREATE TABLE hist_trades (id INTEGER, data TEXT);
        CREATE TABLE state_commitment (domain TEXT, acc BLOB);
        CREATE TABLE post_roots (block_hash TEXT, height INTEGER, root TEXT);
    """)
    for h in range(0, 150):
        conn.execute("INSERT INTO blocks VALUES (?, ?, ?)", (f"{h:064x}", h, "x" * 200))
    conn.execute("INSERT INTO exchange_checkpoint VALUES (1, ?, ?, ?, ?)",
                 (checkpoint, f"{checkpoint:064x}", b"state", b"journal"))
    conn.execute("INSERT INTO undo_log (height, op) VALUES (120, 'put')")
    conn.execute("INSERT INTO account_state VALUES ('0xPQa', '5')")
    conn.execute("INSERT INTO peers VALUES ('p1', ?)", (f"http://{PEER_IP}:3007",))
    conn.execute("INSERT INTO pending_transactions VALUES ('t', 'secret-pending')")
    conn.execute("INSERT INTO tx_index VALUES ('t', 3)")
    conn.execute("INSERT INTO tx_participants VALUES ('0xPQa', 3)")
    conn.execute("INSERT INTO hist_trades VALUES (1, 'fill')")
    conn.execute("INSERT INTO state_commitment VALUES ('accounts', x'00')")
    conn.execute("INSERT INTO post_roots VALUES ('h', 99, 'planted')")  # (never trusted)
    conn.commit()
    return conn


def _count(path, table):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


def _move_checkpoint(conn, height):
    conn.execute("UPDATE exchange_checkpoint SET height = ?, block_hash = ? WHERE id = 1",
                 (height, f"{height:064x}"))
    conn.commit()


def test_a_published_snapshot_leaves_out_what_a_restore_discards(tmp_path):
    db = str(tmp_path / "node.db")
    conn = _node_db(db)
    try:
        manifest = create(db, str(tmp_path / "pub"), public=True)
    finally:
        conn.close()
    copy = str(tmp_path / "pub" / "qrdx.db")
    for table in ("peers", "pending_transactions", "tx_index", "tx_participants", "hist_trades",
                  "state_commitment", "post_roots"):
        assert _count(copy, table) == 0, table
    for table in ("blocks", "undo_log", "account_state", "exchange_checkpoint"):
        assert _count(copy, table) > 0, table
    raw = open(copy, "rb").read()
    assert PEER_IP.encode() not in raw and b"secret-pending" not in raw   # overwritten
    assert manifest["checkpoint"]["height"] == 100 and manifest["tip"] == 149
    assert manifest["sha256"] == hashlib.sha256(raw).hexdigest()
    assert sorted(os.listdir(tmp_path / "pub")) == ["manifest.json", "qrdx.db"]  # no -wal


def test_a_restore_also_discards_the_transaction_participants(tmp_path):
    db = str(tmp_path / "node.db")
    _node_db(db).close()
    snapshot._wipe(db)
    assert _count(db, "tx_participants") == 0 and _count(db, "tx_index") == 0
    assert _count(db, "blocks") == 150


def test_a_node_publishes_each_newer_checkpoint_and_keeps_the_newest(tmp_path):
    db, root = str(tmp_path / "node.db"), str(tmp_path / "published")
    assert snapshot_publisher.publish(db, root) is None                 # no database yet
    conn = _node_db(db)
    try:
        assert snapshot_publisher.publish(db, root)["checkpoint"]["height"] == 100
        assert snapshot_publisher.publish(db, root) is None             # nothing newer
        _move_checkpoint(conn, 140)
        assert snapshot_publisher.publish(db, root)["checkpoint"]["height"] == 140
    finally:
        conn.close()
    assert sorted(os.listdir(root)) == ["140", "latest.json"]
    assert snapshot_publisher.latest(root)["manifest"]["checkpoint"]["height"] == 140


def test_only_the_published_snapshot_is_served_and_advertised(tmp_path, monkeypatch):
    db, root = str(tmp_path / "node.db"), str(tmp_path / "published")
    monkeypatch.setitem(snapshot_publisher._ROOT, "root", root)
    assert snapshot_publisher.published_file("qrdx.db") is None and not snapshot_publisher.advertised()
    _node_db(db).close()
    snapshot_publisher.publish(db, root)
    assert snapshot_publisher.published_file("qrdx.db").endswith("/100/qrdx.db")
    for name in ("latest.json", "../latest.json", "100/qrdx.db", "qrdx.db-wal"):
        assert snapshot_publisher.published_file(name) is None, name
    ad = snapshot_publisher.advertised()
    assert ad["path"] == "/snapshot/" and ad["checkpoint"]["height"] == 100


def test_the_node_serves_it_with_range_requests(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from qrdx.node import main

    class _NodeDB:  # (the app's middleware asks the node's database for old transactions)
        async def get_need_propagate_transactions(self):
            return []

    monkeypatch.setattr(main, "db", _NodeDB())
    db, root = str(tmp_path / "node.db"), str(tmp_path / "published")
    _node_db(db).close()
    snapshot_publisher.publish(db, root)
    client = TestClient(main.app)
    assert client.get("/snapshot/qrdx.db").status_code == 404           # not publishing
    monkeypatch.setitem(snapshot_publisher._ROOT, "root", root)
    whole = client.get("/snapshot/qrdx.db")
    assert whole.status_code == 200
    part = client.get("/snapshot/qrdx.db", headers={"Range": "bytes=100-199"})
    assert part.status_code == 206 and part.content == whole.content[100:200]
    assert client.get("/snapshot/manifest.json").json()["checkpoint"]["height"] == 100
    assert client.get("/snapshot/latest.json").status_code == 404


def _serve(directory):
    import functools
    import http.server
    import threading

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))
    handler.log_message = lambda *a, **k: None
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def test_a_joining_node_takes_the_newest_snapshot_its_peers_publish(tmp_path):
    servers, peers = [], []
    try:
        for name, height in (("a", 100), ("b", 140)):
            db = str(tmp_path / f"{name}.db")
            _node_db(db, checkpoint=height).close()
            create(db, str(tmp_path / name / "snapshot"), public=True)   # served at /snapshot/
            server, url = _serve(tmp_path / name)
            servers.append(server)
            peers.append(url)
        url, manifest = discover(["http://127.0.0.1:9", *peers])           # one does not answer
        assert url == peers[1] + "/snapshot/" and manifest["checkpoint"]["height"] == 140
        got = fetch(url, str(tmp_path / "got"), progress=lambda m: None)
        assert got == json.loads((tmp_path / "b" / "snapshot" / "manifest.json").read_text())
        with pytest.raises(SnapshotError, match="none of these nodes"):
            discover(["http://127.0.0.1:9"])
    finally:
        for server in servers:
            server.shutdown()


async def test_a_restore_refuses_code_stored_under_another_codes_hash(tmp_path):
    """The root commits to each account's code hash, not to the code table keyed by it: a
    server could swap a contract's code under its hash, and the node would run it."""
    from eth_utils import keccak

    from qrdx.database_sqlite import DatabaseSQLite

    db = await DatabaseSQLite.create(str(tmp_path / "restoring.db"))
    try:
        code = bytes.fromhex("6000600055")
        await db.connection.execute(
            "INSERT INTO contract_code (code_hash, bytecode, deployed_at, deployer, size) "
            "VALUES (?, ?, 0, 'genesis', 5)", (keccak(code).hex(), code))
        await snapshot._verify_code(db)                                    # the honest copy
        await db.connection.execute("UPDATE contract_code SET bytecode = ?", (b"\x60\x01\x00",))
        with pytest.raises(SnapshotError, match="is not that code"):
            await snapshot._verify_code(db)
    finally:
        await db.connection.close()
