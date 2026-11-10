"""
Checkpoint sync (qrdx/snapshot.py, docs/CHECKPOINT_SYNC.md). A snapshot comes from anyone: its
exchange checkpoint is read without running code it names, and nothing in it is believed until
the state reproduces the root a block signs. (The whole restore is verified live against a real
network's database; see docs/CHECKPOINT_SYNC.md.)
"""

import os
import pickle
import struct
from decimal import Decimal

import pytest

from qrdx.exchange import ExchangeStateManager
from qrdx.exchange.clearinghouse import Clearinghouse
from qrdx.snapshot import SnapshotError, pickled_globals, safe_loads


@pytest.fixture(autouse=True)
def _fresh():
    ExchangeStateManager.reset_instance()
    yield
    ExchangeStateManager.reset_instance()


def _clearinghouse():
    ch = Clearinghouse()
    ch.create_market("BTC")
    market = "BTC-QRDX-PERP"
    ch.set_oracle_price(market, Decimal(30000))
    ch.new_block(Decimal(1_700_000_000))
    for who in ("alice", "bob"):
        ch.deposit(who, Decimal(1_000_000))
    ch.place_order("bob", market, "s1", "sell", Decimal(2), Decimal(30000), 0)
    ch.place_order("alice", market, "b1", "buy", Decimal(1), Decimal(30000), 0)
    ch.place_order("alice", market, "b2", "buy", Decimal(1), Decimal(29000), 0)
    return ch


def test_an_exchange_state_reads_back_identically():
    m = ExchangeStateManager.get_instance()
    m.clearinghouse = _clearinghouse()
    capture = m.capture()
    blob = pickle.dumps(capture, protocol=5)
    names = pickled_globals(blob)
    assert {("qrdx.exchange.clearinghouse", c) for c in ("Market", "Position", "OrderMeta")} <= names
    state = safe_loads(blob)
    assert state["clearinghouse"].commitment() == capture["clearinghouse"].commitment()
    state["clearinghouse"].verify_commitment()
    ExchangeStateManager.reset_instance()
    restored = ExchangeStateManager.get_instance()
    restored._restore_snapshot(state)
    restored.verify_commitments()
    assert restored.compute_state_root() == m.compute_state_root()


class _Evil:
    def __reduce__(self):
        return (os.system, ("echo owned > /dev/null",))


def _stack_global(module: str, name: str, call: bool = True) -> bytes:
    """A protocol-4 pickle naming ``module.name`` (and calling it with no arguments)."""
    def s(text: str) -> bytes:
        raw = text.encode()
        return b"\x8c" + struct.pack("<B", len(raw)) + raw

    body = s(module) + s(name) + b"\x93" + (b")R" if call else b"")
    return b"\x80\x04" + body + b"."


@pytest.mark.parametrize(
    "blob, why",
    [
        (pickle.dumps(_Evil()), "refused"),
        (_stack_global("builtins", "eval"), "refused"),
        (_stack_global("qrdx.exchange.state_manager", "ExchangeStateManager"), "refused"),
        (_stack_global("qrdx.exchange.state_manager", "ExchangeStateManager.reset_instance"),
         "refused"),
        (_stack_global("qrdx.exchange.state_manager", "Decimal"), "refused"),      # imported
        (_stack_global("qrdx.exchange.state_manager", "logger"), "refused"),       # not a class
        (_stack_global("qrdx.exchange.block_processor", "apply_enforcement"), "refused"),
        (_stack_global("qrdx.exchange.commitment", "trees_on"), "refused"),        # a function
        (_stack_global("qrdx.exchange.nonexistent", "X"), "refused"),
        (b"\x80\x04garbage", "does not decode"),
    ],
)
def test_nothing_else_is_resolved(blob, why, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SnapshotError, match=why):
        safe_loads(blob)
    assert not os.listdir(tmp_path)                                    # nothing ran


def _serve(directory):
    import functools
    import http.server
    import threading

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))
    handler.log_message = lambda *a, **k: None
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/"


def test_a_snapshot_downloads_from_any_server_and_a_broken_one_is_caught(tmp_path):
    import hashlib
    import json

    from qrdx.snapshot import fetch

    published = tmp_path / "pub"
    published.mkdir()
    data = os.urandom(300_000)
    store = os.urandom(70_000)  # (the store's file beside the database: docs/STORAGE.md)
    (published / "qrdx.db").write_bytes(data)
    (published / "qrdx.db.store").write_bytes(store)
    manifest = {"format": 2, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                "store": {"bytes": len(store), "sha256": hashlib.sha256(store).hexdigest()}}
    (published / "manifest.json").write_text(json.dumps(manifest))
    server, url = _serve(published)
    try:
        out = tmp_path / "got"
        out.mkdir()
        (out / "qrdx.db.part").write_bytes(data[:1000])          # a download cut short
        assert fetch(url, str(out), progress=lambda m: None)["bytes"] == len(data)
        assert (out / "qrdx.db").read_bytes() == data and not (out / "qrdx.db.part").exists()
        assert (out / "qrdx.db.store").read_bytes() == store
        (published / "qrdx.db").write_bytes(data[:-1] + b"\x00")  # corrupted in transit
        with pytest.raises(SnapshotError, match="does not match the manifest"):
            fetch(url, str(tmp_path / "bad"), progress=lambda m: None)
        assert not (tmp_path / "bad" / "qrdx.db").exists()
    finally:
        server.shutdown()


@pytest.mark.parametrize("module", ["qrdx.exchange.state_manager", "qrdx.exchange.handlers.common"])
def test_a_helper_resolves_where_it_lives_and_where_it_used_to(module):
    """The manager's helpers moved to handlers/common.py (re-exported from state_manager.py): a
    checkpoint made before the move names them in state_manager and must still load."""
    from qrdx.exchange.handlers.common import _encode_fee_token

    assert safe_loads(_stack_global(module, "_encode_fee_token", call=False)) is _encode_fee_token
