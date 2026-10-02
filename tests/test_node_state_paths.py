"""
Each node keeps its own peer store and DHT routing table (docs/KNOWN_ISSUES.md, "Nodes started
from the same directory share peer and DHT state"): beside its database, or where
QRDX_P2P_STATE_DIR says. They used to be a file inside the package and a cwd-relative data/
directory — shared by every node started from one directory, which made one testnet dial another.
"""
from qrdx.node import main


def test_two_nodes_get_two_state_directories(monkeypatch):
    monkeypatch.delenv("QRDX_P2P_STATE_DIR", raising=False)
    dirs = set()
    for db in ("testnet/databases/node0.db", "testnet/databases/node1.db"):
        monkeypatch.setattr(main, "DENARO_DATABASE_PATH", db)
        dirs.add(main._p2p_state_dir())
    assert dirs == {"testnet/databases/node0.p2p", "testnet/databases/node1.p2p"}


def test_the_state_directory_can_be_named(monkeypatch, tmp_path):
    monkeypatch.setenv("QRDX_P2P_STATE_DIR", str(tmp_path))
    assert main._p2p_state_dir() == str(tmp_path)


def test_the_peer_store_is_no_longer_inside_the_package():
    import inspect
    src = inspect.getsource(main)
    start = src.index("NodesManager.db_path = os.path.join(_p2p_state_dir(), 'nodes.json')")
    assert start < src.index("NodesManager.purge_peers()", start - 200)
    assert "persist_dir = _p2p_state_dir()" in src


def test_no_function_in_the_node_shadows_os():
    """``startup()`` imported ``os`` locally further down, which makes ``os`` local to the
    whole function: the new state-directory line above that import raised UnboundLocalError and
    the node would not start (caught by a soak, not by a source check)."""
    import pathlib
    import symtable
    src = pathlib.Path(main.__file__).read_text()

    def walk(table):
        for child in table.get_children():
            if child.get_type() == "function":
                try:
                    sym = child.lookup("os")
                except KeyError:
                    sym = None
                assert sym is None or not sym.is_local(), (
                    f"{child.get_name()}() (line {child.get_lineno()}) makes 'os' local")
            walk(child)

    walk(symtable.symtable(src, main.__file__, "exec"))
