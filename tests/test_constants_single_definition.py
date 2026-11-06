"""
Every module-level name in qrdx/constants.py is assigned exactly once.

Twice now a protocol constant was defined in two places and the later definition silently won:
SLOTS_PER_EPOCH (validator/config.py hardcoded 32 against the env-driven 8 — proposer and
importer disagreed on epochs) and PERP_FUNDING_INTERVAL_SECONDS (a legacy 8-hour line further
down constants.py overrode the env-driven value, so a testnet configured for 60 s funding paid
none). A second assignment is never intended in a constants module.
"""
import ast
import collections
import pathlib

import qrdx


def test_no_constant_is_defined_twice():
    path = pathlib.Path(qrdx.__file__).parent / "constants.py"
    counts = collections.Counter()
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        for t in targets:
            if isinstance(t, ast.Name):
                counts[t.id] += 1
    assert not {n: c for n, c in counts.items() if c > 1}


def test_the_funding_interval_follows_the_environment(monkeypatch):
    import importlib
    from qrdx import constants
    monkeypatch.setenv("QRDX_PERP_FUNDING_INTERVAL_SECONDS", "60")
    try:
        assert importlib.reload(constants).PERP_FUNDING_INTERVAL_SECONDS == 60
    finally:
        monkeypatch.delenv("QRDX_PERP_FUNDING_INTERVAL_SECONDS")
        importlib.reload(constants)
