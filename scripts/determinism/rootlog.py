"""
pytest plugin: after each test, the exchange's state root, written to ``$ROOTLOG_OUT`` as JSON
lines. A root that a run under the same ``PYTHONHASHSEED`` reproduces must also be the same under
another seed: anything that depends on set or dict-of-str iteration order shows up as a
difference (scripts/determinism/check.py).

    ROOTLOG_OUT=roots.jsonl pytest tests/ -p scripts.determinism.rootlog
"""

import json
import os

import pytest

OUT = os.environ.get("ROOTLOG_OUT", os.devnull)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    yield
    try:
        from qrdx.exchange import ExchangeStateManager

        mgr = ExchangeStateManager.instance
        if mgr is None:
            return
        row = {"test": item.nodeid, "root": mgr.compute_state_root()}
    except Exception as e:  # noqa: BLE001 — a manager the test left half-built
        row = {"test": item.nodeid, "error": type(e).__name__}
    with open(OUT, "a") as f:
        f.write(json.dumps(row) + "\n")
