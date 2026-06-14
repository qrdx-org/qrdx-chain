"""
Parent-hash continuity check (observe-first) — main._check_parent_continuity.

Import validates only height-sequentiality, so a fork block can be appended on a
parent the node never stored, breaking the height→block linkage. This pins the
check: genesis is exempt, a matching parent passes, and a mismatch is observed
(accepted + logged) or enforced (rejected) per the flag.
"""

import json
import pytest

import qrdx.node.main as main


class _FakeDB:
    def __init__(self, blocks):
        self._blocks = blocks  # height -> {'hash': ...}

    async def get_block_by_id(self, height):
        return self._blocks.get(height)


def _content(parent_hash):
    return json.dumps({"parent_hash": parent_hash, "number": 1})


@pytest.fixture
def patched_db(monkeypatch):
    db = _FakeDB({1: {"hash": "tip_hash_AAAA"}})
    monkeypatch.setattr(main, "db", db)
    return db


async def test_genesis_exempt(patched_db):
    ok, err = await main._check_parent_continuity(0, _content("anything"), enforce=True)
    assert ok and err == ""


async def test_matching_parent_passes(patched_db):
    ok, err = await main._check_parent_continuity(2, _content("tip_hash_AAAA"), enforce=True)
    assert ok and err == ""


async def test_mismatch_observe_accepts(patched_db, caplog):
    import logging
    with caplog.at_level(logging.WARNING):
        ok, err = await main._check_parent_continuity(2, _content("WRONG_parent"), enforce=False)
    assert ok  # observe: accepted
    assert any("parent-continuity observe" in r.message for r in caplog.records)


async def test_mismatch_enforce_rejects(patched_db):
    ok, err = await main._check_parent_continuity(2, _content("WRONG_parent"), enforce=True)
    assert not ok and "parent_hash mismatch" in err


async def test_missing_parent_field_is_lenient(patched_db):
    ok, err = await main._check_parent_continuity(2, json.dumps({"number": 1}), enforce=True)
    assert ok and err == ""
