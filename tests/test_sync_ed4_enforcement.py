"""
E-D4 binds on the bulk-sync path too — not only on live broadcast.

With the sync tip only observing, a block the live paths REJECTED for a bad unified root
re-entered through sync: its proposer builds on it, the next live block makes the importer
sync from that proposer, and the sync path accepted the bad block with an "[E-D4 observe]"
warning. Block validity depended on how the block arrived, and E-D4 bound nothing.
"""
import inspect
import os
import tempfile

import pytest

from qrdx.database_sqlite import DatabaseSQLite
from qrdx.node import main as node_main


@pytest.mark.parametrize("tip, finalized_gate, at_finalized, expected", [
    (True, True, False, True),     # the tip itself is enforced
    (True, False, False, True),
    (False, True, True, True),     # observe-tip A/B arm: finalized heights still enforced
    (False, True, False, False),   # ...and the churning tip only observed
    (False, False, True, False),
])
def test_sync_enforcement_decision(monkeypatch, tip, finalized_gate, at_finalized, expected):
    monkeypatch.setattr(node_main, "_ED4_ENFORCE_SYNC_TIP", tip)
    monkeypatch.setattr(node_main, "_ED4_ENFORCE_SYNC_FINALIZED", finalized_gate)
    assert node_main._sync_ed4_enforced(at_finalized) is expected


def test_the_tip_gate_defaults_on():
    if "QRDX_ED4_ENFORCE_SYNC" not in os.environ:
        assert node_main._ED4_ENFORCE_SYNC_TIP is True


def test_the_sync_path_uses_the_decision():
    src = inspect.getsource(node_main.process_and_create_block)
    assert "enforce=_sync_ed4_enforced(at_finalized)" in src


@pytest.fixture
async def node_db(monkeypatch):
    db = await DatabaseSQLite.create(db_path=tempfile.mktemp(suffix=".db"))
    monkeypatch.setattr(node_main, "db", db)
    from qrdx.exchange import ExchangeStateManager
    ExchangeStateManager.reset_instance()
    yield db
    path = db.db_path
    await db.close()
    os.remove(path)


async def _current_root(db):
    from qrdx.crypto.hashing import unified_state_root
    from qrdx.exchange import ExchangeStateManager
    return unified_state_root(
        (await db.get_unspent_outputs_hash()) or "0" * 64,
        await db.get_account_state_root(),
        ExchangeStateManager.get_instance().compute_state_root(),
        await db.get_token_balances_root())


async def test_a_matching_root_is_accepted(node_db):
    content = str({"state_root": await _current_root(node_db)})
    assert await node_main._verify_unified_state_root(content, enforce=True) == (True, "")


async def test_a_mismatched_root_is_rejected_when_enforced(node_db):
    content = str({"state_root": "ab" * 64})
    ok, err = await node_main._verify_unified_state_root(content, enforce=True)
    assert not ok and "unified state root mismatch" in err


async def test_observe_mode_only_logs(node_db, caplog):
    content = str({"state_root": "ab" * 64})
    assert await node_main._verify_unified_state_root(content, enforce=False) == (True, "")
    assert "[E-D4 observe]" in caplog.text
