"""
A block's timestamp is its slot's start time (``slot_timestamps``; block_verification).

It is the exchange's only clock: funding, oracle staleness, TWAPs, lockups and the bridge's
deposit window all read it. It used to be the proposer's wall clock, checked by nothing on the
PoS import path, so a proposer could move any of them forwards or backwards. Slots strictly
increase and are bound to eligibility, so a clock derived from the slot is deterministic and
never runs backwards.
"""

import inspect
import json

from qrdx import chain_spec as cs, constants
from qrdx.validator import block_verification as BV, node_integration as NI

GENESIS = 1_700_000_000.0


class _Db:
    async def get_block_by_id(self, height):
        assert height == 0
        return {"timestamp": GENESIS}


def _block(slot, stamp):
    return json.dumps({"slot": slot, "timestamp": stamp})


def test_a_slots_start_time_is_exact_and_never_runs_backwards(monkeypatch):
    monkeypatch.setattr(constants, "SLOT_DURATION_MS", 250)
    assert [BV.slot_timestamp(GENESIS, s) for s in (0, 3, 4, 7, 8)] == [
        1_700_000_000,
        1_700_000_000,
        1_700_000_001,
        1_700_000_001,
        1_700_000_002,
    ]
    assert BV.slot_timestamp(GENESIS + 0.9, 1) == 1_700_000_001  # 0.9 s + 0.25 s
    stamps = [BV.slot_timestamp(GENESIS + 0.123, s) for s in range(1000)]
    assert stamps == sorted(stamps)


async def test_a_block_must_carry_its_slots_start_time(monkeypatch):
    monkeypatch.setattr(constants, "SLOT_DURATION_MS", 250)
    db = _Db()
    good = BV.slot_timestamp(GENESIS, 41)
    assert await BV.verify_block_timestamp(db, _block(41, good), 5) == (True, "")
    for wrong in (good + 1, good - 1, good + 3600):
        ok, err = await BV.verify_block_timestamp(db, _block(41, wrong), 5)
        assert not ok and "start time" in err
    ok, err = await BV.verify_block_timestamp(db, json.dumps({"slot": 41}), 5)
    assert not ok and "timestamp" in err


async def test_a_chain_without_the_feature_keeps_its_old_rule():
    spec = cs.build_spec("qrdx-old-clock", 4245, {}, features=["incremental_state_root"])
    with cs.use_spec(spec):
        assert await BV.verify_block_timestamp(_Db(), _block(41, 12345), 5) == (True, "")
    assert "slot_timestamps" in cs.GENESIS_DEFAULT_FEATURES


def test_every_import_path_and_the_proposer_use_it():
    from qrdx.node import main as node_main

    src = inspect.getsource(node_main._verify_chain_rules)
    assert "verify_block_timestamp(db, bc, int(block_height))" in src
    proposer = inspect.getsource(NI.ValidatorNode._block_production_loop)
    assert "slot_timestamp(origin, current_slot)" in proposer
