"""
A scheduled fork switches a consensus rule on at exactly its height — for the proposer, for
every importer, and for a node replaying history — whatever each node's own tip is.

RANDAO proposer selection is the first rule on the schedule (chain-spec feature
``randao_selection``). Its eligibility check is judged by the height of the block being
verified, so a block below the fork is judged under the old selection and a block at or above
it under RANDAO: the same slot, the same proposer, opposite verdicts on either side of the line.
"""
from decimal import Decimal

import pytest

from qrdx import chain_spec as cs
from qrdx.validator import randao
from qrdx.validator.block_verification import (
    PROPOSER_RANDAO_MIX, eligible_proposers_for_slot, expected_proposer_for_slot,
    verify_proposer_eligibility,
)

FORK_HEIGHT = 100
MIX = bytes(range(32))
VALIDATORS = [(f"0xPQ{i:064x}", Decimal(100000 + i * 37)) for i in range(1, 9)]
# The height boundary itself; on-chain approval of a fork is tests/test_governance.py's subject
# (a dev network may schedule a fork without it).
SPEC = cs.build_spec("qrdx-dev", 88888, {}, dev=True, forks=[
    {"name": "randao", "height": FORK_HEIGHT, "features": ["randao_selection"], "approval": "none"}])


class _DB:
    """The set every slot is selected from (validator/epoch_state.py, stubbed below)."""


@pytest.fixture(autouse=True)
def scheduled(monkeypatch):
    from qrdx.validator import epoch_state

    async def _proposers(db, slot, parent_height=None):
        return list(VALIDATORS)
    monkeypatch.setattr(epoch_state, "proposers_for_slot", _proposers)
    monkeypatch.setattr(randao, "ENFORCE_RANDAO_SELECTION", False)

    async def _mix(db, slot, *a, **k):
        return MIX
    monkeypatch.setattr(randao, "selection_mix_for_slot", _mix)
    with cs.use_spec(SPEC):
        yield


def _slot_where_the_rules_disagree():
    """A slot whose legacy primary is NOT RANDAO-eligible, plus a RANDAO-eligible proposer who
    is not the legacy primary."""
    for slot in range(1, 10_000):
        legacy = expected_proposer_for_slot(slot, VALIDATORS, PROPOSER_RANDAO_MIX)
        eligible = eligible_proposers_for_slot(slot, VALIDATORS, MIX, randao.RANDAO_PROPOSER_ELIGIBLE_K)
        if legacy not in eligible:
            return slot, legacy, eligible[0]
    raise AssertionError("no disagreeing slot found")


def _block(height, slot, proposer):
    # (A block's signed ``number`` is its slot; its height comes from where it is applied.)
    return {"number": slot, "slot": slot, "proposer_address": proposer}


async def _eligible(db, height, slot, proposer):
    return (await verify_proposer_eligibility(
        db, _block(height, slot, proposer), enforce=True, height=height))[0]


def test_the_rule_is_off_below_the_fork_and_on_from_it():
    assert not randao.randao_selection_active(FORK_HEIGHT - 1)
    assert randao.randao_selection_active(FORK_HEIGHT)
    assert randao.randao_selection_active(FORK_HEIGHT + 10 ** 6)


async def test_each_block_is_judged_under_the_rules_of_its_own_height():
    slot, legacy, randao_pick = _slot_where_the_rules_disagree()
    db = _DB()
    below, at = FORK_HEIGHT - 1, FORK_HEIGHT

    assert await _eligible(db, below, slot, legacy), "below the fork the legacy proposer is eligible"
    assert not await _eligible(db, below, slot, randao_pick), "below the fork RANDAO's pick is out of turn"
    assert await _eligible(db, at, slot, randao_pick), "from the fork RANDAO's pick is eligible"
    assert not await _eligible(db, at, slot, legacy), "from the fork the legacy primary is not"


async def test_a_block_is_judged_by_its_height_never_its_slot():
    """A block's signed ``number`` is its slot, which runs ahead of the height once a slot is
    skipped. Judged by it, an importer switched to a height-gated rule before the proposer did:
    here the slot is past the fork while the height is not."""
    slot, legacy, randao_pick = _slot_where_the_rules_disagree()
    block = {"number": FORK_HEIGHT + 5, "slot": slot, "proposer_address": legacy}
    ok, _ = await verify_proposer_eligibility(_DB(), block, enforce=True, height=FORK_HEIGHT - 1)
    assert ok, "below the fork by height, whatever its slot"


async def test_without_the_fork_nothing_changes():
    slot, legacy, randao_pick = _slot_where_the_rules_disagree()
    with cs.use_spec(cs.build_spec("qrdx-dev", 88888, {}, dev=True)):
        for height in (FORK_HEIGHT - 1, FORK_HEIGHT, 10 ** 6):
            assert await _eligible(_DB(), height, slot, legacy)
            assert not await _eligible(_DB(), height, slot, randao_pick)


def test_the_dev_override_still_forces_the_rule_on(monkeypatch):
    with cs.use_spec(cs.build_spec("qrdx-dev", 88888, {}, dev=True)):
        assert not randao.randao_selection_active(5)
        monkeypatch.setattr(randao, "ENFORCE_RANDAO_SELECTION", True)
        assert randao.randao_selection_active(5)
