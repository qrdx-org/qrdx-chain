"""
Fork-choice mechanism-2 — equal-height tie-break decision logic.

Pins `P2PModule._equal_height_incoming_wins`: the lowest-hash canonical rule that
decides whether a competing block at an already-filled height should replace the
stored one. A genuine equal-height fork (same parent, different hash) is resolved
deterministically by lowest hash; re-broadcasts and different-parent blocks are not
forks. (The replacement *mechanism* itself was soaked and found to need active
reconciliation — see docs/FORK_CHOICE_CONVERGENCE.md — but this pure decision is the
reusable core of that future approach.)
"""

import json
import pytest

from qrdx.rpc.modules.p2p import P2PModule


class _FakeDB:
    def __init__(self, stored):
        self._stored = stored  # height -> {'hash':..., 'content': json}

    async def get_block_by_id(self, height):
        return self._stored.get(height)


def _stored_block(h, parent):
    return {"hash": h, "content": json.dumps({"parent_hash": parent, "number": 2})}


def _make_module(stored_hash, stored_parent, enforce=False):
    m = P2PModule()
    m._db = _FakeDB({2: _stored_block(stored_hash, stored_parent)})
    m._enforce_equal_height_tiebreak = enforce
    return m


def _incoming(block_hash, parent):
    return ({"block_hash": block_hash}, json.dumps({"parent_hash": parent, "number": 2}))


async def test_incoming_lower_hash_same_parent_wins():
    m = _make_module(stored_hash="bbbb", stored_parent="P")
    data, content = _incoming("aaaa", "P")  # lower hash, same parent
    assert await m._equal_height_incoming_wins(2, data, content) is True


async def test_incoming_higher_hash_loses():
    m = _make_module(stored_hash="aaaa", stored_parent="P")
    data, content = _incoming("bbbb", "P")  # higher hash
    assert await m._equal_height_incoming_wins(2, data, content) is False


async def test_same_block_is_not_a_fork():
    m = _make_module(stored_hash="aaaa", stored_parent="P")
    data, content = _incoming("aaaa", "P")  # identical hash → re-broadcast
    assert await m._equal_height_incoming_wins(2, data, content) is False


async def test_different_parent_is_not_equal_height_fork():
    m = _make_module(stored_hash="bbbb", stored_parent="P1")
    data, content = _incoming("aaaa", "P2")  # lower hash but different parent
    assert await m._equal_height_incoming_wins(2, data, content) is False


async def test_no_stored_block_returns_false():
    m = P2PModule()
    m._db = _FakeDB({})  # nothing at height 2
    m._enforce_equal_height_tiebreak = False
    data, content = _incoming("aaaa", "P")
    assert await m._equal_height_incoming_wins(2, data, content) is False


async def test_decision_is_independent_of_enforce_flag():
    # The flag governs whether we ACT on the decision, not the decision itself.
    won_observe = await _make_module("bbbb", "P", enforce=False)._equal_height_incoming_wins(
        2, *_incoming("aaaa", "P"))
    won_enforce = await _make_module("bbbb", "P", enforce=True)._equal_height_incoming_wins(
        2, *_incoming("aaaa", "P"))
    assert won_observe is True and won_enforce is True
