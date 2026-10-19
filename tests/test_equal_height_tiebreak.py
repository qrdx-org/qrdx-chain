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
    return {"hash": h, "content": json.dumps({"parent_hash": _p(parent), "number": 2})}


def _make_module(stored_hash, stored_parent, enforce=False):
    m = P2PModule()
    m._db = _FakeDB({2: _stored_block(stored_hash, stored_parent)})
    m._enforce_equal_height_tiebreak = enforce
    return m


def _header(parent, salt=0):
    from qrdx.validator.block_verification import body_root

    bc = {"number": 2, "parent_hash": parent, "state_root": f"{salt:064x}",
          "transactions_root": "ef" * 32, "timestamp": 1700000000, "slot": 2, "epoch": 0,
          "proposer_address": "0xPQ" + "a" * 64, "randao_reveal": "",
          "base_fee": 10 ** 9, "exchange_base_fee": 10 ** 9}
    bc["body_root"] = body_root(bc)
    return bc


def _incoming(block_hash, parent):
    """An incoming block on ``parent`` sent under ``block_hash`` — a real header whose hash is
    ``block_hash`` when that is "low" (below any stored hash here) or "high" (above), and any
    other value sent as given (a hash the block does not own)."""
    from qrdx.validator.block_verification import reconstruct_signing_root

    parent = parent if len(parent) == 64 else (parent.encode().hex() * 64)[:64]
    for salt in range(1, 10_000):
        bc = _header(parent, salt)
        real = reconstruct_signing_root(bc).hex()
        if (block_hash == "low" and real < "8") or (block_hash == "high" and real >= "8"):
            return {"block_hash": real}, json.dumps(bc)
        if block_hash not in ("low", "high"):
            return {"block_hash": block_hash}, json.dumps(bc)
    raise AssertionError("no header found")


def _p(parent):
    return (parent.encode().hex() * 64)[:64]


async def test_incoming_lower_hash_same_parent_wins():
    m = _make_module(stored_hash="8" + "0" * 63, stored_parent="P")
    data, content = _incoming("low", "P")  # lower hash, same parent
    assert await m._equal_height_incoming_wins(2, data, content) is True


async def test_incoming_higher_hash_loses():
    m = _make_module(stored_hash="8" + "0" * 63, stored_parent="P")
    data, content = _incoming("high", "P")  # higher hash
    assert await m._equal_height_incoming_wins(2, data, content) is False


async def test_same_block_is_not_a_fork():
    data, content = _incoming("low", "P")
    m = _make_module(stored_hash=data["block_hash"], stored_parent="P")  # a re-broadcast
    assert await m._equal_height_incoming_wins(2, data, content) is False


async def test_different_parent_is_not_equal_height_fork():
    m = _make_module(stored_hash="8" + "0" * 63, stored_parent="P1")
    data, content = _incoming("low", "P2")  # lower hash but different parent
    assert await m._equal_height_incoming_wins(2, data, content) is False


async def test_no_stored_block_returns_false():
    m = P2PModule()
    m._db = _FakeDB({})  # nothing at height 2
    m._enforce_equal_height_tiebreak = False
    data, content = _incoming("low", "P")
    assert await m._equal_height_incoming_wins(2, data, content) is False


async def test_a_block_sent_under_a_hash_it_does_not_own_never_wins():
    """A sender cannot choose the hash a block is stored under: the lowest possible one wins
    nothing unless it is the header's own."""
    m = _make_module(stored_hash="8" + "0" * 63, stored_parent="P")
    data, content = _incoming("0" * 64, "P")
    assert await m._equal_height_incoming_wins(2, data, content) is False


async def test_decision_is_independent_of_enforce_flag():
    # The flag governs whether we ACT on the decision, not the decision itself.
    won_observe = await _make_module("8" + "0" * 63, "P", enforce=False)._equal_height_incoming_wins(
        2, *_incoming("low", "P"))
    won_enforce = await _make_module("8" + "0" * 63, "P", enforce=True)._equal_height_incoming_wins(
        2, *_incoming("low", "P"))
    assert won_observe is True and won_enforce is True
