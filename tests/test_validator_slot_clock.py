"""
The validator's loops run on the slot clock (qrdx/validator/node_integration.py).

They used to sleep a fixed SLOT_DURATION after doing their work, so every iteration took
work + one slot: a lone validator's block time was 2 s plus its per-block work (which grew
with the chain — 14.5 s on the testnet), and with several validators each drifted off the
slots it was meant to propose in. Now each pass sleeps until a point in the next slot, computed
from genesis time, so work time no longer shifts the schedule.
"""
import time

import pytest

from qrdx.constants import SLOT_DURATION
from qrdx.validator import node_integration as NI


def _node(genesis_ts):
    node = NI.ValidatorNode.__new__(NI.ValidatorNode)
    node._genesis_ts = genesis_ts
    return node


def test_the_slot_duration_is_the_chain_specs():
    # The spec sets milliseconds; the slot clock runs on the same value in seconds. (It used to
    # fall back to 12 s for anything that was not an int.)
    from qrdx.constants import SLOT_DURATION_MS

    assert NI.SLOT_DURATION_SECONDS == SLOT_DURATION == SLOT_DURATION_MS / 1000


@pytest.mark.parametrize("share", [0.0, 0.2, 0.65])
async def test_the_next_slot_starts_on_time_however_long_the_work_took(monkeypatch, share):
    slept = []

    async def fake_sleep(delay):
        slept.append(delay)

    monkeypatch.setattr(NI.asyncio, "sleep", fake_sleep)
    d = NI.SLOT_DURATION_SECONDS
    work = share * d                            # the work took this much of the slot
    genesis = time.time() - 5 * d - work        # we are `work` seconds into slot 5
    node = _node(genesis)
    assert await node._get_current_slot() == 5
    await node._sleep_until(6)
    assert slept and abs(slept[0] - (d - work)) < 0.05


async def test_a_point_already_passed_does_not_sleep(monkeypatch):
    slept = []

    async def fake_sleep(delay):
        slept.append(delay)

    monkeypatch.setattr(NI.asyncio, "sleep", fake_sleep)
    node = _node(time.time() - 10 * NI.SLOT_DURATION_SECONDS)
    await node._sleep_until(3, 1 / 3)
    assert slept == []


async def test_genesis_time_is_read_once():
    class DB:
        calls = 0

        async def get_block_by_id(self, h):
            DB.calls += 1
            return {"timestamp": "2026-06-08 13:57:09+00:00"}

    node = _node(None)
    node.db = DB()
    for _ in range(5):
        await node._get_current_slot()
    assert DB.calls == 1


async def test_sub_second_slots_keep_time(monkeypatch):
    """A 250 ms slot: the slot number advances four times a second and the clock wakes at each
    slot boundary (and at a third of the slot for attestations)."""
    monkeypatch.setattr(NI, "SLOT_DURATION_SECONDS", 0.25)
    slept = []

    async def fake_sleep(delay):
        slept.append(delay)

    monkeypatch.setattr(NI.asyncio, "sleep", fake_sleep)
    node = _node(time.time() - 10.1)  # 0.1 s into slot 40
    assert await node._get_current_slot() == 40
    await node._sleep_until(41)
    await node._sleep_until(41, 1 / 3)
    assert abs(slept[0] - 0.15) < 0.03 and abs(slept[1] - (0.15 + 0.25 / 3)) < 0.03
