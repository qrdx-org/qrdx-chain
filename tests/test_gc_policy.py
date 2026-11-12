"""
The garbage collector's policy for a running node (qrdx/node/gc_policy.py): what is alive once it
has started is frozen, full collections stop being automatic and run on a timer instead.
"""

import asyncio
import gc

import pytest

from qrdx.node import gc_policy


@pytest.fixture
def restored():
    threshold = gc.get_threshold()
    try:
        yield
    finally:
        gc.unfreeze()
        gc.set_threshold(*threshold)


def test_installed_it_freezes_the_live_objects_and_stops_automatic_full_collections(
    restored, monkeypatch
):
    monkeypatch.delenv("QRDX_GC_POLICY", raising=False)
    young, middle, _full = gc.get_threshold()
    assert gc_policy.install()
    assert gc.get_freeze_count() > 0
    assert gc.get_threshold() == (young, middle, gc_policy._NEVER)


def test_off_it_changes_nothing(restored, monkeypatch):
    monkeypatch.setenv("QRDX_GC_POLICY", "0")
    before = gc.get_threshold()
    assert not gc_policy.install()
    assert gc.get_threshold() == before and gc.get_freeze_count() == 0


def test_a_full_collection_finds_the_cycles_that_became_garbage(restored, monkeypatch):
    monkeypatch.delenv("QRDX_GC_POLICY", raising=False)
    gc_policy.install()

    class Node:
        pass

    gc.disable()  # (no young collection gets to them first)
    try:
        for _ in range(100):
            a, b = Node(), Node()
            a.other, b.other = b, a  # (a cycle: reference counting never frees it)
        del a, b
        assert gc_policy.collect_full() >= 200
    finally:
        gc.enable()


def test_the_timer_runs_them(monkeypatch):
    monkeypatch.setenv("QRDX_GC_FULL_SECONDS", "0.01")
    ran = []
    monkeypatch.setattr(gc_policy, "collect_full", lambda: ran.append(1))

    async def a_while():
        task = asyncio.create_task(gc_policy.run())
        await asyncio.sleep(0.1)
        task.cancel()

    asyncio.run(a_while())
    assert len(ran) >= 2
