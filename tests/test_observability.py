"""
Operational-readiness surface — health/metrics + realtime event hub (qrdx/node/observability.py).
Consensus-decoupled: the poller reads chain tip/finality only, so these tests need no node.
"""
import asyncio

import pytest

from qrdx.node.observability import (
    EventHub, Metrics, chain_event_poller, sse_frame, sse_stream,
)


@pytest.mark.asyncio
async def test_hub_fanout_to_multiple_subscribers():
    hub = EventHub()
    a, b = hub.subscribe(), hub.subscribe()
    assert hub.subscriber_count == 2
    await hub.publish({"type": "block", "height": 7})
    assert (await a.get())["height"] == 7
    assert (await b.get())["height"] == 7
    hub.unsubscribe(a)
    assert hub.subscriber_count == 1


@pytest.mark.asyncio
async def test_hub_drops_oldest_on_overflow():
    """A slow subscriber must never grow node memory — overflow drops the OLDEST event, keeping the
    freshest, and increments the dropped counter."""
    hub = EventHub(max_queue=3)
    q = hub.subscribe()
    for i in range(5):                       # 5 into a size-3 queue
        await hub.publish({"n": i})
    drained = [q.get_nowait()["n"] for _ in range(q.qsize())]
    assert drained == [2, 3, 4]              # oldest (0,1) dropped, newest kept
    assert hub.dropped_count == 2


def test_metrics_prometheus_render():
    m = Metrics()
    m.describe("qrdx_chain_height", "tip")
    m.set("qrdx_chain_height", 42)
    m.inc("qrdx_blocks_streamed_total")
    m.inc("qrdx_blocks_streamed_total", 2)
    text = m.render_prometheus()
    assert "# TYPE qrdx_chain_height gauge" in text
    assert "qrdx_chain_height 42" in text
    assert "# TYPE qrdx_blocks_streamed_total counter" in text
    assert "qrdx_blocks_streamed_total 3" in text
    assert m.snapshot()["qrdx_chain_height"] == 42


def test_metrics_labels_group_under_one_type_line():
    """Labeled series (per-RPC-method) render as one # TYPE line + a series per label set, and
    aggregate independently."""
    m = Metrics()
    m.describe("qrdx_rpc_requests_total", "reqs")
    m.inc("qrdx_rpc_requests_total", labels={"method": "eth_blockNumber"})
    m.inc("qrdx_rpc_requests_total", labels={"method": "eth_blockNumber"})
    m.inc("qrdx_rpc_requests_total", labels={"method": "net_version"})
    text = m.render_prometheus()
    assert text.count("# TYPE qrdx_rpc_requests_total counter") == 1
    assert 'qrdx_rpc_requests_total{method="eth_blockNumber"} 2' in text
    assert 'qrdx_rpc_requests_total{method="net_version"} 1' in text
    snap = m.snapshot()
    assert snap['qrdx_rpc_requests_total{method="eth_blockNumber"}'] == 2


def test_metrics_label_value_escaping():
    m = Metrics()
    m.inc("x_total", labels={"m": 'a"b\\c'})
    assert 'x_total{m="a\\"b\\\\c"} 1' in m.render_prometheus()


@pytest.mark.asyncio
async def test_poller_emits_block_events_and_updates_metrics():
    hub, m = EventHub(), Metrics()
    q = hub.subscribe()
    heights = iter([2, 2, 4])                 # tip stays, then jumps 2→4
    fin = {"finalized_epoch": 1, "justified_epoch": 2}
    await chain_event_poller(
        hub, m, get_tip=lambda: next(heights), get_peer_count=lambda: 3,
        get_finality=lambda: fin, interval=0, _max_iterations=3)
    got = []
    while not q.empty():
        got.append(q.get_nowait())
    emitted = [e["height"] for e in got if e["type"] == "block"]
    assert emitted == [2, 3, 4]              # initial tip 2, then 3 and 4 on the jump
    assert m.snapshot()["qrdx_chain_height"] == 4
    assert m.snapshot()["qrdx_finalized_epoch"] == 1
    assert m.snapshot()["qrdx_peer_count"] == 3
    assert m.snapshot()["qrdx_blocks_streamed_total"] == 3


@pytest.mark.asyncio
async def test_poller_computes_finality_lag_and_mempool():
    hub, m = EventHub(), Metrics()
    fin = {"finalized_epoch": 5, "justified_epoch": 6, "max_epoch": 9}
    await chain_event_poller(
        hub, m, get_tip=lambda: 100, get_finality=lambda: fin,
        get_mempool_depth=lambda: 12, interval=0, _max_iterations=1)
    snap = m.snapshot()
    assert snap["qrdx_finalized_epoch"] == 5
    assert snap["qrdx_finality_lag_epochs"] == 4      # 9 - 5
    assert snap["qrdx_mempool_pending"] == 12


@pytest.mark.asyncio
async def test_poller_survives_getter_errors():
    hub, m = EventHub(), Metrics()
    def boom():
        raise RuntimeError("db down")
    # Must not raise — best-effort, swallowed and retried.
    await chain_event_poller(hub, m, get_tip=boom, interval=0, _max_iterations=2)
    assert m.snapshot().get("qrdx_up") == 1


def test_sse_frame_format():
    f = sse_frame({"type": "block", "height": 9})
    assert f.startswith("data: ") and f.endswith("\n\n")
    assert '"height": 9' in f


@pytest.mark.asyncio
async def test_sse_stream_yields_hello_then_events():
    hub = EventHub()
    gen = sse_stream(hub, keepalive=5)
    hello = await gen.__anext__()
    assert '"type": "hello"' in hello
    await hub.publish({"type": "block", "height": 11})
    frame = await gen.__anext__()
    assert '"height": 11' in frame
    await gen.aclose()


# ── Real time: the publishers wake when a block is applied, not on a timer ──────────────────

from qrdx.node.observability import ChangeSignal, SignallingLock  # noqa: E402


@pytest.mark.asyncio
async def test_releasing_the_block_lock_raises_the_signal():
    signal = ChangeSignal()
    listener = signal.listener()
    lock = SignallingLock(signal)
    async with lock:
        assert not listener.is_set()
    assert listener.is_set() and signal.raised == 1
    assert await ChangeSignal.wait(listener, 0.01) is True
    assert not listener.is_set()                        # reset for the next change
    assert await ChangeSignal.wait(listener, 0.01) is False


async def _drain(q):
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


@pytest.mark.asyncio
async def test_a_block_is_published_as_soon_as_it_is_applied():
    """The block feed used to wake every 2 s, so 250 ms blocks arrived eight at a time. With the
    signal it publishes each block within a moment of the lock's release, long before the
    (here 60 s) fallback timer."""
    import asyncio
    import time

    hub, m, signal = EventHub(), Metrics(), ChangeSignal()
    q = hub.subscribe()
    chain = {"tip": 5}
    task = asyncio.create_task(chain_event_poller(
        hub, m, get_tip=lambda: chain["tip"], get_hashes=lambda lo, hi: {
            h: f"h{h}" for h in range(lo, hi + 1)}, interval=60, signal=signal))
    await asyncio.sleep(0.05)
    assert [e["height"] for e in await _drain(q)] == [5]
    for height in (6, 7, 8):
        chain["tip"] = height
        t0 = time.monotonic()
        signal.raise_()
        event = await asyncio.wait_for(q.get(), 1.0)
        assert event["height"] == height and event["hash"] == f"h{height}"
        assert time.monotonic() - t0 < 0.2
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_replaced_blocks_are_announced_as_a_reorg():
    hub, m = EventHub(), Metrics()
    q = hub.subscribe()
    a = {h: f"a{h}" for h in range(12)}
    chain = {"tip": 8, "hashes": a}
    steps = iter([
        lambda: None,                                        # the feed starts at 8
        lambda: chain.update(tip=10),                        # 9 and 10 arrive
        lambda: chain.update(tip=11, hashes={**{h: a[h] for h in range(9)},
                                             9: "b9", 10: "b10", 11: "b11"}),
    ])

    def tip():
        next(steps)()
        return chain["tip"]

    await chain_event_poller(hub, m, get_tip=tip,
                             get_hashes=lambda lo, hi: {h: chain["hashes"][h]
                                                        for h in range(lo, hi + 1)},
                             interval=0, _max_iterations=3)
    events = await _drain(q)
    assert [(e["type"], e.get("height")) for e in events] == [
        ("block", 8), ("block", 9), ("block", 10), ("reorg", None),
        ("block", 9), ("block", 10), ("block", 11)]
    reorg = events[3]
    assert reorg["ancestor"] == 8 and reorg["ancestor_hash"] == "a8"
    assert reorg["orphaned"] == ["a9", "a10"]
    assert [e["hash"] for e in events[4:]] == ["b9", "b10", "b11"]
    assert m.snapshot()["qrdx_reorgs_streamed_total"] == 1


@pytest.mark.asyncio
async def test_exchange_channels_wake_on_the_signal():
    import asyncio

    from qrdx.exchange.stream import perp_stream_poller

    signal, steps = ChangeSignal(), []

    class Mgr:
        pass

    class Publisher:
        def __init__(self, hub, depth):
            pass

        def step(self, mgr):
            steps.append(1)

    import qrdx.exchange.stream as stream

    original = stream.PerpStreamPublisher
    stream.PerpStreamPublisher = Publisher
    try:
        task = asyncio.create_task(perp_stream_poller(
            EventHub(), get_manager=Mgr, interval=60, signal=signal))
        await asyncio.sleep(0.05)
        assert len(steps) == 1
        for n in (2, 3):
            signal.raise_()
            await asyncio.sleep(0.05)
            assert len(steps) == n
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    finally:
        stream.PerpStreamPublisher = original
