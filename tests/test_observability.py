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
