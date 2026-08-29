"""
Node operational-readiness endpoints (qrdx/node/main.py): /healthz, /readyz, /metrics, and the
TOGGLEABLE realtime stream (/stream SSE, /ws WebSocket). Handlers are exercised directly so no full
node startup is needed.
"""
import pytest
from starlette.responses import StreamingResponse

import qrdx.node.main as m


@pytest.mark.asyncio
async def test_healthz_ok():
    r = await m.healthz()
    assert r["status"] == "ok" and "version" in r and r["uptime_s"] >= 0


@pytest.mark.asyncio
async def test_metrics_renders_prometheus():
    m.METRICS.set("qrdx_chain_height", 5)
    resp = await m.metrics_endpoint()
    body = resp.body.decode()
    assert "qrdx_chain_height 5" in body
    assert "qrdx_streaming_enabled" in body
    assert resp.media_type.startswith("text/plain")


@pytest.mark.asyncio
async def test_readyz_ready_and_not_ready(monkeypatch):
    class _DB:
        async def get_next_block_id(self):
            return 7                      # tip = 6
    monkeypatch.setattr(m, "db", _DB())
    ok = await m.readyz()
    assert ok.status_code == 200

    class _BadDB:
        async def get_next_block_id(self):
            raise RuntimeError("db down")
    monkeypatch.setattr(m, "db", _BadDB())
    bad = await m.readyz()
    assert bad.status_code == 503


@pytest.mark.asyncio
async def test_stream_toggle(monkeypatch):
    monkeypatch.setattr(m, "STREAMING_ENABLED", False)
    off = await m.stream_endpoint()
    assert off.status_code == 404                       # disabled → 404

    monkeypatch.setattr(m, "STREAMING_ENABLED", True)
    on = await m.stream_endpoint()
    assert isinstance(on, StreamingResponse)            # enabled → SSE stream


@pytest.mark.asyncio
async def test_ws_disabled_closes_without_accept(monkeypatch):
    """Toggle off → the WebSocket is closed with policy code 1008 and never accepted."""
    monkeypatch.setattr(m, "STREAMING_ENABLED", False)
    events = {}

    class _WS:
        async def accept(self):
            events["accepted"] = True
        async def close(self, code=1000):
            events["close_code"] = code
        async def send_json(self, _):
            events["sent"] = True

    await m.ws_stream(_WS())
    assert events.get("close_code") == 1008 and "accepted" not in events


@pytest.mark.asyncio
async def test_ws_enabled_accepts_and_streams_a_published_event(monkeypatch):
    """Toggle on → accept, send hello, then push a hub event; a client disconnect ends the loop."""
    monkeypatch.setattr(m, "STREAMING_ENABLED", True)
    from fastapi import WebSocketDisconnect
    sent = []

    class _WS:
        def __init__(self):
            self._n = 0
        async def accept(self):
            pass
        async def send_json(self, data):
            sent.append(data)
            # After hello + one real event, simulate the client going away.
            if len(sent) >= 2:
                raise WebSocketDisconnect()
        async def close(self, code=1000):
            pass

    import asyncio
    task = asyncio.create_task(m.ws_stream(_WS()))
    await asyncio.sleep(0.05)
    await m.EVENT_HUB.publish({"type": "block", "height": 99})
    await asyncio.wait_for(task, timeout=2)
    assert sent[0]["type"] == "hello"
    assert any(e.get("height") == 99 for e in sent)
