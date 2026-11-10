"""
Health, readiness, Prometheus metrics and the realtime stream (/healthz, /readyz,
/metrics, /stream, /ws), plus the chain spec and snapshot downloads.

The node's state (the database, the HTTP client, the EVM and exchange runtimes, this node's
identity) lives in qrdx.node.main and is read from it at call time, as ``_node.<name>``:
startup rebinds it, and tests replace it.
"""

import asyncio
import os
import time
from typing import Optional

from fastapi import HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse

from qrdx import chain_spec as chain_spec_mod
from qrdx.constants import CHAIN_SPEC, NODE_VERSION
from qrdx.logger import get_logger
from qrdx.node import main as _node
from qrdx.node.main import app
from qrdx.node.nodes_manager import NodesManager
from qrdx.node.observability import (
    EVENT_HUB,
    METRICS,
    handle_client_frame,
    parse_channels,
    sse_stream,
)

logger = get_logger(__name__)


@app.get("/healthz")
async def healthz():
    """Liveness probe — the process is up and serving. Always 200."""
    return {
        "status": "ok",
        "version": NODE_VERSION,
        "build": _build_info(),
        "uptime_s": round(time.time() - _node.startup_time, 1),
    }


def _build_info() -> dict:
    """The release this node was built from — set by the reproducible image build
    (docker/Dockerfile); "unknown" outside it. Compare with a release manifest
    (docs/RELEASES.md) to confirm what is actually running."""
    return {
        "version": os.getenv("QRDX_BUILD_VERSION", "unknown"),
        "commit": os.getenv("QRDX_BUILD_COMMIT", "unknown"),
    }


@app.get("/readyz")
async def readyz():
    """Readiness probe — the node can serve chain data (DB reachable, a tip exists). 503 if not,
    so a load balancer / orchestrator drains this node until it is caught up."""
    try:
        tip = (await _node.db.get_next_block_id()) - 1
        ready = tip is not None and tip >= 0
    except Exception:
        tip, ready = None, False
    return JSONResponse(
        {"ready": ready, "height": tip if ready else None}, status_code=200 if ready else 503
    )


@app.get("/snapshot/{name}")
async def snapshot_file(name: str):
    """The snapshot this node publishes (``QRDX_SNAPSHOT_DIR``; qrdx/snapshot_publisher.py):
    ``manifest.json``, ``qrdx.db`` and ``qrdx.db.store``, with range requests so a cut download
    resumes. 404 when it publishes none. A restore verifies it whoever served it
    (docs/CHECKPOINT_SYNC.md)."""
    from qrdx.snapshot_publisher import published_file

    path = published_file(name)
    if path is None or not os.path.isfile(path):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "this node publishes no snapshot")
    kind = "application/json" if name.endswith(".json") else "application/octet-stream"
    return FileResponse(path, media_type=kind)


@app.get("/chain_spec")
async def chain_spec_endpoint():
    """The network this node follows and its upgrade schedule: chain id, parameters, which
    rules are active, the next fork and how many blocks away it is, this node's fork id and
    software version (docs/PROTOCOL_UPGRADES.md). Read-only."""
    if _node.GENESIS_BLOCK_HASH is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "chain identity not verified yet")
    tip = max(0, (await _node.db.get_next_block_id()) - 1)
    out = chain_spec_mod.report(CHAIN_SPEC, _node.GENESIS_BLOCK_HASH, tip, NODE_VERSION)
    out["build"] = _build_info()
    out["peers"] = _fork_readiness(out["next_fork"])
    return out


def _fork_readiness(next_fork) -> dict:
    """How many known peers announce the next fork (their status's fork_next): the
    readiness signal to watch before an activation height."""
    peers = list(NodesManager.peers.values()) if hasattr(NodesManager, "peers") else []
    seen = [p for p in peers if "fork_next" in p]
    ready = [p for p in seen if next_fork and p.get("fork_next") == next_fork["height"]]
    return {"known": len(peers), "reporting": len(seen), "ready_for_next_fork": len(ready)}


@app.get("/metrics")
async def metrics_endpoint():
    """Prometheus text exposition — chain height, finality, peers, stream subscribers, etc."""
    try:
        METRICS.set("qrdx_uptime_seconds", round(time.time() - _node.startup_time, 1))
        METRICS.set("qrdx_streaming_enabled", 1 if _node.STREAMING_ENABLED else 0)
    except Exception:
        pass
    try:
        # Upgrade schedule: alert when a fork is near and peers have not announced it.
        tip = max(0, (await _node.db.get_next_block_id()) - 1)
        nxt = CHAIN_SPEC.next_fork(tip)
        readiness = _fork_readiness(nxt)
        METRICS.set("qrdx_fork_next_height", nxt["height"] if nxt else 0)
        METRICS.set("qrdx_fork_blocks_until_next", (nxt["height"] - tip) if nxt else -1)
        METRICS.set("qrdx_fork_ready_peers", readiness["ready_for_next_fork"])
        METRICS.set("qrdx_fork_reporting_peers", readiness["reporting"])
        METRICS.set("qrdx_forks_active", sum(1 for f in CHAIN_SPEC.forks if f["height"] <= tip))
    except Exception:
        pass
    return Response(METRICS.render_prometheus(), media_type="text/plain; version=0.0.4")


def _perp_snapshots(channels) -> list:
    """Current state for newly subscribed perps channels (qrdx/exchange/stream.py)."""
    wanted = [c for c in channels if c.startswith("perp_")]
    if not wanted:
        return []
    try:
        from qrdx.exchange import ExchangeStateManager
        from qrdx.exchange.stream import initial_snapshots

        return initial_snapshots(ExchangeStateManager.get_instance(), wanted)
    except Exception as e:
        logger.debug(f"stream snapshot failed: {e}")
        return []


@app.get("/stream")
async def stream_endpoint(channels: Optional[str] = None):
    """Realtime data stream over Server-Sent Events (HTTP; proxy/curl-friendly). Toggleable —
    404 when QRDX_ENABLE_STREAMING is off. ``?channels=blocks,perp_markets,perp_book:BTC-USD-PERP,
    perp_events,perp_account:0xPQ…`` picks the feeds (default: blocks); perps channels start
    with a snapshot of the current state."""
    if not _node.STREAMING_ENABLED:
        return JSONResponse(
            {"error": "streaming disabled", "hint": "set QRDX_ENABLE_STREAMING=1"}, status_code=404
        )
    METRICS.inc("qrdx_stream_connections_total")
    chosen = parse_channels(channels)
    return StreamingResponse(
        sse_stream(EVENT_HUB, channels=chosen, initial=_perp_snapshots(chosen or ())),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.websocket("/ws")
async def ws_stream(websocket: WebSocket):
    """Realtime data stream over WebSocket. Toggleable — closed immediately (policy 1008) when
    QRDX_ENABLE_STREAMING is off. The default feed is blocks; a client changes its feeds by
    sending ``{"op": "subscribe" | "unsubscribe" | "set", "channels": [...]}`` (or
    ``{"op": "channels"}`` to list them), or with ``?channels=`` on the URL. Channels:
    ``blocks``, ``perp_markets[:<id>]``, ``perp_book:<id>``, ``perp_events[:<id>]``,
    ``perp_account:<address>`` — each perps subscription starts with a snapshot."""
    if not _node.STREAMING_ENABLED:
        await websocket.close(code=1008)  # policy violation: disabled
        return
    await websocket.accept()
    METRICS.inc("qrdx_ws_connections_total")
    query = getattr(websocket, "query_params", None) or {}
    q = EVENT_HUB.subscribe(parse_channels(query.get("channels")))

    async def _reader():
        # Control frames are answered through the client's own queue, so the one sender below
        # writes every frame (no concurrent sends on the socket).
        receive = getattr(websocket, "receive_json", None)
        if receive is None:
            await asyncio.Event().wait()  # a socket that cannot receive: feed only
        while True:
            try:
                frame = await receive()
            except WebSocketDisconnect:
                return
            except Exception:
                EVENT_HUB.deliver(q, {"type": "error", "error": "expected a JSON object"})
                continue
            before = EVENT_HUB.channels(q)
            EVENT_HUB.deliver(q, handle_client_frame(EVENT_HUB, q, frame))
            for event in _perp_snapshots(EVENT_HUB.channels(q) - before):
                EVENT_HUB.deliver(q, event)

    reader = asyncio.create_task(_reader())
    try:
        await websocket.send_json(
            {
                "type": "hello",
                "ts": time.time(),
                "version": NODE_VERSION,
                "channels": sorted(EVENT_HUB.channels(q)),
            }
        )
        for event in _perp_snapshots(EVENT_HUB.channels(q)):
            await websocket.send_json(event)
        while not reader.done():
            getter = asyncio.ensure_future(q.get())
            done, _ = await asyncio.wait(
                {getter, reader}, timeout=30.0, return_when=asyncio.FIRST_COMPLETED
            )
            if getter in done:
                await websocket.send_json(getter.result())
            else:
                getter.cancel()
                if not done:
                    await websocket.send_json(
                        {"type": "ping", "ts": time.time()}
                    )  # detect dead peers
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        reader.cancel()
        EVENT_HUB.unsubscribe(q)
