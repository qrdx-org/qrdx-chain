"""
Operational-readiness surface: health/readiness probes, Prometheus metrics, and a realtime
event stream (WebSocket + SSE) fed by an in-process pub/sub hub.

Design goals:
  * ZERO coupling to the consensus/import path — realtime events come from a background POLLER
    that reads the chain tip + finality, so nothing here can stall or diverge block processing.
  * Bounded memory under load — each subscriber has a bounded queue that DROPS OLDEST on overflow
    (telemetry favors the freshest data; a slow client never grows the node's memory).
  * Toggleable streaming — the WebSocket/SSE endpoints are opt-in (a node operator enables them),
    while health + metrics are always available for monitoring.

Pure + framework-agnostic (no FastAPI import here) so the core is unit-testable; main.py wires the
endpoints and the poller's data getters.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Optional, Set, Union


# ─────────────────────────────────────────────────────────────────────────────
# Pub/sub event hub
# ─────────────────────────────────────────────────────────────────────────────
class EventHub:
    """In-process fan-out of realtime events to any number of subscribers (WebSocket/SSE clients).

    Each subscriber gets its own bounded ``asyncio.Queue``; on overflow the OLDEST queued event is
    dropped so a slow consumer can never grow node memory or back-pressure the publisher."""

    def __init__(self, max_queue: int = 256):
        self._max_queue = max_queue
        self._subs: Set[asyncio.Queue] = set()
        self._dropped = 0

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self._max_queue)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    @property
    def subscriber_count(self) -> int:
        return len(self._subs)

    @property
    def dropped_count(self) -> int:
        return self._dropped

    async def publish(self, event: Dict[str, Any]) -> None:
        """Fan ``event`` out to every subscriber (drop-oldest on a full queue). Never raises."""
        for q in list(self._subs):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()          # drop oldest
                    self._dropped += 1
                    q.put_nowait(event)
                except Exception:
                    pass
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# Metrics registry (Prometheus text exposition)
# ─────────────────────────────────────────────────────────────────────────────
class Metrics:
    """Minimal counter/gauge registry rendered in Prometheus text format. Counters only increase;
    gauges are set to a current value. Thread-safety is not needed — the event loop is single-
    threaded and all updates happen on it."""

    def __init__(self):
        self._counters: Dict[str, float] = defaultdict(float)
        self._gauges: Dict[str, float] = {}
        self._help: Dict[str, str] = {}

    def describe(self, name: str, help_text: str) -> None:
        self._help[name] = help_text

    def inc(self, name: str, amount: float = 1.0) -> None:
        self._counters[name] += amount

    def set(self, name: str, value: float) -> None:
        try:
            self._gauges[name] = float(value)
        except (TypeError, ValueError):
            pass

    def snapshot(self) -> Dict[str, float]:
        out: Dict[str, float] = dict(self._gauges)
        out.update(self._counters)
        return out

    def render_prometheus(self) -> str:
        lines = []
        for name, val in sorted(self._counters.items()):
            if name in self._help:
                lines.append(f"# HELP {name} {self._help[name]}")
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {_fmt(val)}")
        for name, val in sorted(self._gauges.items()):
            if name in self._help:
                lines.append(f"# HELP {name} {self._help[name]}")
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {_fmt(val)}")
        return "\n".join(lines) + "\n"


def _fmt(v: float) -> str:
    # Prometheus wants a plain number; render integers without a trailing .0.
    if v == int(v):
        return str(int(v))
    return repr(v)


# ─────────────────────────────────────────────────────────────────────────────
# Realtime chain-event poller (the consensus-decoupled event source)
# ─────────────────────────────────────────────────────────────────────────────
_MaybeAsync = Union[Callable[[], Any], Callable[[], Awaitable[Any]]]


async def _maybe_await(v: Any) -> Any:
    if asyncio.iscoroutine(v):
        return await v
    return v


async def chain_event_poller(
    hub: EventHub,
    metrics: Metrics,
    *,
    get_tip: _MaybeAsync,
    get_peer_count: Optional[_MaybeAsync] = None,
    get_finality: Optional[_MaybeAsync] = None,
    interval: float = 1.0,
    _max_iterations: Optional[int] = None,   # test hook
) -> None:
    """Poll chain tip + finality (+ peer count) and publish deltas to ``hub`` while updating
    ``metrics``. Reads only — never touches the import path. A new-tip transition emits a ``block``
    event per newly-observed height (capped) so streaming clients get a per-block feed. Best-effort:
    a getter error is swallowed and retried next tick."""
    metrics.describe("qrdx_chain_height", "Current chain tip height")
    metrics.describe("qrdx_finalized_epoch", "Highest finalized epoch")
    metrics.describe("qrdx_peer_count", "Connected peer count")
    metrics.describe("qrdx_blocks_streamed_total", "Blocks emitted to the realtime stream")
    metrics.set("qrdx_up", 1)

    last_height = -1
    iterations = 0
    while True:
        try:
            tip = int(await _maybe_await(get_tip()))
            metrics.set("qrdx_chain_height", tip)
            metrics.set("qrdx_stream_subscribers", hub.subscriber_count)
            metrics.set("qrdx_stream_dropped_total", hub.dropped_count)
            if get_peer_count is not None:
                metrics.set("qrdx_peer_count", int(await _maybe_await(get_peer_count())))
            fin: Dict[str, Any] = {}
            if get_finality is not None:
                fin = (await _maybe_await(get_finality())) or {}
                metrics.set("qrdx_finalized_epoch", int(fin.get("finalized_epoch", -1)))
                metrics.set("qrdx_justified_epoch", int(fin.get("justified_epoch", -1)))

            if tip > last_height:
                # Emit a per-height block event (cap the catch-up burst so a fresh node that jumps
                # far doesn't flood subscribers).
                start = last_height + 1 if last_height >= 0 else tip
                for h in range(max(start, tip - 63), tip + 1):
                    await hub.publish({
                        "type": "block", "height": h, "ts": time.time(),
                        "finalized_epoch": int(fin.get("finalized_epoch", -1)) if fin else None,
                    })
                    metrics.inc("qrdx_blocks_streamed_total")
                last_height = tip
        except asyncio.CancelledError:
            break
        except Exception:
            pass
        iterations += 1
        if _max_iterations is not None and iterations >= _max_iterations:
            break
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            break


# ─────────────────────────────────────────────────────────────────────────────
# Stream framing helpers (shared by WebSocket + SSE)
# ─────────────────────────────────────────────────────────────────────────────
def sse_frame(event: Dict[str, Any]) -> str:
    """Format an event as a Server-Sent-Events frame."""
    return f"data: {json.dumps(event, default=str)}\n\n"


async def sse_stream(hub: EventHub, *, keepalive: float = 15.0) -> AsyncIterator[str]:
    """Yield SSE frames from the hub, with periodic keepalive comments so idle proxies don't cut
    the connection. Always unsubscribes on exit."""
    q = hub.subscribe()
    try:
        yield sse_frame({"type": "hello", "ts": time.time()})
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=keepalive)
                yield sse_frame(event)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
    finally:
        hub.unsubscribe(q)
