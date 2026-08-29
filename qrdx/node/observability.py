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
    """Minimal counter/gauge registry rendered in Prometheus text format, with optional LABELS
    (e.g. per-RPC-method, per-p2p-event breakdowns). Counters only increase; gauges are set to a
    current value. Thread-safety is not needed — the event loop is single-threaded.

    Labels are passed as a dict; a metric name may carry many label series. Keep label VALUE
    cardinality bounded (method names, event kinds) — never user-supplied unbounded strings."""

    def __init__(self):
        self._counters: Dict[tuple, float] = defaultdict(float)   # (name, labelkey) -> value
        self._gauges: Dict[tuple, float] = {}                     # (name, labelkey) -> value
        self._help: Dict[str, str] = {}

    @staticmethod
    def _lk(labels: Optional[Dict[str, Any]]) -> tuple:
        return tuple(sorted((str(k), str(v)) for k, v in (labels or {}).items()))

    def describe(self, name: str, help_text: str) -> None:
        self._help[name] = help_text

    def inc(self, name: str, amount: float = 1.0, labels: Optional[Dict[str, Any]] = None) -> None:
        self._counters[(name, self._lk(labels))] += amount

    def set(self, name: str, value: float, labels: Optional[Dict[str, Any]] = None) -> None:
        try:
            self._gauges[(name, self._lk(labels))] = float(value)
        except (TypeError, ValueError):
            pass

    @staticmethod
    def _series(name: str, labelkey: tuple) -> str:
        if not labelkey:
            return name
        inner = ",".join(f'{k}="{_esc(v)}"' for k, v in labelkey)
        return f"{name}{{{inner}}}"

    def snapshot(self) -> Dict[str, float]:
        out: Dict[str, float] = {}
        for (name, lk), v in self._gauges.items():
            out[self._series(name, lk)] = v
        for (name, lk), v in self._counters.items():
            out[self._series(name, lk)] = v
        return out

    def _render_group(self, store: Dict[tuple, float], kind: str) -> list:
        by_name: Dict[str, list] = defaultdict(list)
        for (name, lk), v in store.items():
            by_name[name].append((lk, v))
        lines = []
        for name in sorted(by_name):
            if name in self._help:
                lines.append(f"# HELP {name} {self._help[name]}")
            lines.append(f"# TYPE {name} {kind}")
            for lk, v in sorted(by_name[name]):
                lines.append(f"{self._series(name, lk)} {_fmt(v)}")
        return lines

    def render_prometheus(self) -> str:
        lines = self._render_group(self._counters, "counter")
        lines += self._render_group(self._gauges, "gauge")
        return "\n".join(lines) + "\n"


def _fmt(v: float) -> str:
    # Prometheus wants a plain number; render integers without a trailing .0.
    if v == int(v):
        return str(int(v))
    return repr(v)


def _esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


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
    get_slashing_count: Optional[_MaybeAsync] = None,
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
            if get_slashing_count is not None:
                metrics.set("qrdx_slashing_events", int(await _maybe_await(get_slashing_count())))

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
# ─────────────────────────────────────────────────────────────────────────────
# Process-wide singletons — shared by main.py (endpoints + poller) AND the RPC / p2p layers, which
# record into them WITHOUT importing main.py (observability imports only stdlib, so it is safe to
# import from anywhere with no cycle). Recording is best-effort; a metrics error never breaks a
# request or block-propagation path.
# ─────────────────────────────────────────────────────────────────────────────
METRICS = Metrics()
EVENT_HUB = EventHub()


def record(name: str, amount: float = 1.0, labels: Optional[Dict[str, Any]] = None) -> None:
    """Best-effort counter increment on the shared registry (never raises into a caller)."""
    try:
        METRICS.inc(name, amount, labels)
    except Exception:
        pass


def gauge(name: str, value: float, labels: Optional[Dict[str, Any]] = None) -> None:
    """Best-effort gauge set on the shared registry (never raises into a caller)."""
    try:
        METRICS.set(name, value, labels)
    except Exception:
        pass


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
