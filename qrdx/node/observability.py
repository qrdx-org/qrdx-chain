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
# Channels a stream client may subscribe to. Every event names its ``channel`` (block events:
# "blocks") and may carry a ``key`` (a market id, an address); a subscription to "<channel>"
# receives every event on it, one to "<channel>:<key>" only that key's. A client that never
# subscribes receives DEFAULT_CHANNELS — the block feed, exactly as before channels existed.
DEFAULT_CHANNELS = frozenset({"blocks"})
STREAM_CHANNELS = frozenset({"blocks", "perp_markets", "perp_book", "perp_events", "perp_account",
                             "spot_pools", "spot_book", "spot_account", "tokens"})
# Channels that only make sense for one market / pair / address.
KEYED_CHANNELS = frozenset({"perp_book", "perp_account", "spot_book", "spot_account"})
MAX_CHANNELS_PER_CLIENT = 64
MAX_CHANNEL_LEN = 160


def valid_channel(name: Any) -> bool:
    if not isinstance(name, str) or not name or len(name) > MAX_CHANNEL_LEN:
        return False
    base, _, key = name.partition(":")
    if base not in STREAM_CHANNELS:
        return False
    if base in KEYED_CHANNELS and not key:
        return False                     # a book / account stream is per market or address
    return all(c.isalnum() or c in "-_:." for c in key)


def canonical_channel(name: str) -> str:
    """The form events are published under: a spot pair in sorted order (token0:token1, as
    pools and books key it), so either order subscribes to the same book; a token address in
    lowercase."""
    base, _, key = name.partition(":")
    if base == "spot_book" and key.count(":") == 1:
        a, b = key.split(":")
        return f"{base}:{min(a, b)}:{max(a, b)}"
    if base == "tokens" and key:
        return f"{base}:{key.lower()}"       # token addresses are lowercase
    return name


def event_matches(channels: Set[str], event: Dict[str, Any]) -> bool:
    channel = event.get("channel", "blocks")
    if channel in channels:
        return True
    key = event.get("key")
    if key is None:
        return False
    return any(f"{channel}:{k}" in channels for k in str(key).split(","))


class EventHub:
    """In-process fan-out of realtime events to any number of subscribers (WebSocket/SSE clients).

    Each subscriber gets its own bounded ``asyncio.Queue`` and its own channel set (see
    STREAM_CHANNELS); on overflow the OLDEST queued event is dropped so a slow consumer can never
    grow node memory or back-pressure the publisher."""

    def __init__(self, max_queue: int = 256):
        self._max_queue = max_queue
        self._subs: Set[asyncio.Queue] = set()
        self._channels: Dict[asyncio.Queue, Set[str]] = {}
        self._dropped = 0

    def subscribe(self, channels: Optional[Set[str]] = None) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self._max_queue)
        self._subs.add(q)
        self._channels[q] = set(channels) if channels else set(DEFAULT_CHANNELS)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)
        self._channels.pop(q, None)

    def channels(self, q: asyncio.Queue) -> Set[str]:
        return set(self._channels.get(q, DEFAULT_CHANNELS))

    def set_channels(self, q: asyncio.Queue, channels: Set[str]) -> None:
        if q in self._subs:
            self._channels[q] = set(channels)

    def wants(self, channel: str, key: Optional[str] = None) -> bool:
        """Whether any subscriber would receive an event on ``channel`` (for ``key``) — so a
        publisher can skip building events nobody listens to."""
        probe = {"channel": channel, "key": key}
        return any(event_matches(ch, probe) for ch in self._channels.values())

    def keys(self, channel: str) -> Set[str]:
        """Every key subscribed to on ``channel`` ("perp_account:0xPQ…" → "0xPQ…")."""
        prefix = channel + ":"
        return {c[len(prefix):] for chans in self._channels.values() for c in chans
                if c.startswith(prefix)}

    @property
    def subscriber_count(self) -> int:
        return len(self._subs)

    @property
    def dropped_count(self) -> int:
        return self._dropped

    def _offer(self, q: asyncio.Queue, event: Dict[str, Any]) -> None:
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

    def publish_nowait(self, event: Dict[str, Any]) -> None:
        """Fan ``event`` out to every subscriber whose channels match it (drop-oldest on a full
        queue). Never raises, never waits."""
        for q in list(self._subs):
            if event_matches(self._channels.get(q, DEFAULT_CHANNELS), event):
                self._offer(q, event)

    async def publish(self, event: Dict[str, Any]) -> None:
        self.publish_nowait(event)

    def deliver(self, q: asyncio.Queue, event: Dict[str, Any]) -> None:
        """Send ``event`` to one subscriber only (e.g. the reply to its subscribe request)."""
        if q in self._subs:
            self._offer(q, event)


def handle_client_frame(hub: EventHub, q: asyncio.Queue, frame: Any) -> Dict[str, Any]:
    """A stream client's control message → the reply to send it.

    ``{"op": "subscribe" | "unsubscribe" | "set", "channels": [...]}`` adds, removes or replaces
    channels; ``{"op": "channels"}`` lists them. Unknown channels are refused, and a client may
    hold at most MAX_CHANNELS_PER_CLIENT."""
    if not isinstance(frame, dict):
        return {"type": "error", "error": "expected a JSON object"}
    op = frame.get("op")
    current = hub.channels(q)
    if op == "channels":
        return {"type": "channels", "channels": sorted(current)}
    if op not in ("subscribe", "unsubscribe", "set"):
        return {"type": "error", "error": f"unknown op {op!r}"}
    requested = frame.get("channels")
    if isinstance(requested, str):
        requested = [requested]
    if not isinstance(requested, list) or not requested:
        return {"type": "error", "error": "channels must be a non-empty list"}
    bad = [c for c in requested if not valid_channel(c)]
    if bad:
        return {"type": "error", "error": f"invalid channel(s): {bad[:5]}"}
    requested = [canonical_channel(c) for c in requested]
    if op == "subscribe":
        updated = current | set(requested)
    elif op == "unsubscribe":
        updated = current - set(requested)
    else:
        updated = set(requested)
    if len(updated) > MAX_CHANNELS_PER_CLIENT:
        return {"type": "error", "error": f"at most {MAX_CHANNELS_PER_CLIENT} channels"}
    hub.set_channels(q, updated)
    return {"type": "subscribed", "channels": sorted(updated)}


def parse_channels(spec: Optional[str]) -> Optional[Set[str]]:
    """A comma-separated channel list (the SSE ``?channels=`` query) → a valid set, or None for
    the default. Invalid names are dropped; the list is capped."""
    if not spec:
        return None
    chans = [canonical_channel(c.strip()) for c in spec.split(",") if valid_channel(c.strip())]
    return set(chans[:MAX_CHANNELS_PER_CLIENT]) or None


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
    get_mempool_depth: Optional[_MaybeAsync] = None,
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
                fin_ep = int(fin.get("finalized_epoch", -1))
                metrics.set("qrdx_finalized_epoch", fin_ep)
                metrics.set("qrdx_justified_epoch", int(fin.get("justified_epoch", -1)))
                # Finality lag = how many epochs the tip is ahead of the finalized boundary. A
                # healthy chain keeps this small + bounded; a growing lag = finality falling behind
                # (the key production alert). -1 finalized (pre-finality) → lag 0 (not yet meaningful).
                max_ep = int(fin.get("max_epoch", -1))
                metrics.set("qrdx_finality_lag_epochs", max(0, max_ep - fin_ep) if fin_ep >= 0 else 0)
            if get_slashing_count is not None:
                metrics.set("qrdx_slashing_events", int(await _maybe_await(get_slashing_count())))
            if get_mempool_depth is not None:
                metrics.set("qrdx_mempool_pending", int(await _maybe_await(get_mempool_depth())))

            if tip > last_height:
                # Emit a per-height block event (cap the catch-up burst so a fresh node that jumps
                # far doesn't flood subscribers).
                start = last_height + 1 if last_height >= 0 else tip
                for h in range(max(start, tip - 63), tip + 1):
                    await hub.publish({
                        "type": "block", "channel": "blocks", "height": h, "ts": time.time(),
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


async def sse_stream(hub: EventHub, *, keepalive: float = 15.0,
                     channels: Optional[Set[str]] = None,
                     initial: Optional[list] = None) -> AsyncIterator[str]:
    """Yield SSE frames from the hub for ``channels`` (None: the default block feed) — first any
    ``initial`` snapshot events — with periodic keepalive comments so idle proxies don't cut the
    connection. Always unsubscribes on exit."""
    q = hub.subscribe(channels)
    try:
        yield sse_frame({"type": "hello", "ts": time.time(), "channels": sorted(hub.channels(q))})
        for event in initial or ():
            yield sse_frame(event)
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=keepalive)
                yield sse_frame(event)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
    finally:
        hub.unsubscribe(q)
