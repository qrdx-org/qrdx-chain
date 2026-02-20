"""
QRDX Prometheus Metrics Collector

Pure-Python Prometheus exposition format implementation.
No external dependency on ``prometheus_client`` — we generate the text
format ourselves so the node has zero extra requirements.

Metric types:
    - Counter   — monotonically increasing (e.g. total_transactions)
    - Gauge     — can go up and down (e.g. peer_count)
    - Histogram — request latencies with configurable buckets

Exposition endpoint is a plain HTTP handler returning ``text/plain``
in Prometheus text format (version 0.0.4).
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Metric primitives
# ---------------------------------------------------------------------------

@dataclass
class Counter:
    """Monotonically increasing counter."""
    name: str
    help: str = ""
    _value: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def inc(self, amount: float = 1.0) -> None:
        if amount < 0:
            raise ValueError("Counter can only be incremented")
        with self._lock:
            self._value += amount

    @property
    def value(self) -> float:
        return self._value

    def expose(self) -> str:
        lines = []
        if self.help:
            lines.append(f"# HELP {self.name} {self.help}")
        lines.append(f"# TYPE {self.name} counter")
        lines.append(f"{self.name} {self._value}")
        return "\n".join(lines)


@dataclass
class Gauge:
    """Gauge that can go up and down."""
    name: str
    help: str = ""
    _value: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def set(self, value: float) -> None:
        with self._lock:
            self._value = value

    def inc(self, amount: float = 1.0) -> None:
        with self._lock:
            self._value += amount

    def dec(self, amount: float = 1.0) -> None:
        with self._lock:
            self._value -= amount

    @property
    def value(self) -> float:
        return self._value

    def expose(self) -> str:
        lines = []
        if self.help:
            lines.append(f"# HELP {self.name} {self.help}")
        lines.append(f"# TYPE {self.name} gauge")
        lines.append(f"{self.name} {self._value}")
        return "\n".join(lines)


# Default histogram buckets (latency in seconds)
DEFAULT_BUCKETS: Tuple[float, ...] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)


@dataclass
class Histogram:
    """Histogram with configurable buckets."""
    name: str
    help: str = ""
    buckets: Tuple[float, ...] = DEFAULT_BUCKETS
    _bucket_counts: Dict[float, int] = field(default_factory=dict, repr=False)
    _sum: float = 0.0
    _count: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self):
        if not self._bucket_counts:
            self._bucket_counts = {b: 0 for b in self.buckets}
            self._bucket_counts[math.inf] = 0  # +Inf bucket

    def observe(self, value: float) -> None:
        with self._lock:
            self._sum += value
            self._count += 1
            # Increment only the first (smallest) matching bucket
            for b in sorted(self.buckets):
                if value <= b:
                    self._bucket_counts[b] = self._bucket_counts.get(b, 0) + 1
                    break

    @property
    def count(self) -> int:
        return self._count

    @property
    def sum(self) -> float:
        return self._sum

    def expose(self) -> str:
        lines = []
        if self.help:
            lines.append(f"# HELP {self.name} {self.help}")
        lines.append(f"# TYPE {self.name} histogram")

        cumulative = 0
        for b in sorted(self.buckets):
            cumulative += self._bucket_counts.get(b, 0)
            le = f"{b}" if b != math.inf else "+Inf"
            lines.append(f'{self.name}_bucket{{le="{le}"}} {cumulative}')

        # +Inf bucket = total count
        lines.append(f'{self.name}_bucket{{le="+Inf"}} {self._count}')
        lines.append(f"{self.name}_sum {self._sum}")
        lines.append(f"{self.name}_count {self._count}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class MetricsRegistry:
    """
    Central registry holding all metrics.

    Provides ``expose()`` to render all metrics in Prometheus text format.
    """

    def __init__(self):
        self._metrics: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def register(self, metric: Any) -> None:
        """Register a metric (Counter, Gauge, or Histogram)."""
        with self._lock:
            if metric.name in self._metrics:
                raise ValueError(f"Metric already registered: {metric.name}")
            self._metrics[metric.name] = metric

    def unregister(self, name: str) -> None:
        with self._lock:
            self._metrics.pop(name, None)

    def get(self, name: str) -> Optional[Any]:
        return self._metrics.get(name)

    @property
    def metric_count(self) -> int:
        return len(self._metrics)

    def expose(self) -> str:
        """
        Render all registered metrics in Prometheus text exposition format.

        Returns:
            String in Prometheus text format (0.0.4)
        """
        parts: List[str] = []
        with self._lock:
            for metric in self._metrics.values():
                parts.append(metric.expose())
        return "\n\n".join(parts) + "\n"


# ---------------------------------------------------------------------------
# Node-level collector — pre-registers standard QRDX metrics
# ---------------------------------------------------------------------------

class MetricsCollector:
    """
    Pre-configured metrics for a QRDX node.

    Instantiate once at node startup and update metrics as events occur.
    Call ``expose()`` to get the Prometheus endpoint body.
    """

    def __init__(self):
        self.registry = MetricsRegistry()

        # --- Block metrics ---
        self.block_height = Gauge(
            "qrdx_block_height",
            "Current block height",
        )
        self.blocks_processed = Counter(
            "qrdx_blocks_processed_total",
            "Total blocks processed",
        )
        self.block_processing_time = Histogram(
            "qrdx_block_processing_seconds",
            "Block processing time in seconds",
        )

        # --- Transaction metrics ---
        self.transactions_total = Counter(
            "qrdx_transactions_total",
            "Total transactions processed",
        )
        self.mempool_size = Gauge(
            "qrdx_mempool_size",
            "Current mempool size",
        )

        # --- Network metrics ---
        self.peer_count = Gauge(
            "qrdx_peer_count",
            "Number of connected peers",
        )
        self.ws_connections = Gauge(
            "qrdx_ws_connections",
            "Active WebSocket connections",
        )

        # --- Validator metrics ---
        self.validator_active = Gauge(
            "qrdx_validator_active",
            "Whether this node is an active validator (0 or 1)",
        )
        self.attestations_sent = Counter(
            "qrdx_attestations_sent_total",
            "Total attestations sent",
        )
        self.proposals_made = Counter(
            "qrdx_proposals_made_total",
            "Total blocks proposed",
        )

        # --- RPC metrics ---
        self.rpc_requests_total = Counter(
            "qrdx_rpc_requests_total",
            "Total RPC requests handled",
        )
        self.rpc_errors_total = Counter(
            "qrdx_rpc_errors_total",
            "Total RPC errors",
        )
        self.rpc_latency = Histogram(
            "qrdx_rpc_latency_seconds",
            "RPC request latency in seconds",
        )

        # --- Consensus metrics ---
        self.finalized_epoch = Gauge(
            "qrdx_finalized_epoch",
            "Last finalized epoch",
        )
        self.current_slot = Gauge(
            "qrdx_current_slot",
            "Current consensus slot",
        )

        # --- System metrics ---
        self.uptime_seconds = Gauge(
            "qrdx_uptime_seconds",
            "Node uptime in seconds",
        )
        self._start_time = time.time()

        # Register all
        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            if isinstance(attr, (Counter, Gauge, Histogram)):
                self.registry.register(attr)

    def update_uptime(self) -> None:
        """Refresh the uptime gauge."""
        self.uptime_seconds.set(time.time() - self._start_time)

    def expose(self) -> str:
        """
        Render all metrics in Prometheus text exposition format.

        Automatically updates uptime before rendering.
        """
        self.update_uptime()
        return self.registry.expose()
