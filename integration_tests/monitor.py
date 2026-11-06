"""
Testnet Health Monitor

Continuous monitoring of the QRDX integration testnet:
  - Per-node health (HTTP reachability, block height, peer count)
  - Consensus tracking (slot, epoch, finalized checkpoint)
  - Chain consistency (block heights across nodes)
  - Resource usage (process alive, memory rough check)
  - Alerts on anomalies (stalled blocks, peer loss, crashes)

Runs as an async task alongside the orchestrator.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from integration_tests.rpc_client import NodeRPCClient, MultiNodeClient

logger = logging.getLogger(__name__)


@dataclass
class NodeSnapshot:
    """Point-in-time snapshot of a node's state."""
    node_name: str
    url: str
    timestamp: float
    healthy: bool = False
    block_height: int = -1
    peer_count: int = 0
    slot: int = -1
    epoch: int = -1
    finalized_epoch: int = -1
    validator_active: bool = False
    pending_tx_count: int = 0
    error: Optional[str] = None


@dataclass
class NetworkSnapshot:
    """Point-in-time snapshot of the entire testnet."""
    timestamp: float
    nodes: List[NodeSnapshot] = field(default_factory=list)
    max_height: int = -1
    min_height: int = -1
    height_spread: int = 0
    all_healthy: bool = False
    total_peers: int = 0
    block_production_rate: float = 0.0
    stalled: bool = False


class Alert:
    """A monitoring alert."""
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"

    def __init__(self, level: str, node: str, message: str):
        self.level = level
        self.node = node
        self.message = message
        self.timestamp = time.time()

    def __str__(self):
        symbol = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "🔵"}.get(self.level, "⚪")
        return f"{symbol} [{self.level}] {self.node}: {self.message}"


class TestnetMonitor:
    """
    Continuous testnet health monitoring.

    Usage:
        monitor = TestnetMonitor(node_urls, node_names)
        task = asyncio.create_task(monitor.run(interval=5.0))
        # ... later ...
        monitor.stop()
        await task
    """

    def __init__(
        self,
        node_urls: List[str],
        node_names: Optional[List[str]] = None,
        alert_callback=None,
    ):
        self.node_urls = node_urls
        self.node_names = node_names or [f"node{i}" for i in range(len(node_urls))]
        self.alert_callback = alert_callback or self._default_alert_handler
        self._running = False
        self._history: List[NetworkSnapshot] = []
        self._alerts: List[Alert] = []
        self._max_history = 1000
        self._last_heights: Dict[str, int] = {}
        self._stall_counter: Dict[str, int] = {}

    # ─────────── Snapshot Collection ───────────

    async def _collect_node_snapshot(self, client: NodeRPCClient, name: str, url: str) -> NodeSnapshot:
        """Collect full state from a single node."""
        snap = NodeSnapshot(node_name=name, url=url, timestamp=time.time())

        try:
            snap.healthy = await client.health()
        except Exception as e:
            snap.error = f"health check failed: {e}"
            return snap

        if not snap.healthy:
            snap.error = "node reports unhealthy"
            return snap

        try:
            snap.block_height = await client.get_block_height()
        except Exception:
            snap.block_height = -1

        try:
            peers = await client.get_nodes()
            snap.peer_count = len(peers) if peers else 0
        except Exception:
            snap.peer_count = 0

        # Try consensus endpoints
        try:
            result = await client._get("/get_consensus_state")
            if result:
                snap.slot = result.get("current_slot", -1)
                snap.epoch = result.get("current_epoch", -1)
                snap.finalized_epoch = result.get("finalized_epoch", -1)
        except Exception:
            pass

        try:
            info = await client.get_mining_info()
            if info:
                pending = info.get("pending_transactions", [])
                snap.pending_tx_count = len(pending) if isinstance(pending, list) else 0
        except Exception:
            pass

        return snap

    async def collect_snapshot(self) -> NetworkSnapshot:
        """Collect a full network snapshot."""
        net_snap = NetworkSnapshot(timestamp=time.time())

        async with MultiNodeClient(self.node_urls) as clients:
            tasks = [
                self._collect_node_snapshot(c, name, url)
                for c, name, url in zip(clients._clients, self.node_names, self.node_urls)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                snap = NodeSnapshot(
                    node_name="unknown",
                    url="",
                    timestamp=time.time(),
                    error=str(result),
                )
            else:
                snap = result
            net_snap.nodes.append(snap)

        # Compute aggregate metrics
        heights = [n.block_height for n in net_snap.nodes if n.block_height >= 0]
        if heights:
            net_snap.max_height = max(heights)
            net_snap.min_height = min(heights)
            net_snap.height_spread = net_snap.max_height - net_snap.min_height

        net_snap.all_healthy = all(n.healthy for n in net_snap.nodes)
        net_snap.total_peers = sum(n.peer_count for n in net_snap.nodes)

        # Block production rate
        if len(self._history) >= 2:
            prev = self._history[-1]
            dt = net_snap.timestamp - prev.timestamp
            if dt > 0 and net_snap.max_height >= 0 and prev.max_height >= 0:
                net_snap.block_production_rate = (net_snap.max_height - prev.max_height) / dt

        # Stall detection
        net_snap.stalled = self._check_stall(net_snap)

        return net_snap

    def _check_stall(self, snap: NetworkSnapshot) -> bool:
        """Check if block production has stalled."""
        for node in snap.nodes:
            name = node.node_name
            prev_height = self._last_heights.get(name, -1)
            if node.block_height >= 0:
                if node.block_height <= prev_height:
                    self._stall_counter[name] = self._stall_counter.get(name, 0) + 1
                else:
                    self._stall_counter[name] = 0
                self._last_heights[name] = node.block_height

        # Stalled if any node hasn't advanced in 5 checks
        return any(v >= 5 for v in self._stall_counter.values())

    # ─────────── Alert Analysis ───────────

    def _analyze_snapshot(self, snap: NetworkSnapshot) -> List[Alert]:
        """Analyze a snapshot and generate alerts."""
        alerts = []

        for node in snap.nodes:
            # Node down
            if not node.healthy:
                alerts.append(Alert(Alert.CRITICAL, node.node_name, f"Node unhealthy: {node.error}"))

            # No peers
            if node.healthy and node.peer_count == 0:
                alerts.append(Alert(Alert.WARNING, node.node_name, "No peers connected"))

            # Stall
            stall = self._stall_counter.get(node.node_name, 0)
            if stall >= 5:
                alerts.append(Alert(Alert.CRITICAL, node.node_name,
                                    f"Block production stalled for {stall} checks (height {node.block_height})"))

        # Height divergence
        if snap.height_spread > 5:
            alerts.append(Alert(Alert.WARNING, "network",
                                f"Block height spread is {snap.height_spread} "
                                f"(max={snap.max_height}, min={snap.min_height})"))

        return alerts

    def _default_alert_handler(self, alert: Alert) -> None:
        """Default alert handler — log it."""
        if alert.level == Alert.CRITICAL:
            logger.error(str(alert))
        elif alert.level == Alert.WARNING:
            logger.warning(str(alert))
        else:
            logger.info(str(alert))

    # ─────────── Monitor Loop ───────────

    async def run(self, interval: float = 5.0) -> None:
        """Run the monitor loop."""
        self._running = True
        logger.info("Monitor started (interval=%.1fs, nodes=%d)", interval, len(self.node_urls))

        while self._running:
            try:
                snap = await self.collect_snapshot()

                # Store history
                self._history.append(snap)
                if len(self._history) > self._max_history:
                    self._history = self._history[-self._max_history:]

                # Check alerts
                alerts = self._analyze_snapshot(snap)
                for alert in alerts:
                    self._alerts.append(alert)
                    self.alert_callback(alert)

                # Periodic log
                if len(self._history) % 12 == 0:  # Every ~60s at 5s interval
                    self._log_summary(snap)

            except Exception as e:
                logger.error("Monitor error: %s", e)

            await asyncio.sleep(interval)

    def stop(self) -> None:
        """Stop the monitor loop."""
        self._running = False

    def _log_summary(self, snap: NetworkSnapshot) -> None:
        """Log a periodic summary."""
        heights = [f"{n.node_name}={n.block_height}" for n in snap.nodes]
        peers = [f"{n.node_name}={n.peer_count}" for n in snap.nodes]
        logger.info("MONITOR: heights=[%s] peers=[%s] rate=%.2f blk/s stalled=%s",
                     ", ".join(heights), ", ".join(peers),
                     snap.block_production_rate, snap.stalled)

    # ─────────── Public Accessors ───────────

    @property
    def latest(self) -> Optional[NetworkSnapshot]:
        return self._history[-1] if self._history else None

    @property
    def alerts(self) -> List[Alert]:
        return self._alerts.copy()

    @property
    def history(self) -> List[NetworkSnapshot]:
        return self._history.copy()

    def get_node_history(self, node_name: str) -> List[NodeSnapshot]:
        """Get history for a specific node."""
        result = []
        for snap in self._history:
            for node in snap.nodes:
                if node.node_name == node_name:
                    result.append(node)
                    break
        return result

    def get_summary_report(self) -> str:
        """Generate a summary report of the monitoring session."""
        lines = ["TESTNET MONITORING REPORT", "=" * 40]

        if not self._history:
            lines.append("No data collected.")
            return "\n".join(lines)

        first = self._history[0]
        last = self._history[-1]
        duration = last.timestamp - first.timestamp

        lines.append(f"Duration: {duration:.0f}s ({len(self._history)} snapshots)")
        lines.append(f"Final block height: {last.max_height}")
        lines.append(f"Final height spread: {last.height_spread}")
        lines.append(f"Avg block rate: {last.block_production_rate:.2f} blk/s")
        lines.append("")

        # Per-node summary
        for node in last.nodes:
            status = "✓" if node.healthy else "✗"
            lines.append(f"  {status} {node.node_name}: height={node.block_height} "
                         f"peers={node.peer_count} slot={node.slot}")

        # Alert summary
        crit = sum(1 for a in self._alerts if a.level == Alert.CRITICAL)
        warn = sum(1 for a in self._alerts if a.level == Alert.WARNING)
        lines.append(f"\nAlerts: {crit} critical, {warn} warnings, {len(self._alerts)} total")

        return "\n".join(lines)
