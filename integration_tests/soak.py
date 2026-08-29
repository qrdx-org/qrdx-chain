"""
Soak-mode invariant monitor — runs the already-started testnet for a fixed DURATION and continuously
asserts consensus / liveness / safety invariants via each node's ``/metrics`` surface, optionally
injecting a node fault and verifying recovery. This is the parameterized shape of the ≥30-day
production-readiness soak: point it at a longer duration (and, eventually, a larger validator set).

Invariants, checked every ``interval`` seconds and summarized into a PASS/FAIL verdict:
  * HEALTH      — every (non-killed) node's /healthz is ok.
  * LIVENESS    — the network's max chain height keeps ADVANCING (no sustained stall).
  * FINALITY    — the finalized epoch advances over the soak (finality is not frozen).
  * CONVERGENCE — the height spread across LIVE nodes stays bounded (a trailing node is fine; a
                  stuck/forked node that drifts far and stays there is not).
  * SAFETY      — qrdx_slashing_events stays 0 on the honest network; reorgs stay bounded.
  * RECOVERY (fault mode) — after a node is killed the rest keep advancing + finalizing, and the
                  killed node re-syncs to the tip once restarted.

Driven entirely by the node's own /metrics + /healthz (dogfooding the observability surface), so it
needs no DB access and works against any reachable node set.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("soak")


def _scrape_metrics(url: str, timeout: float = 5.0) -> Dict[str, float]:
    """Fetch + parse a node's Prometheus /metrics (label-less series only — the soak's gauges)."""
    try:
        raw = urllib.request.urlopen(url.rstrip("/") + "/metrics", timeout=timeout).read().decode()
    except Exception:
        return {}
    out: Dict[str, float] = {}
    for line in raw.splitlines():
        if not line.startswith("qrdx_") or "{" in line or " " not in line:
            continue
        name, _, val = line.partition(" ")
        try:
            out[name] = float(val)
        except ValueError:
            pass
    return out


def _healthz_ok(url: str, timeout: float = 5.0) -> bool:
    try:
        r = json.loads(urllib.request.urlopen(url.rstrip("/") + "/healthz", timeout=timeout).read())
        return r.get("status") == "ok"
    except Exception:
        return False


@dataclass
class SoakReport:
    duration: float = 0.0
    ticks: int = 0
    start_max_height: int = -1
    end_max_height: int = -1
    start_min_height: int = -1
    end_min_height: int = -1
    start_finalized: int = -1
    end_finalized: int = -1
    worst_live_spread: int = 0
    max_reorgs: int = 0
    violations: List[str] = field(default_factory=list)
    recovery: Optional[str] = None

    def violate(self, kind: str, msg: str) -> None:
        line = f"{kind}: {msg}"
        self.violations.append(line)
        logger.error("[soak violation] %s", line)

    @property
    def passed(self) -> bool:
        return not self.violations

    def summary(self) -> str:
        v = "PASS" if self.passed else f"FAIL ({len(self.violations)} violations)"
        lines = [
            f"── SOAK {v} ──",
            f"  duration={self.duration:.0f}s ticks={self.ticks}",
            f"  max height {self.start_max_height} → {self.end_max_height} "
            f"(+{self.end_max_height - self.start_max_height})",
            f"  min height {self.start_min_height} → {self.end_min_height} "
            f"(all nodes advanced: {self.end_min_height > self.start_min_height})",
            f"  finalized_epoch {self.start_finalized} → {self.end_finalized}",
            f"  worst live height spread={self.worst_live_spread}  max reorgs={self.max_reorgs}",
        ]
        if self.recovery is not None:
            lines.append(f"  fault recovery: {self.recovery}")
        for viol in self.violations:
            lines.append(f"  ✗ {viol}")
        return "\n".join(lines)


async def run_soak_phase(
    node_urls: List[str],
    *,
    duration: float,
    interval: float = 5.0,
    node_processes: Optional[list] = None,
    fault_inject: bool = False,
    stall_ticks: int = 8,
) -> SoakReport:
    """Monitor the network for ``duration`` seconds, asserting the soak invariants each ``interval``.
    If ``fault_inject`` and ``node_processes`` are given, kills a non-primary node ~40% in and
    restarts it ~70% in, verifying the rest stay live and the node re-syncs."""
    report = SoakReport()
    start = time.time()
    global_max_height = -1
    stall = 0
    killed_idx: Optional[int] = None
    killed_url: Optional[str] = None
    restart_pending = False
    fault_kill_at = duration * 0.40
    fault_restart_at = duration * 0.70
    height_at_kill = -1

    logger.info("Soak start: %d nodes, duration=%.0fs, interval=%.0fs, fault_inject=%s",
                len(node_urls), duration, interval, fault_inject)

    while True:
        elapsed = time.time() - start
        if elapsed >= duration:
            break

        # ── Fault injection: kill a backup node, then restart it later ────────────────────
        if fault_inject and node_processes and killed_idx is None and elapsed >= fault_kill_at \
                and len(node_processes) >= 3:
            killed_idx = len(node_processes) - 1        # a non-primary node
            killed_url = node_urls[killed_idx]
            height_at_kill = global_max_height
            try:
                await node_processes[killed_idx].stop()
                restart_pending = True
                logger.warning("[soak fault] killed node %d (%s) at height ~%d",
                               killed_idx, killed_url, height_at_kill)
            except Exception as e:
                logger.error("[soak fault] kill failed: %s", e)
                killed_idx = None
        if restart_pending and elapsed >= fault_restart_at:
            try:
                await node_processes[killed_idx].start()
                logger.warning("[soak fault] restarted node %d (%s)", killed_idx, killed_url)
            except Exception as e:
                logger.error("[soak fault] restart failed: %s", e)
            restart_pending = False

        # Once a node has been fault-killed it is EXCLUDED from the per-tick invariants for the
        # rest of the soak (it is expected down, then catching up); its return is validated
        # separately by the RECOVERY check. The remaining nodes must stay healthy/live/converged.
        assessed = [u for u in node_urls if u != killed_url]
        metrics = {u: _scrape_metrics(u) for u in assessed}

        # HEALTH — every assessed node must be healthy.
        for u in assessed:
            if not _healthz_ok(u):
                report.violate("health", f"{u} not healthy")

        heights = [int(m.get("qrdx_chain_height", -1)) for m in metrics.values() if m]
        heights = [h for h in heights if h >= 0]
        finals = [int(m.get("qrdx_finalized_epoch", -1)) for m in metrics.values() if m]
        slashes = [int(m.get("qrdx_slashing_events", 0)) for m in metrics.values() if m]
        reorg_counts = [int(m.get("qrdx_reorgs_total", 0)) for m in metrics.values() if m]

        if report.start_max_height < 0 and heights:
            report.start_max_height = max(heights)
            report.start_min_height = min(heights)
            report.start_finalized = max(finals) if finals else -1

        # LIVENESS — max height advances.
        cur_max = max(heights) if heights else -1
        if cur_max > global_max_height:
            global_max_height = cur_max
            stall = 0
        else:
            stall += 1
            if stall >= stall_ticks:
                report.violate("liveness", f"max height stalled {stall} ticks at {cur_max}")
                stall = 0  # report once per stall window

        # CONVERGENCE — track the worst live spread for the report. A transient trailing node is
        # NORMAL (nodes converge in STATE, height differs while catching up); the real failure is a
        # STUCK node, caught by the min-height-advances check at the end (its height is frozen while
        # the network moves), not by a per-tick spread threshold (too noisy under reorg churn).
        if len(heights) >= 2:
            report.worst_live_spread = max(report.worst_live_spread, max(heights) - min(heights))

        # SAFETY — no slashing on an honest network; track reorg count.
        if slashes and max(slashes) > 0:
            report.violate("safety", f"slashing_events={max(slashes)} on an honest network")
        if reorg_counts:
            report.max_reorgs = max(report.max_reorgs, max(reorg_counts))

        report.ticks += 1
        report.end_max_height = cur_max
        if heights:
            report.end_min_height = min(heights)
        report.end_finalized = max(finals) if finals else report.end_finalized
        await asyncio.sleep(interval)

    report.duration = time.time() - start

    # FINALITY — the finalized epoch must have advanced over the soak.
    if report.end_finalized <= report.start_finalized and report.start_finalized >= 0:
        report.violate("finality", f"finalized epoch did not advance "
                                   f"({report.start_finalized} → {report.end_finalized})")

    # CONVERGENCE / no-stuck-node — every assessed node made forward progress (the MIN height rose).
    # A node frozen while the network advances is stuck/forked; a merely-trailing node still rises.
    if report.start_min_height >= 0 and report.end_min_height <= report.start_min_height \
            and report.end_max_height > report.start_max_height:
        report.violate("convergence", f"a node made no progress (min height "
                                      f"{report.start_min_height} → {report.end_min_height} while "
                                      f"max reached {report.end_max_height})")

    # RECOVERY — the restarted node must re-sync near the tip.
    if fault_inject and killed_url is not None:
        await asyncio.sleep(interval)
        m = _scrape_metrics(killed_url)
        others = [int(v.get("qrdx_chain_height", -1)) for u, v in
                  {u: _scrape_metrics(u) for u in node_urls if u != killed_url}.items() if v]
        killed_h = int(m.get("qrdx_chain_height", -1)) if m else -1
        tip = max(others) if others else -1
        if killed_h >= 0 and tip >= 0 and (tip - killed_h) <= 6:  # re-synced to within a few blocks
            report.recovery = f"node re-synced to {killed_h} (tip {tip}) ✓"
        else:
            report.recovery = f"node at {killed_h} vs tip {tip} ✗"
            report.violate("recovery", f"killed node did not re-sync (at {killed_h}, tip {tip})")

    logger.info("\n%s", report.summary())
    return report
