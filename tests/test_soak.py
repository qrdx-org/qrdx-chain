"""
Soak-invariant monitor (integration_tests/soak.py) — verdict logic + invariant detection, driven by
mocked /metrics so no live network is needed.
"""
import pytest

import integration_tests.soak as soak
from integration_tests.soak import SoakReport, run_soak_phase

URLS = ["http://n0", "http://n1", "http://n2"]


def _feeder(seq):
    """Return a _scrape_metrics stand-in that yields successive per-tick metric dicts (by url).
    `seq` is a list of {url: {metric: value}} snapshots; the last repeats."""
    state = {"i": 0}

    def scrape(url, timeout=5.0):
        snap = seq[min(state["i"], len(seq) - 1)]
        # advance the tick index once per full sweep of urls
        if url == URLS[-1]:
            state["i"] += 1
        return snap.get(url, {})
    return scrape


def _uniform(height, finalized=1, slashing=0, reorgs=0, lag=0, mempool=0):
    return {u: {"qrdx_chain_height": height, "qrdx_finalized_epoch": finalized,
                "qrdx_slashing_events": slashing, "qrdx_reorgs_total": reorgs,
                "qrdx_finality_lag_epochs": lag, "qrdx_mempool_pending": mempool} for u in URLS}


def test_report_verdict_and_summary():
    r = SoakReport()
    assert r.passed
    r.violate("liveness", "stalled")
    assert not r.passed and "liveness: stalled" in r.summary()


@pytest.mark.asyncio
async def test_healthy_network_passes(monkeypatch):
    # Height advances each tick, finality climbs, 0 slashing, converged.
    seq = [_uniform(h, finalized=1 + h // 3) for h in range(1, 12)]
    monkeypatch.setattr(soak, "_scrape_metrics", _feeder(seq))
    monkeypatch.setattr(soak, "_healthz_ok", lambda u, timeout=5.0: True)
    rep = await run_soak_phase(URLS, duration=0.3, interval=0.02)
    assert rep.passed, rep.summary()
    assert rep.end_max_height > rep.start_max_height
    assert rep.end_finalized > rep.start_finalized


@pytest.mark.asyncio
async def test_detects_liveness_stall(monkeypatch):
    monkeypatch.setattr(soak, "_scrape_metrics", _feeder([_uniform(5)]))   # height never moves
    monkeypatch.setattr(soak, "_healthz_ok", lambda u, timeout=5.0: True)
    rep = await run_soak_phase(URLS, duration=0.3, interval=0.01, stall_ticks=4)
    assert not rep.passed
    assert any(v.startswith("liveness") for v in rep.violations)


@pytest.mark.asyncio
async def test_detects_stuck_node(monkeypatch):
    """A node whose height is FROZEN while the network advances → convergence (no-progress)
    violation. A merely-trailing node that still rises must NOT trigger it."""
    def snap(h0, h1, h2, fin):
        return {"http://n0": {"qrdx_chain_height": h0, "qrdx_finalized_epoch": fin},
                "http://n1": {"qrdx_chain_height": h1, "qrdx_finalized_epoch": fin},
                "http://n2": {"qrdx_chain_height": h2, "qrdx_finalized_epoch": fin}}
    # n2 stuck at 3 forever; n0/n1 advance.
    seq = [snap(h, h, 3, 1 + h // 3) for h in range(4, 16)]
    monkeypatch.setattr(soak, "_scrape_metrics", _feeder(seq))
    monkeypatch.setattr(soak, "_healthz_ok", lambda u, timeout=5.0: True)
    rep = await run_soak_phase(URLS, duration=0.25, interval=0.02, stall_ticks=50)  # not a max-stall
    assert not rep.passed
    assert any(v.startswith("convergence") for v in rep.violations)


@pytest.mark.asyncio
async def test_trailing_but_advancing_node_passes(monkeypatch):
    """A node trailing by a large but ADVANCING margin is fine (state converges; height catches up)."""
    def snap(h):
        return {"http://n0": {"qrdx_chain_height": h, "qrdx_finalized_epoch": 1 + h // 3},
                "http://n1": {"qrdx_chain_height": h, "qrdx_finalized_epoch": 1 + h // 3},
                "http://n2": {"qrdx_chain_height": max(1, h - 9), "qrdx_finalized_epoch": 1 + h // 3}}
    seq = [snap(h) for h in range(10, 24)]
    monkeypatch.setattr(soak, "_scrape_metrics", _feeder(seq))
    monkeypatch.setattr(soak, "_healthz_ok", lambda u, timeout=5.0: True)
    rep = await run_soak_phase(URLS, duration=0.25, interval=0.02)
    assert rep.passed, rep.summary()
    assert rep.worst_live_spread >= 9


@pytest.mark.asyncio
async def test_detects_slashing_safety_violation(monkeypatch):
    seq = [_uniform(h, slashing=1) for h in range(1, 12)]  # advancing but slashing recorded
    monkeypatch.setattr(soak, "_scrape_metrics", _feeder(seq))
    monkeypatch.setattr(soak, "_healthz_ok", lambda u, timeout=5.0: True)
    rep = await run_soak_phase(URLS, duration=0.2, interval=0.02)
    assert not rep.passed
    assert any(v.startswith("safety") for v in rep.violations)


@pytest.mark.asyncio
async def test_detects_finality_lag_falling_behind(monkeypatch):
    """Finality advances but the tip outruns it → the lag peaks past the bound → finality-lag
    violation (distinct from the finalized-frozen check)."""
    seq = [_uniform(h, finalized=1 + h // 5, lag=h) for h in range(1, 20)]  # lag grows with height
    monkeypatch.setattr(soak, "_scrape_metrics", _feeder(seq))
    monkeypatch.setattr(soak, "_healthz_ok", lambda u, timeout=5.0: True)
    rep = await run_soak_phase(URLS, duration=0.3, interval=0.01, max_finality_lag=8)
    assert not rep.passed
    assert any(v.startswith("finality-lag") for v in rep.violations)
    assert rep.max_finality_lag >= 9


@pytest.mark.asyncio
async def test_bounded_finality_lag_and_mempool_pass(monkeypatch):
    seq = [_uniform(h, finalized=1 + h // 3, lag=2, mempool=5) for h in range(1, 14)]
    monkeypatch.setattr(soak, "_scrape_metrics", _feeder(seq))
    monkeypatch.setattr(soak, "_healthz_ok", lambda u, timeout=5.0: True)
    rep = await run_soak_phase(URLS, duration=0.2, interval=0.02, max_finality_lag=8)
    assert rep.passed, rep.summary()
    assert rep.max_finality_lag == 2 and rep.max_mempool == 5


@pytest.mark.asyncio
async def test_detects_unhealthy_node(monkeypatch):
    seq = [_uniform(h) for h in range(1, 12)]
    monkeypatch.setattr(soak, "_scrape_metrics", _feeder(seq))
    monkeypatch.setattr(soak, "_healthz_ok", lambda u, timeout=5.0: u != "http://n1")  # n1 down
    rep = await run_soak_phase(URLS, duration=0.15, interval=0.02)
    assert not rep.passed
    assert any("health" in v and "n1" in v for v in rep.violations)


@pytest.mark.asyncio
async def test_detects_finality_frozen(monkeypatch):
    seq = [_uniform(h, finalized=3) for h in range(1, 12)]  # height moves, finality stuck at 3
    monkeypatch.setattr(soak, "_scrape_metrics", _feeder(seq))
    monkeypatch.setattr(soak, "_healthz_ok", lambda u, timeout=5.0: True)
    rep = await run_soak_phase(URLS, duration=0.15, interval=0.02)
    assert not rep.passed
    assert any(v.startswith("finality") for v in rep.violations)


def test_scrape_metrics_parses(monkeypatch):
    import io
    text = ("# TYPE qrdx_chain_height gauge\nqrdx_chain_height 42\n"
            'qrdx_rpc_requests_total{method="x"} 9\nqrdx_slashing_events 0\n')
    monkeypatch.setattr(soak.urllib.request, "urlopen",
                        lambda *a, **k: io.BytesIO(text.encode()))
    m = soak._scrape_metrics("http://n")
    assert m["qrdx_chain_height"] == 42 and m["qrdx_slashing_events"] == 0
    assert not any("{" in k for k in m)  # labeled series skipped
