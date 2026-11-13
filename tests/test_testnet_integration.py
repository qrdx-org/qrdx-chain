"""
Pytest wrapper for the QRDX integration testnet.

Runs the canonical scenario suite (``integration_tests.run_scenarios.ALL_SCENARIOS``) once,
against one live multi-node testnet and in dependency order — exactly what
``python -m integration_tests.run_scenarios`` does — and reports each scenario as its own test.

    pytest tests/test_testnet_integration.py -m integration -q
    pytest tests/test_testnet_integration.py -m integration -k s22

(``-k`` selects which results are reported; the suite always runs whole, because later
scenarios depend on earlier ones.) The previous wrapper ran every scenario through a fresh
runner, so each one after the first was skipped for "unmet dependencies", and it covered only
13 of the scenarios.
"""

import asyncio
import os
from typing import Any, Dict, Optional

import pytest

from integration_tests.config import build_node_specs
from integration_tests.orchestrator import TestnetOrchestrator
from integration_tests.run_scenarios import ALL_SCENARIOS
from integration_tests.scenarios.base import ScenarioContext, ScenarioResult, ScenarioRunner

# The whole suite runs in the first test's setup and takes several minutes.
pytestmark = [pytest.mark.integration, pytest.mark.timeout(3600)]

SCENARIO_NAMES = [cls.name for cls in ALL_SCENARIOS]


# The nightly run (.github/workflows/nightly.yml) adds, after the scenarios, the attacks of
# integration_tests/adversarial.py (QRDX_ADVERSARIAL=1) and a soak with a node killed and
# restarted (QRDX_SOAK_SECONDS=N): each reported as a test of its own.
ADVERSARIAL = os.environ.get("QRDX_ADVERSARIAL") == "1"
SOAK_SECONDS = float(os.environ.get("QRDX_SOAK_SECONDS") or 0)


async def _run_suite() -> Optional[Dict[str, Any]]:
    orch = TestnetOrchestrator(force_regenerate=True)
    try:
        await orch.setup()
        await orch.start_all_nodes()
        if not await orch.wait_network_ready():
            return None
        specs = build_node_specs(orch.num_nodes, orch.num_validators)
        urls = [p.url for p in orch.node_processes]
        ctx = ScenarioContext(
            orchestrator=orch,
            wallets=orch.wallets,
            node_urls=urls,
            db_paths=[s.db_path for s in specs],
        )
        runner = ScenarioRunner(ctx)
        runner.register_all(ALL_SCENARIOS)
        results: Dict[str, Any] = {
            r.name: r for r in await runner.run_all(stop_on_failure=False)}
        if ADVERSARIAL:
            from integration_tests.adversarial import run_adversarial_phase

            results["adversarial"] = await run_adversarial_phase(
                urls, [s.db_path for s in specs], orch.get_wallet("Validator 0"))
        if SOAK_SECONDS:
            from integration_tests.soak import run_soak_phase

            results["soak"] = await run_soak_phase(
                urls, duration=SOAK_SECONDS, node_processes=orch.node_processes,
                fault_inject=True,
                expected_slashings=results["adversarial"].slashings if ADVERSARIAL else 0)
        return results
    finally:
        await orch.stop_all_nodes()


@pytest.fixture(scope="module")
def suite_results() -> Optional[Dict[str, ScenarioResult]]:
    return asyncio.run(_run_suite())


def test_the_testnet_reaches_ready_state(suite_results):
    assert suite_results is not None, "testnet failed to reach ready state"


@pytest.mark.parametrize("name", SCENARIO_NAMES)
def test_scenario(suite_results, name):
    assert suite_results is not None, "testnet failed to reach ready state"
    result = suite_results[name]
    assert result.passed, (
        f"{name}: {result.error_message} ({result.checks_passed}/{result.checks_total} checks)"
    )


@pytest.mark.skipif(not ADVERSARIAL, reason="QRDX_ADVERSARIAL=1: the nightly run")
def test_the_network_holds_against_attacks(suite_results):
    assert suite_results is not None, "testnet failed to reach ready state"
    report = suite_results["adversarial"]
    assert report.passed, report.summary()


@pytest.mark.skipif(not SOAK_SECONDS, reason="QRDX_SOAK_SECONDS=N: the nightly run")
def test_the_soak_holds_its_invariants(suite_results):
    assert suite_results is not None, "testnet failed to reach ready state"
    report = suite_results["soak"]
    assert report.passed, report.summary()
