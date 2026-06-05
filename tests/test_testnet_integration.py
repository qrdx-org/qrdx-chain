"""
Pytest wrapper for the QRDX integration testnet.

Runs the full scenario suite as a pytest test, allowing CI integration.

Usage:
    pytest tests/test_testnet_integration.py -v --timeout=300
    pytest tests/test_testnet_integration.py -v -k "genesis"
"""

import asyncio
import os

import pytest

pytestmark = pytest.mark.integration

from integration_tests.config import build_node_specs, DATABASES_DIR
from integration_tests.orchestrator import TestnetOrchestrator
from integration_tests.scenarios.base import ScenarioContext, ScenarioRunner

# Import scenarios
from integration_tests.scenarios.s01_genesis import S01GenesisBootstrap
from integration_tests.scenarios.s02_peer_mesh import S02PeerMesh
from integration_tests.scenarios.s03_block_production import S03BlockProduction
from integration_tests.scenarios.s04_transactions import S04Transactions
from integration_tests.scenarios.s05_tokens import S05Tokens
from integration_tests.scenarios.s06_pools import S06Pools
from integration_tests.scenarios.s07_validators import S07Validators
from integration_tests.scenarios.s08_governance import S08Governance
from integration_tests.scenarios.s09_bridge import S09Bridge
from integration_tests.scenarios.s10_consistency import S10Consistency
from integration_tests.scenarios.s11_stress import S11Stress


@pytest.fixture(scope="module")
def event_loop():
    """Create an event loop for the module."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="module")
async def testnet(event_loop):
    """Start the full integration testnet for the test module."""
    orch = TestnetOrchestrator(force_regenerate=True)
    await orch.setup()
    await orch.start_all_nodes()
    ready = await orch.wait_network_ready()
    assert ready, "Testnet failed to reach ready state"

    yield orch

    await orch.stop_all_nodes()


@pytest.fixture(scope="module")
def scenario_ctx(testnet):
    """Build a ScenarioContext from the running testnet."""
    node_specs = build_node_specs(testnet.num_nodes, testnet.num_validators)
    return ScenarioContext(
        orchestrator=testnet,
        wallets=testnet.wallets,
        node_urls=[p.url for p in testnet.node_processes],
        db_paths=[s.db_path for s in node_specs],
    )


# ── Individual Scenario Tests ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_s01_genesis_bootstrap(scenario_ctx):
    """S01: Verify genesis block creation and node bootstrap."""
    runner = ScenarioRunner(scenario_ctx)
    runner.register(S01GenesisBootstrap)
    results = await runner.run_all()
    assert results[0].passed, f"S01 failed: {results[0].error_message}"


@pytest.mark.asyncio
async def test_s02_peer_mesh(scenario_ctx):
    """S02: Verify P2P network mesh formation."""
    runner = ScenarioRunner(scenario_ctx)
    runner.register(S02PeerMesh)
    results = await runner.run_all()
    assert results[0].passed, f"S02 failed: {results[0].error_message}"


@pytest.mark.asyncio
async def test_s03_block_production(scenario_ctx):
    """S03: Verify block production and consensus."""
    runner = ScenarioRunner(scenario_ctx)
    runner.register(S03BlockProduction)
    results = await runner.run_all()
    assert results[0].passed, f"S03 failed: {results[0].error_message}"


@pytest.mark.asyncio
async def test_s04_transactions(scenario_ctx):
    """S04: Verify UTXO transaction lifecycle."""
    runner = ScenarioRunner(scenario_ctx)
    runner.register(S04Transactions)
    results = await runner.run_all()
    assert results[0].passed, f"S04 failed: {results[0].error_message}"


@pytest.mark.asyncio
async def test_s05_token_operations(scenario_ctx):
    """S05: Verify qRC20 token deployment and operations."""
    runner = ScenarioRunner(scenario_ctx)
    runner.register(S05Tokens)
    results = await runner.run_all()
    assert results[0].passed, f"S05 failed: {results[0].error_message}"


@pytest.mark.asyncio
async def test_s06_pool_operations(scenario_ctx):
    """S06: Verify AMM pool creation, liquidity, and swaps."""
    runner = ScenarioRunner(scenario_ctx)
    runner.register(S06Pools)
    results = await runner.run_all()
    assert results[0].passed, f"S06 failed: {results[0].error_message}"


@pytest.mark.asyncio
async def test_s07_validator_lifecycle(scenario_ctx):
    """S07: Verify validator registration and epoch processing."""
    runner = ScenarioRunner(scenario_ctx)
    runner.register(S07Validators)
    results = await runner.run_all()
    assert results[0].passed, f"S07 failed: {results[0].error_message}"


@pytest.mark.asyncio
async def test_s08_governance(scenario_ctx):
    """S08: Verify governance proposal lifecycle."""
    runner = ScenarioRunner(scenario_ctx)
    runner.register(S08Governance)
    results = await runner.run_all()
    assert results[0].passed, f"S08 failed: {results[0].error_message}"


@pytest.mark.asyncio
async def test_s09_bridge_operations(scenario_ctx):
    """S09: Verify cross-chain bridge operations."""
    runner = ScenarioRunner(scenario_ctx)
    runner.register(S09Bridge)
    results = await runner.run_all()
    assert results[0].passed, f"S09 failed: {results[0].error_message}"


@pytest.mark.asyncio
async def test_s10_multi_node_consistency(scenario_ctx):
    """S10: Verify state consistency across all nodes."""
    runner = ScenarioRunner(scenario_ctx)
    runner.register(S10Consistency)
    results = await runner.run_all()
    assert results[0].passed, f"S10 failed: {results[0].error_message}"


@pytest.mark.asyncio
async def test_s11_stress(scenario_ctx):
    """S11: Stress test with rapid transactions."""
    runner = ScenarioRunner(scenario_ctx)
    runner.register(S11Stress)
    results = await runner.run_all()
    assert results[0].passed, f"S11 failed: {results[0].error_message}"


# ── Full Suite Test ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_full_integration_suite(scenario_ctx):
    """Run all 11 scenarios in dependency order."""
    from integration_tests.run_scenarios import ALL_SCENARIOS

    runner = ScenarioRunner(scenario_ctx)
    runner.register_all(ALL_SCENARIOS)
    results = await runner.run_all(stop_on_failure=False)

    passed = sum(1 for r in results if r.passed)
    total = len(results)
    assert passed == total, f"Integration suite: {passed}/{total} passed"
