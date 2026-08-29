"""
QRDX Integration Testnet — Main Entry Point

Orchestrates the full testnet lifecycle:
  1. Setup (wallets, genesis, databases, configs)
  2. Start all nodes
  3. Wait for network mesh
  4. Run all integration scenarios
  5. Generate report
  6. Shutdown

Usage:
    python -m integration_tests.run_scenarios
    python -m integration_tests.run_scenarios --force    # Regenerate everything
    python -m integration_tests.run_scenarios --keep     # Keep nodes running after
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from integration_tests.config import DATABASES_DIR, build_node_specs
from integration_tests.orchestrator import TestnetOrchestrator
from integration_tests.monitor import TestnetMonitor
from integration_tests.scenarios.base import Scenario, ScenarioContext, ScenarioRunner

# Import all scenarios
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
from integration_tests.scenarios.s12_exchange_consensus import S12ExchangeConsensus
from integration_tests.scenarios.s13_perp_collateral import S13PerpCollateral
from integration_tests.scenarios.s14_token_consensus import S14TokenConsensus
from integration_tests.scenarios.s15_spot_settlement import S15SpotSettlement
from integration_tests.scenarios.s16_validator_membership import S16ValidatorMembership
from integration_tests.scenarios.s17_clob_settlement import S17ClobSettlement
from integration_tests.scenarios.s18_clob_match import S18ClobMatch


ALL_SCENARIOS = [
    S01GenesisBootstrap,
    S02PeerMesh,
    S03BlockProduction,
    S04Transactions,
    S05Tokens,
    S06Pools,
    S07Validators,
    S08Governance,
    S09Bridge,
    S10Consistency,
    S11Stress,
    S12ExchangeConsensus,
    S13PerpCollateral,
    S14TokenConsensus,
    S15SpotSettlement,
    S16ValidatorMembership,
    S17ClobSettlement,
    S18ClobMatch,
]


async def main(args: argparse.Namespace) -> int:
    """Main async entry point."""
    # Configure logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logger = logging.getLogger("testnet")

    orch = TestnetOrchestrator(force_regenerate=args.force)
    monitor = None
    monitor_task = None
    exit_code = 0

    try:
        # ── Phase 1: Setup ──────────────────────────────────────
        logger.info("Phase 1: Setup")
        await orch.setup()

        # ── Phase 2: Start Nodes ────────────────────────────────
        logger.info("Phase 2: Starting nodes")
        await orch.start_all_nodes()

        # ── Phase 3: Wait for Network ──────────────────────────
        logger.info("Phase 3: Waiting for network")
        ready = await orch.wait_network_ready()
        if not ready:
            logger.error("Network failed to reach ready state")
            return 1

        # Start health monitor
        node_urls = [p.url for p in orch.node_processes]
        node_names = [s.name for s in orch.node_specs]
        monitor = TestnetMonitor(node_urls, node_names)
        monitor_task = asyncio.create_task(monitor.run(interval=5.0))

        # ── Phase 4: Run Scenarios ──────────────────────────────
        logger.info("Phase 4: Running integration scenarios")

        # Build context
        node_specs = build_node_specs(orch.num_nodes, orch.num_validators)
        ctx = ScenarioContext(
            orchestrator=orch,
            wallets=orch.wallets,
            node_urls=node_urls,
            db_paths=[s.db_path for s in node_specs],
        )

        runner = ScenarioRunner(ctx)
        runner.register_all(ALL_SCENARIOS)
        results = await runner.run_all(stop_on_failure=args.stop_on_failure)

        # ── Phase 5: Report ─────────────────────────────────────
        logger.info("Phase 5: Generating report")

        if monitor:
            monitor.stop()
            logger.info("\n" + monitor.get_summary_report())

        if runner.all_passed:
            logger.info("\n✓ ALL SCENARIOS PASSED")
            exit_code = 0
        else:
            failed = [r.name for r in results if not r.passed]
            logger.error("\n✗ FAILED SCENARIOS: %s", failed)
            exit_code = 1

        # ── Phase 4.5: Soak-invariant monitor (opt-in) ──────────────
        if args.soak and args.soak > 0:
            logger.info("Phase 4.5: Soak-invariant monitor (%.0fs, fault_inject=%s)",
                        args.soak, args.fault_inject)
            from integration_tests.soak import run_soak_phase
            soak_report = await run_soak_phase(
                node_urls, duration=args.soak, node_processes=orch.node_processes,
                fault_inject=args.fault_inject)
            logger.info("\n" + soak_report.summary())
            if not soak_report.passed:
                logger.error("\n✗ SOAK FAILED")
                exit_code = 1

        # Keep running if requested
        if args.keep:
            logger.info("\nNodes still running. Press Ctrl+C to stop.")
            try:
                while True:
                    await asyncio.sleep(10)
                    await orch.print_status()
            except KeyboardInterrupt:
                pass

    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")
        exit_code = 130
    except Exception as e:
        logger.error("Fatal error: %s", e, exc_info=True)
        exit_code = 2
    finally:
        # Stop monitor
        if monitor:
            monitor.stop()
        if monitor_task:
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass

        # Stop nodes
        await orch.stop_all_nodes()

    return exit_code


def cli():
    parser = argparse.ArgumentParser(
        description="QRDX Integration Testnet Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m integration_tests.run_scenarios              # Run all scenarios
  python -m integration_tests.run_scenarios --force      # Regenerate wallets/genesis
  python -m integration_tests.run_scenarios --keep       # Keep nodes running after
  python -m integration_tests.run_scenarios -v           # Verbose logging
  python -m integration_tests.run_scenarios --stop       # Stop on first failure
        """,
    )
    parser.add_argument("--force", action="store_true",
                        help="Force regenerate wallets, genesis, databases")
    parser.add_argument("--keep", action="store_true",
                        help="Keep nodes running after scenarios complete")
    parser.add_argument("--stop-on-failure", "--stop", action="store_true",
                        help="Stop execution on first failed scenario")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--soak", type=float, default=0.0, metavar="SECONDS",
                        help="After scenarios, run a soak-invariant monitor for SECONDS (health/"
                             "liveness/finality/convergence/safety via /metrics). The ≥30-day soak "
                             "gate, parameterized. Requires QRDX_ENABLE_STREAMING for /metrics.")
    parser.add_argument("--fault-inject", action="store_true",
                        help="During --soak, kill + restart a backup node and verify recovery")
    return parser.parse_args()


if __name__ == "__main__":
    args = cli()
    sys.exit(asyncio.run(main(args)))
