"""
Base Scenario Framework

Provides the abstract base class for all testnet scenarios,
plus the ScenarioRunner that executes them in order with
timing, logging, and result reporting.
"""

import asyncio
import logging
import time
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Type

logger = logging.getLogger(__name__)


class ScenarioStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class ScenarioResult:
    """Result of a single scenario run."""
    name: str
    status: ScenarioStatus
    duration: float = 0.0
    checks_passed: int = 0
    checks_total: int = 0
    error_message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.status == ScenarioStatus.PASSED


@dataclass
class ScenarioContext:
    """Shared context passed to all scenarios."""
    orchestrator: Any  # TestnetOrchestrator
    wallets: Dict[str, dict] = field(default_factory=dict)
    node_urls: List[str] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)  # Shared state between scenarios
    db_paths: List[str] = field(default_factory=list)


class Scenario(ABC):
    """
    Abstract base class for testnet integration scenarios.

    Each scenario should:
      1. Have a unique name and description
      2. Implement setup(), execute(), and verify()
      3. Use self.check() for assertions with nice reporting
      4. Use self.ctx for accessing shared testnet resources
    """

    name: str = "unnamed"
    description: str = ""
    depends_on: List[str] = []  # Scenarios that must pass first

    def __init__(self, ctx: ScenarioContext):
        self.ctx = ctx
        self._checks_passed = 0
        self._checks_total = 0
        self._log = logging.getLogger(f"scenario.{self.name}")

    def check(self, condition: bool, message: str, **details) -> bool:
        """
        Assert a condition with descriptive messaging.

        Returns True if condition passed, False otherwise.
        Does NOT raise — scenarios continue after failed checks.
        """
        self._checks_total += 1
        if condition:
            self._checks_passed += 1
            self._log.info("  ✓ %s", message)
        else:
            detail_str = f" ({details})" if details else ""
            self._log.error("  ✗ %s%s", message, detail_str)
        return condition

    def check_equal(self, actual, expected, message: str) -> bool:
        """Check that actual == expected."""
        return self.check(
            actual == expected,
            f"{message} (got {actual}, expected {expected})",
            actual=actual,
            expected=expected,
        )

    def check_gte(self, actual, minimum, message: str) -> bool:
        """Check that actual >= minimum."""
        return self.check(
            actual >= minimum,
            f"{message} (got {actual}, min {minimum})",
            actual=actual,
            minimum=minimum,
        )

    def check_not_none(self, value, message: str) -> bool:
        """Check that value is not None."""
        return self.check(value is not None, message, value=value)

    async def setup(self) -> None:
        """Optional setup before execution."""
        pass

    @abstractmethod
    async def execute(self) -> None:
        """Main scenario logic. Use self.check() for assertions."""
        ...

    async def teardown(self) -> None:
        """Optional cleanup after execution."""
        pass


class ScenarioRunner:
    """
    Executes scenarios in order, tracking results and dependencies.
    """

    def __init__(self, ctx: ScenarioContext):
        self.ctx = ctx
        self._scenarios: List[Type[Scenario]] = []
        self._results: List[ScenarioResult] = []

    def register(self, scenario_cls: Type[Scenario]) -> None:
        """Register a scenario class."""
        self._scenarios.append(scenario_cls)

    def register_all(self, scenario_classes: List[Type[Scenario]]) -> None:
        """Register multiple scenario classes."""
        self._scenarios.extend(scenario_classes)

    async def run_all(self, stop_on_failure: bool = False) -> List[ScenarioResult]:
        """
        Run all registered scenarios in order.

        Args:
            stop_on_failure: If True, stop after first failed scenario.
        """
        logger.info("=" * 60)
        logger.info("SCENARIO RUNNER: %d scenarios queued", len(self._scenarios))
        logger.info("=" * 60)

        self._results = []
        passed_names = set()
        total_start = time.time()

        for scenario_cls in self._scenarios:
            # Check dependencies
            deps_ok = all(dep in passed_names for dep in scenario_cls.depends_on)
            if not deps_ok:
                missing = [d for d in scenario_cls.depends_on if d not in passed_names]
                result = ScenarioResult(
                    name=scenario_cls.name,
                    status=ScenarioStatus.SKIPPED,
                    error_message=f"Skipped: unmet dependencies {missing}",
                )
                self._results.append(result)
                logger.warning("[SKIP] %s — depends on %s", scenario_cls.name, missing)
                continue

            result = await self._run_one(scenario_cls)
            self._results.append(result)

            if result.passed:
                passed_names.add(scenario_cls.name)

            if not result.passed and stop_on_failure:
                logger.error("[ABORT] Stopping after failure: %s", scenario_cls.name)
                break

        total_time = time.time() - total_start
        self._print_summary(total_time)
        return self._results

    async def _run_one(self, scenario_cls: Type[Scenario]) -> ScenarioResult:
        """Run a single scenario with full lifecycle."""
        scenario = scenario_cls(self.ctx)
        name = scenario.name

        logger.info("\n" + "-" * 60)
        logger.info("[RUN] %s: %s", name, scenario.description)
        logger.info("-" * 60)

        start = time.time()

        try:
            await scenario.setup()
            await scenario.execute()
            await scenario.teardown()

            duration = time.time() - start
            all_passed = scenario._checks_passed == scenario._checks_total and scenario._checks_total > 0

            result = ScenarioResult(
                name=name,
                status=ScenarioStatus.PASSED if all_passed else ScenarioStatus.FAILED,
                duration=duration,
                checks_passed=scenario._checks_passed,
                checks_total=scenario._checks_total,
            )

            if all_passed:
                logger.info("[PASS] %s (%.2fs, %d/%d checks)",
                            name, duration, scenario._checks_passed, scenario._checks_total)
            else:
                logger.error("[FAIL] %s (%.2fs, %d/%d checks)",
                             name, duration, scenario._checks_passed, scenario._checks_total)

        except Exception as e:
            duration = time.time() - start
            tb = traceback.format_exc()
            logger.error("[ERROR] %s: %s\n%s", name, e, tb)

            try:
                await scenario.teardown()
            except Exception:
                pass

            result = ScenarioResult(
                name=name,
                status=ScenarioStatus.ERROR,
                duration=duration,
                checks_passed=scenario._checks_passed,
                checks_total=scenario._checks_total,
                error_message=str(e),
                details={"traceback": tb},
            )

        return result

    def _print_summary(self, total_time: float) -> None:
        """Print a final summary of all scenario results."""
        print("\n" + "=" * 60)
        print("SCENARIO RESULTS")
        print("=" * 60)

        for r in self._results:
            symbol = {
                ScenarioStatus.PASSED: "✓",
                ScenarioStatus.FAILED: "✗",
                ScenarioStatus.ERROR: "💥",
                ScenarioStatus.SKIPPED: "⏭",
                ScenarioStatus.PENDING: "○",
            }.get(r.status, "?")

            checks = f"({r.checks_passed}/{r.checks_total})" if r.checks_total > 0 else ""
            err = f" — {r.error_message}" if r.error_message else ""
            print(f"  {symbol} {r.name}: {r.status.value} {checks} [{r.duration:.2f}s]{err}")

        passed = sum(1 for r in self._results if r.status == ScenarioStatus.PASSED)
        failed = sum(1 for r in self._results if r.status == ScenarioStatus.FAILED)
        errors = sum(1 for r in self._results if r.status == ScenarioStatus.ERROR)
        skipped = sum(1 for r in self._results if r.status == ScenarioStatus.SKIPPED)

        print()
        print(f"Total: {len(self._results)} scenarios in {total_time:.1f}s")
        print(f"  Passed:  {passed}")
        print(f"  Failed:  {failed}")
        print(f"  Errors:  {errors}")
        print(f"  Skipped: {skipped}")

        success_rate = (passed / len(self._results) * 100) if self._results else 0
        print(f"  Success rate: {success_rate:.0f}%")
        print("=" * 60)

    @property
    def results(self) -> List[ScenarioResult]:
        return self._results.copy()

    @property
    def all_passed(self) -> bool:
        return all(r.passed for r in self._results)
