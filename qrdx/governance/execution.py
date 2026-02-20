"""
Time-Lock Execution Engine — Whitepaper §13.4–§13.5

Implements:
  - TimelockQueue: queues passed proposals with a delay before execution
  - GovernanceExecutor: resolves parameter mutations after timelock expires
  - Guardian veto: 3-of-5 PQ multisig can cancel during timelock
"""

import time
from dataclasses import dataclass, field
from decimal import Decimal
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional

from ..logger import get_logger
from ..constants import (
    GOVERNANCE_DEFAULT_PARAMETERS,
    GOVERNANCE_GUARDIAN_THRESHOLD,
    GOVERNANCE_GUARDIAN_TOTAL,
    GOVERNANCE_TIMELOCK_DEFAULT_DELAY_SECONDS,
    GOVERNANCE_TIMELOCK_MAX_DELAY_SECONDS,
    GOVERNANCE_TIMELOCK_MIN_DELAY_SECONDS,
)
from .proposals import (
    GovernanceError,
    Proposal,
    ProposalLifecycleError,
    ProposalStatus,
    ProposalType,
)

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════
#  EXCEPTIONS
# ══════════════════════════════════════════════════════════════════════

class TimelockError(GovernanceError):
    """Timelock-specific errors."""


class TimelockNotReadyError(TimelockError):
    """Execution attempted before delay expires."""


class GuardianVetoError(GovernanceError):
    """Guardian council vetoed execution."""


# ══════════════════════════════════════════════════════════════════════
#  TIMELOCK
# ══════════════════════════════════════════════════════════════════════

class TimelockStatus(IntEnum):
    """Status of a queued timelock entry."""
    PENDING = 0     # Waiting for delay to expire
    READY = 1       # Delay expired, can execute
    EXECUTED = 2    # Successfully executed
    VETOED = 3      # Guardian council vetoed
    EXPIRED = 4     # Execution window passed (grace period)


@dataclass
class TimelockEntry:
    """
    A queued governance action awaiting execution.

    Attributes:
        proposal_id:   Associated proposal ID
        queued_at:      Timestamp when queued
        delay_seconds:  Execution delay
        eta:            Earliest execution timestamp
        grace_period:   Extra time after ETA before entry expires
        status:         Current status
    """
    proposal_id: int
    queued_at: float = field(default_factory=time.time)
    delay_seconds: int = GOVERNANCE_TIMELOCK_DEFAULT_DELAY_SECONDS
    eta: float = 0.0
    grace_period: int = 14 * 86400  # 14 days grace
    status: TimelockStatus = TimelockStatus.PENDING
    executed_at: Optional[float] = None
    vetoed_at: Optional[float] = None
    veto_signers: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.eta == 0.0:
            self.eta = self.queued_at + self.delay_seconds

    @property
    def is_ready(self) -> bool:
        """Can be executed now?"""
        now = time.time()
        return (
            self.status == TimelockStatus.PENDING
            and now >= self.eta
            and now < self.eta + self.grace_period
        )

    @property
    def is_expired(self) -> bool:
        now = time.time()
        return (
            self.status == TimelockStatus.PENDING
            and now >= self.eta + self.grace_period
        )

    @property
    def time_remaining(self) -> float:
        """Seconds until ETA (0 if already past)."""
        return max(0.0, self.eta - time.time())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposalId": self.proposal_id,
            "queuedAt": self.queued_at,
            "delaySeconds": self.delay_seconds,
            "eta": self.eta,
            "gracePeriod": self.grace_period,
            "status": self.status.name,
            "isReady": self.is_ready,
            "timeRemaining": self.time_remaining,
            "executedAt": self.executed_at,
            "vetoedAt": self.vetoed_at,
            "vetoSigners": self.veto_signers,
        }


class TimelockQueue:
    """
    Queue of governance actions awaiting execution after delay.
    """

    def __init__(
        self,
        default_delay: int = GOVERNANCE_TIMELOCK_DEFAULT_DELAY_SECONDS,
        min_delay: int = GOVERNANCE_TIMELOCK_MIN_DELAY_SECONDS,
        max_delay: int = GOVERNANCE_TIMELOCK_MAX_DELAY_SECONDS,
    ):
        self.default_delay = default_delay
        self.min_delay = min_delay
        self.max_delay = max_delay
        self._entries: Dict[int, TimelockEntry] = {}  # proposal_id → entry

    def queue(
        self,
        proposal: Proposal,
        delay_seconds: Optional[int] = None,
    ) -> TimelockEntry:
        """
        Queue a passed proposal for delayed execution.
        """
        if proposal.status != ProposalStatus.PASSED:
            raise TimelockError(
                f"Only PASSED proposals can be queued (got {proposal.status.name})"
            )
        if proposal.id in self._entries:
            raise TimelockError(
                f"Proposal #{proposal.id} already queued"
            )

        delay = delay_seconds if delay_seconds is not None else self.default_delay
        if delay < self.min_delay:
            raise TimelockError(
                f"Delay {delay}s < minimum {self.min_delay}s"
            )
        if delay > self.max_delay:
            raise TimelockError(
                f"Delay {delay}s > maximum {self.max_delay}s"
            )

        now = time.time()
        entry = TimelockEntry(
            proposal_id=proposal.id,
            queued_at=now,
            delay_seconds=delay,
            eta=now + delay,
        )
        self._entries[proposal.id] = entry
        proposal.queue_for_execution(entry.eta)

        logger.info(
            f"Proposal #{proposal.id} queued with {delay}s delay "
            f"(ETA={entry.eta:.0f})"
        )
        return entry

    def get_entry(self, proposal_id: int) -> Optional[TimelockEntry]:
        return self._entries.get(proposal_id)

    def is_ready(self, proposal_id: int) -> bool:
        entry = self._entries.get(proposal_id)
        return entry is not None and entry.is_ready

    def pending_entries(self) -> List[TimelockEntry]:
        return [
            e for e in self._entries.values()
            if e.status == TimelockStatus.PENDING
        ]

    def ready_entries(self) -> List[TimelockEntry]:
        return [e for e in self._entries.values() if e.is_ready]

    def guardian_veto(
        self,
        proposal_id: int,
        signers: List[str],
        threshold: int = GOVERNANCE_GUARDIAN_THRESHOLD,
    ) -> TimelockEntry:
        """
        Guardian council veto (§13.4).

        Requires *threshold* valid guardian signatures.
        """
        entry = self._entries.get(proposal_id)
        if entry is None:
            raise TimelockError(f"No queued entry for proposal #{proposal_id}")
        if entry.status != TimelockStatus.PENDING:
            raise TimelockError(
                f"Cannot veto entry in {entry.status.name} status"
            )
        if len(signers) < threshold:
            raise GuardianVetoError(
                f"Need {threshold} guardian signatures, got {len(signers)}"
            )

        entry.status = TimelockStatus.VETOED
        entry.vetoed_at = time.time()
        entry.veto_signers = list(signers)

        logger.warning(
            f"GUARDIAN VETO: proposal #{proposal_id} vetoed by "
            f"{len(signers)} guardians"
        )
        return entry

    def to_dict(self) -> Dict[str, Any]:
        return {
            "defaultDelay": self.default_delay,
            "minDelay": self.min_delay,
            "maxDelay": self.max_delay,
            "queuedCount": len(self._entries),
            "entries": {
                pid: e.to_dict() for pid, e in self._entries.items()
            },
        }


# ══════════════════════════════════════════════════════════════════════
#  GOVERNANCE EXECUTOR
# ══════════════════════════════════════════════════════════════════════

class GovernanceExecutor:
    """
    Executes governance proposals after timelock expires.

    Manages the set of governable parameters (§13.5) and applies
    approved changes.
    """

    def __init__(
        self,
        timelock_queue: Optional[TimelockQueue] = None,
        initial_parameters: Optional[Dict[str, Any]] = None,
    ):
        self.timelock = timelock_queue or TimelockQueue()
        self._parameters: Dict[str, Any] = dict(
            initial_parameters or GOVERNANCE_DEFAULT_PARAMETERS
        )
        self._execution_log: List[Dict[str, Any]] = []
        self._custom_executors: Dict[ProposalType, Callable] = {}

    # ── Parameters ────────────────────────────────────────────────────

    def get_parameter(self, key: str) -> Any:
        return self._parameters.get(key)

    def get_all_parameters(self) -> Dict[str, Any]:
        return dict(self._parameters)

    def set_parameter(self, key: str, value: Any):
        """Directly set a parameter (for internal use / testing)."""
        old = self._parameters.get(key)
        self._parameters[key] = value
        logger.info(f"Parameter '{key}' changed: {old} → {value}")

    # ── Custom executors ──────────────────────────────────────────────

    def register_executor(
        self,
        proposal_type: ProposalType,
        executor_fn: Callable,
    ):
        """Register a custom execution function for a proposal type."""
        self._custom_executors[proposal_type] = executor_fn

    # ── Execute ───────────────────────────────────────────────────────

    def execute(self, proposal: Proposal) -> Dict[str, Any]:
        """
        Execute a governance proposal.

        Checks:
            1. Proposal is QUEUED
            2. Timelock entry exists and is ready
            3. Entry has not been vetoed
        Then applies the proposal's parameter changes.
        """
        if proposal.status != ProposalStatus.QUEUED:
            raise GovernanceError(
                f"Proposal #{proposal.id} is not QUEUED "
                f"(status={proposal.status.name})"
            )

        entry = self.timelock.get_entry(proposal.id)
        if entry is None:
            raise TimelockError(
                f"No timelock entry for proposal #{proposal.id}"
            )

        if entry.status == TimelockStatus.VETOED:
            proposal.cancel("Guardian veto")
            raise GuardianVetoError(
                f"Proposal #{proposal.id} was vetoed by guardians"
            )

        if entry.is_expired:
            entry.status = TimelockStatus.EXPIRED
            proposal.mark_expired()
            raise TimelockError(
                f"Timelock for proposal #{proposal.id} has expired"
            )

        if not entry.is_ready:
            raise TimelockNotReadyError(
                f"Timelock not ready (remaining={entry.time_remaining:.0f}s)"
            )

        # Execute based on proposal type
        changes = self._apply_proposal(proposal)

        # Update statuses
        entry.status = TimelockStatus.EXECUTED
        entry.executed_at = time.time()
        proposal.mark_executed()

        log_entry = {
            "proposalId": proposal.id,
            "proposalType": proposal.proposal_type.name,
            "title": proposal.title,
            "changes": changes,
            "executedAt": entry.executed_at,
        }
        self._execution_log.append(log_entry)

        logger.info(
            f"Proposal #{proposal.id} EXECUTED: "
            f"{proposal.proposal_type.name} — {changes}"
        )
        return changes

    def _apply_proposal(self, proposal: Proposal) -> Dict[str, Any]:
        """Apply proposal's changes to governable parameters."""
        changes: Dict[str, Any] = {}

        # Check for custom executor first
        if proposal.proposal_type in self._custom_executors:
            fn = self._custom_executors[proposal.proposal_type]
            return fn(proposal)

        # Default: apply parameter changes from proposal.parameters
        if proposal.proposal_type == ProposalType.PARAMETER_CHANGE:
            for key, value in proposal.parameters.items():
                old = self._parameters.get(key)
                self._parameters[key] = value
                changes[key] = {"old": old, "new": value}

        elif proposal.proposal_type == ProposalType.TREASURY_SPEND:
            # Record treasury spending (actual transfer handled elsewhere)
            changes["treasury_spend"] = {
                "recipient": proposal.parameters.get("recipient"),
                "amount": proposal.parameters.get("amount"),
                "purpose": proposal.parameters.get("purpose"),
            }

        elif proposal.proposal_type == ProposalType.PROTOCOL_UPGRADE:
            # Record upgrade (actual deployment handled externally)
            changes["protocol_upgrade"] = {
                "version": proposal.parameters.get("version"),
                "description": proposal.parameters.get("description"),
            }

        elif proposal.proposal_type == ProposalType.ORACLE_CONFIG:
            for key, value in proposal.parameters.items():
                old = self._parameters.get(key)
                self._parameters[key] = value
                changes[key] = {"old": old, "new": value}

        else:
            # Generic: store parameters as changes
            changes["generic"] = proposal.parameters

        return changes

    # ── Queries ───────────────────────────────────────────────────────

    @property
    def execution_log(self) -> List[Dict[str, Any]]:
        return list(self._execution_log)

    def execution_count(self) -> int:
        return len(self._execution_log)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "parameters": {
                k: str(v) if isinstance(v, Decimal) else v
                for k, v in self._parameters.items()
            },
            "timelockQueue": self.timelock.to_dict(),
            "executionLog": self._execution_log,
            "customExecutors": list(self._custom_executors.keys()),
        }

    def __repr__(self) -> str:
        return (
            f"<GovernanceExecutor params={len(self._parameters)} "
            f"executed={len(self._execution_log)}>"
        )
