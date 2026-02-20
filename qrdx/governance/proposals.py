"""
Governance Proposals — Whitepaper §13.1–§13.2

Defines proposal types, lifecycle states, and the Proposal dataclass
that tracks an individual governance proposal from draft to execution.
"""

import hashlib
import time
from dataclasses import dataclass, field
from decimal import Decimal
from enum import IntEnum
from typing import Any, Dict, List, Optional

from ..logger import get_logger
from ..constants import (
    GOVERNANCE_APPROVAL_THRESHOLD,
    GOVERNANCE_MIN_DISCUSSION_DAYS,
    GOVERNANCE_PROPOSAL_DEPOSIT,
    GOVERNANCE_SUPERMAJORITY_THRESHOLD,
    GOVERNANCE_VOTING_PERIOD_DAYS,
)

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════
#  EXCEPTIONS
# ══════════════════════════════════════════════════════════════════════

class GovernanceError(Exception):
    """Base governance exception."""


class InvalidProposalError(GovernanceError):
    """Raised when proposal data is invalid."""


class ProposalLifecycleError(GovernanceError):
    """Raised on illegal state transitions."""


# ══════════════════════════════════════════════════════════════════════
#  ENUMS
# ══════════════════════════════════════════════════════════════════════

class ProposalType(IntEnum):
    """Category of governance proposal (§13.1)."""
    PARAMETER_CHANGE = 1      # Fee / limit adjustments
    PROTOCOL_UPGRADE = 2      # Hard/soft fork upgrade
    TREASURY_SPEND = 3        # Allocate treasury funds
    VALIDATOR_MANAGEMENT = 4  # Validator set changes
    CONTRACT_UPGRADE = 5      # Smart-contract upgrade
    ECOSYSTEM_GRANT = 6       # Ecosystem grant / partnership
    ORACLE_CONFIG = 7         # Oracle adapter / threshold config
    EMERGENCY = 8             # Emergency action (uses guardian veto path)


class ProposalStatus(IntEnum):
    """Lifecycle stage (§13.2)."""
    DRAFT = 0           # Created but not yet submitted
    DISCUSSION = 1      # Open for community discussion
    TEMPERATURE = 2     # Informal temperature-check vote
    ACTIVE = 3          # Formal on-chain voting in progress
    PASSED = 4          # Voting concluded — met quorum & approval
    DEFEATED = 5        # Voting concluded — failed
    QUEUED = 6          # In timelock queue awaiting execution
    EXECUTED = 7        # Successfully executed on-chain
    CANCELLED = 8       # Cancelled by proposer or guardian veto
    EXPIRED = 9         # Voting period elapsed without quorum


# Valid forward transitions
_VALID_TRANSITIONS: Dict[ProposalStatus, set] = {
    ProposalStatus.DRAFT:       {ProposalStatus.DISCUSSION, ProposalStatus.CANCELLED},
    ProposalStatus.DISCUSSION:  {ProposalStatus.TEMPERATURE, ProposalStatus.CANCELLED},
    ProposalStatus.TEMPERATURE: {ProposalStatus.ACTIVE, ProposalStatus.CANCELLED},
    ProposalStatus.ACTIVE:      {ProposalStatus.PASSED, ProposalStatus.DEFEATED,
                                  ProposalStatus.EXPIRED, ProposalStatus.CANCELLED},
    ProposalStatus.PASSED:      {ProposalStatus.QUEUED, ProposalStatus.CANCELLED},
    ProposalStatus.QUEUED:      {ProposalStatus.EXECUTED, ProposalStatus.CANCELLED},
    # Terminal states — no further transitions
    ProposalStatus.DEFEATED:    set(),
    ProposalStatus.EXECUTED:    set(),
    ProposalStatus.CANCELLED:   set(),
    ProposalStatus.EXPIRED:     set(),
}


# ══════════════════════════════════════════════════════════════════════
#  PROPOSAL
# ══════════════════════════════════════════════════════════════════════

@dataclass
class Proposal:
    """
    On-chain governance proposal (§13.2).

    Fields:
        id:               Unique monotonic identifier
        title:            Short title
        description:      Detailed description / rationale
        proposal_type:    Category (ProposalType enum)
        proposer:         PQ address of submitter
        deposit:          QRDX deposited (must ≥ GOVERNANCE_PROPOSAL_DEPOSIT)
        status:           Current lifecycle stage
        parameters:       Dict of parameters to change (type-specific payload)
        created_at:       Timestamp of creation
        voting_start:     Timestamp when ACTIVE voting begins
        voting_end:       Timestamp when voting closes
        execution_eta:    Timestamp when timelock expires (earliest execution)
    """
    id: int
    title: str
    description: str
    proposal_type: ProposalType
    proposer: str
    deposit: Decimal = field(default_factory=lambda: Decimal("0"))
    status: ProposalStatus = ProposalStatus.DRAFT
    parameters: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    voting_start: Optional[float] = None
    voting_end: Optional[float] = None
    execution_eta: Optional[float] = None
    executed_at: Optional[float] = None
    cancelled_at: Optional[float] = None
    _history: List[Dict[str, Any]] = field(default_factory=list, repr=False)

    def __post_init__(self):
        if not self.title:
            raise InvalidProposalError("Proposal title cannot be empty")
        if not self.description:
            raise InvalidProposalError("Proposal description cannot be empty")
        if not self.proposer:
            raise InvalidProposalError("Proposer address is required")
        self._record_transition(ProposalStatus.DRAFT, "created")

    # ── Properties ────────────────────────────────────────────────────

    @property
    def proposal_hash(self) -> str:
        """Deterministic hash for on-chain anchoring."""
        payload = (
            str(self.id).encode()
            + self.title.encode()
            + self.proposer.encode()
            + str(self.proposal_type.value).encode()
            + str(self.created_at).encode()
        )
        return hashlib.blake2b(payload, digest_size=32).hexdigest()

    @property
    def requires_supermajority(self) -> bool:
        """Protocol upgrades need 75% approval (§13.3)."""
        return self.proposal_type == ProposalType.PROTOCOL_UPGRADE

    @property
    def approval_threshold(self) -> Decimal:
        if self.requires_supermajority:
            return GOVERNANCE_SUPERMAJORITY_THRESHOLD
        return GOVERNANCE_APPROVAL_THRESHOLD

    @property
    def is_terminal(self) -> bool:
        return self.status in (
            ProposalStatus.DEFEATED,
            ProposalStatus.EXECUTED,
            ProposalStatus.CANCELLED,
            ProposalStatus.EXPIRED,
        )

    @property
    def is_votable(self) -> bool:
        return self.status == ProposalStatus.ACTIVE

    @property
    def history(self) -> List[Dict[str, Any]]:
        return list(self._history)

    # ── State transitions ─────────────────────────────────────────────

    def _record_transition(self, new_status: ProposalStatus, reason: str):
        self._history.append({
            "from": self.status.name if self._history else "INIT",
            "to": new_status.name,
            "reason": reason,
            "timestamp": time.time(),
        })

    def transition_to(self, new_status: ProposalStatus, reason: str = ""):
        """
        Advance proposal to *new_status*.

        Raises ProposalLifecycleError on invalid transitions.
        """
        allowed = _VALID_TRANSITIONS.get(self.status, set())
        if new_status not in allowed:
            raise ProposalLifecycleError(
                f"Cannot transition from {self.status.name} → {new_status.name}. "
                f"Allowed: {[s.name for s in allowed]}"
            )
        old = self.status
        self._record_transition(new_status, reason)
        self.status = new_status
        logger.info(
            f"Proposal #{self.id} ({self.title}): "
            f"{old.name} → {new_status.name} | {reason}"
        )

    def submit_for_discussion(self):
        """Move DRAFT → DISCUSSION."""
        self.transition_to(ProposalStatus.DISCUSSION, "Submitted for discussion")

    def start_temperature_check(self):
        """Move DISCUSSION → TEMPERATURE."""
        self.transition_to(ProposalStatus.TEMPERATURE, "Temperature check started")

    def activate_voting(self, voting_period_seconds: Optional[float] = None):
        """Move TEMPERATURE → ACTIVE (start formal voting)."""
        if self.deposit < GOVERNANCE_PROPOSAL_DEPOSIT:
            raise GovernanceError(
                f"Deposit {self.deposit} < required {GOVERNANCE_PROPOSAL_DEPOSIT}"
            )
        now = time.time()
        period = voting_period_seconds or (GOVERNANCE_VOTING_PERIOD_DAYS * 86400)
        self.voting_start = now
        self.voting_end = now + period
        self.transition_to(ProposalStatus.ACTIVE, "Voting activated")

    def mark_passed(self):
        """ACTIVE → PASSED after vote tally."""
        self.transition_to(ProposalStatus.PASSED, "Quorum and approval met")

    def mark_defeated(self, reason: str = "Vote did not pass"):
        """ACTIVE → DEFEATED."""
        self.transition_to(ProposalStatus.DEFEATED, reason)

    def mark_expired(self):
        """ACTIVE → EXPIRED (quorum not reached in time)."""
        self.transition_to(ProposalStatus.EXPIRED, "Voting period expired without quorum")

    def queue_for_execution(self, timelock_eta: float):
        """PASSED → QUEUED with timelock."""
        self.execution_eta = timelock_eta
        self.transition_to(ProposalStatus.QUEUED, f"Queued with ETA {timelock_eta}")

    def mark_executed(self):
        """QUEUED → EXECUTED."""
        self.executed_at = time.time()
        self.transition_to(ProposalStatus.EXECUTED, "Executed")

    def cancel(self, reason: str = "Cancelled"):
        """Move to CANCELLED from any non-terminal state."""
        if self.is_terminal:
            raise ProposalLifecycleError(
                f"Cannot cancel terminal proposal (status={self.status.name})"
            )
        self.cancelled_at = time.time()
        self.transition_to(ProposalStatus.CANCELLED, reason)

    # ── Serialization ─────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "proposalType": self.proposal_type.name,
            "proposer": self.proposer,
            "deposit": str(self.deposit),
            "status": self.status.name,
            "parameters": self.parameters,
            "proposalHash": self.proposal_hash,
            "requiresSupermajority": self.requires_supermajority,
            "approvalThreshold": str(self.approval_threshold),
            "createdAt": self.created_at,
            "votingStart": self.voting_start,
            "votingEnd": self.voting_end,
            "executionETA": self.execution_eta,
            "executedAt": self.executed_at,
            "cancelledAt": self.cancelled_at,
            "historyLength": len(self._history),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Proposal":
        return cls(
            id=data["id"],
            title=data["title"],
            description=data["description"],
            proposal_type=ProposalType[data["proposalType"]],
            proposer=data["proposer"],
            deposit=Decimal(data.get("deposit", "0")),
            parameters=data.get("parameters", {}),
        )

    def __repr__(self) -> str:
        return (
            f"<Proposal #{self.id} '{self.title}' "
            f"type={self.proposal_type.name} status={self.status.name}>"
        )
