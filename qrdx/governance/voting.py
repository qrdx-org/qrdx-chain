"""
Stake-Weighted Voting Engine — Whitepaper §13.3

Implements:
  - 1 QRDX = 1 vote
  - Vote types: For / Against / Abstain (abstain counts toward quorum)
  - Quorum check: ≥10% of circulating supply participation
  - Approval thresholds: 60% standard / 75% supermajority
  - Delegation support
  - Vote locking (optional weight multiplier)
"""

import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Dict, List, Optional, Set

from ..logger import get_logger
from ..constants import (
    GOVERNANCE_APPROVAL_THRESHOLD,
    GOVERNANCE_QUORUM_THRESHOLD,
    GOVERNANCE_SUPERMAJORITY_THRESHOLD,
    GOVERNANCE_VOTE_ABSTAIN,
    GOVERNANCE_VOTE_AGAINST,
    GOVERNANCE_VOTE_FOR,
)
from .proposals import (
    GovernanceError,
    Proposal,
    ProposalStatus,
)

logger = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════
#  EXCEPTIONS
# ══════════════════════════════════════════════════════════════════════

class VotingError(GovernanceError):
    """Base voting error."""


class InsufficientVotingPowerError(VotingError):
    """Voter has no stake."""


class QuorumNotReachedError(VotingError):
    """Quorum requirement not met."""


class AlreadyVotedError(VotingError):
    """Voter already cast a vote on this proposal."""


class VotingClosedError(VotingError):
    """Voting period not active."""


# ══════════════════════════════════════════════════════════════════════
#  VOTE DATA
# ══════════════════════════════════════════════════════════════════════

class Vote:
    """Vote type constants matching constants.py."""
    FOR = GOVERNANCE_VOTE_FOR
    AGAINST = GOVERNANCE_VOTE_AGAINST
    ABSTAIN = GOVERNANCE_VOTE_ABSTAIN

    _NAMES = {
        GOVERNANCE_VOTE_FOR: "FOR",
        GOVERNANCE_VOTE_AGAINST: "AGAINST",
        GOVERNANCE_VOTE_ABSTAIN: "ABSTAIN",
    }

    @classmethod
    def name(cls, vote_type: int) -> str:
        return cls._NAMES.get(vote_type, "UNKNOWN")

    @classmethod
    def is_valid(cls, vote_type: int) -> bool:
        return vote_type in cls._NAMES


@dataclass(frozen=True)
class VoteRecord:
    """An individual vote cast by a voter."""
    proposal_id: int
    voter: str
    vote_type: int          # Vote.FOR / AGAINST / ABSTAIN
    voting_power: Decimal   # Stake-derived weight
    delegated_from: Optional[str] = None  # If voting on behalf of delegator
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposalId": self.proposal_id,
            "voter": self.voter,
            "voteType": Vote.name(self.vote_type),
            "votingPower": str(self.voting_power),
            "delegatedFrom": self.delegated_from,
            "timestamp": self.timestamp,
        }


@dataclass
class VotingResult:
    """Aggregated tally for a proposal."""
    proposal_id: int
    votes_for: Decimal = field(default_factory=lambda: Decimal("0"))
    votes_against: Decimal = field(default_factory=lambda: Decimal("0"))
    votes_abstain: Decimal = field(default_factory=lambda: Decimal("0"))
    total_eligible_supply: Decimal = field(default_factory=lambda: Decimal("0"))
    quorum_threshold: Decimal = GOVERNANCE_QUORUM_THRESHOLD
    approval_threshold: Decimal = GOVERNANCE_APPROVAL_THRESHOLD
    finalized: bool = False
    finalized_at: Optional[float] = None

    @property
    def total_votes(self) -> Decimal:
        """Total stake that participated (including abstain)."""
        return self.votes_for + self.votes_against + self.votes_abstain

    @property
    def quorum_reached(self) -> bool:
        """Has ≥10% of eligible supply voted?"""
        if self.total_eligible_supply <= 0:
            return False
        participation = self.total_votes / self.total_eligible_supply
        return participation >= self.quorum_threshold

    @property
    def approval_rate(self) -> Decimal:
        """Percentage of non-abstain votes that are FOR."""
        decisive = self.votes_for + self.votes_against
        if decisive <= 0:
            return Decimal("0")
        return self.votes_for / decisive

    @property
    def is_approved(self) -> bool:
        """Quorum met AND approval rate ≥ threshold."""
        return self.quorum_reached and self.approval_rate >= self.approval_threshold

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposalId": self.proposal_id,
            "votesFor": str(self.votes_for),
            "votesAgainst": str(self.votes_against),
            "votesAbstain": str(self.votes_abstain),
            "totalVotes": str(self.total_votes),
            "totalEligibleSupply": str(self.total_eligible_supply),
            "quorumReached": self.quorum_reached,
            "approvalRate": str(self.approval_rate),
            "isApproved": self.is_approved,
            "finalized": self.finalized,
            "finalizedAt": self.finalized_at,
        }


# ══════════════════════════════════════════════════════════════════════
#  DELEGATION
# ══════════════════════════════════════════════════════════════════════

@dataclass
class Delegation:
    """Delegation of voting power from delegator → delegate."""
    delegator: str
    delegate: str
    amount: Decimal
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "delegator": self.delegator,
            "delegate": self.delegate,
            "amount": str(self.amount),
            "createdAt": self.created_at,
        }


# ══════════════════════════════════════════════════════════════════════
#  VOTING ENGINE
# ══════════════════════════════════════════════════════════════════════

class VotingEngine:
    """
    Stake-weighted voting engine (§13.3).

    Responsibilities:
        - Accept votes with stake-weighted power
        - Track per-proposal tallies
        - Enforce quorum and approval thresholds
        - Support delegation
        - Finalize voting when period ends
    """

    def __init__(self, get_stake_fn=None, get_total_supply_fn=None):
        """
        Args:
            get_stake_fn:        Callable(address) → Decimal  (voter's stake)
            get_total_supply_fn: Callable() → Decimal          (circulating supply)
        """
        self._get_stake = get_stake_fn
        self._get_total_supply = get_total_supply_fn

        # Per-proposal state
        self._results: Dict[int, VotingResult] = {}
        self._votes: Dict[int, List[VoteRecord]] = {}
        self._voters: Dict[int, Set[str]] = {}  # proposal_id → {voter_addresses}

        # Global delegation state
        self._delegations: Dict[str, Delegation] = {}  # delegator → Delegation

    # ── Delegation ────────────────────────────────────────────────────

    def delegate(self, delegator: str, delegate: str, amount: Decimal):
        """Register a delegation of voting power."""
        if amount <= 0:
            raise VotingError("Delegation amount must be positive")
        if delegator == delegate:
            raise VotingError("Cannot delegate to self")
        self._delegations[delegator] = Delegation(
            delegator=delegator, delegate=delegate, amount=amount
        )
        logger.info(f"Delegation: {delegator} → {delegate} ({amount} QRDX)")

    def undelegate(self, delegator: str):
        """Remove delegation."""
        self._delegations.pop(delegator, None)

    def get_delegated_power(self, delegate: str) -> Decimal:
        """Total power delegated TO this delegate."""
        return sum(
            d.amount for d in self._delegations.values()
            if d.delegate == delegate
        )

    # ── Voting power resolution ───────────────────────────────────────

    def get_voting_power(self, voter: str, own_stake: Optional[Decimal] = None) -> Decimal:
        """
        Resolve total voting power: own stake + delegated power.
        """
        if own_stake is not None:
            base = own_stake
        elif self._get_stake:
            base = self._get_stake(voter)
        else:
            base = Decimal("0")

        delegated = self.get_delegated_power(voter)
        return base + delegated

    def get_total_eligible(self) -> Decimal:
        """Get total eligible supply for quorum calculation."""
        if self._get_total_supply:
            return self._get_total_supply()
        return Decimal("0")

    # ── Cast vote ─────────────────────────────────────────────────────

    def cast_vote(
        self,
        proposal: Proposal,
        voter: str,
        vote_type: int,
        voting_power: Optional[Decimal] = None,
    ) -> VoteRecord:
        """
        Cast a stake-weighted vote on a proposal.

        Args:
            proposal: The proposal being voted on
            voter: Voter's PQ address
            vote_type: Vote.FOR, Vote.AGAINST, or Vote.ABSTAIN
            voting_power: Override voting power (if None, auto-resolves)
        """
        # Validate vote type
        if not Vote.is_valid(vote_type):
            raise VotingError(f"Invalid vote type: {vote_type}")

        # Proposal must be in ACTIVE status
        if not proposal.is_votable:
            raise VotingClosedError(
                f"Proposal #{proposal.id} is not votable "
                f"(status={proposal.status.name})"
            )

        # Check voting period
        now = time.time()
        if proposal.voting_end and now > proposal.voting_end:
            raise VotingClosedError(
                f"Voting period for proposal #{proposal.id} has ended"
            )

        # Prevent double voting
        pid = proposal.id
        if pid not in self._voters:
            self._voters[pid] = set()
        if voter in self._voters[pid]:
            raise AlreadyVotedError(
                f"{voter} has already voted on proposal #{pid}"
            )

        # Resolve voting power
        power = voting_power if voting_power is not None else self.get_voting_power(voter)
        if power <= 0:
            raise InsufficientVotingPowerError(
                f"{voter} has no voting power (stake=0, no delegation)"
            )

        # Record vote
        record = VoteRecord(
            proposal_id=pid,
            voter=voter,
            vote_type=vote_type,
            voting_power=power,
        )

        if pid not in self._votes:
            self._votes[pid] = []
        self._votes[pid].append(record)
        self._voters[pid].add(voter)

        # Update tally
        result = self._get_or_create_result(proposal)
        if vote_type == Vote.FOR:
            result.votes_for += power
        elif vote_type == Vote.AGAINST:
            result.votes_against += power
        else:
            result.votes_abstain += power

        logger.info(
            f"Vote: {voter} → {Vote.name(vote_type)} on proposal #{pid} "
            f"(power={power})"
        )
        return record

    # ── Result management ─────────────────────────────────────────────

    def _get_or_create_result(self, proposal: Proposal) -> VotingResult:
        pid = proposal.id
        if pid not in self._results:
            supply = self.get_total_eligible()
            threshold = (
                GOVERNANCE_SUPERMAJORITY_THRESHOLD
                if proposal.requires_supermajority
                else GOVERNANCE_APPROVAL_THRESHOLD
            )
            self._results[pid] = VotingResult(
                proposal_id=pid,
                total_eligible_supply=supply,
                approval_threshold=threshold,
            )
        return self._results[pid]

    def get_result(self, proposal_id: int) -> Optional[VotingResult]:
        return self._results.get(proposal_id)

    def get_votes(self, proposal_id: int) -> List[VoteRecord]:
        return list(self._votes.get(proposal_id, []))

    def voter_count(self, proposal_id: int) -> int:
        return len(self._voters.get(proposal_id, set()))

    # ── Finalization ──────────────────────────────────────────────────

    def finalize(self, proposal: Proposal) -> VotingResult:
        """
        Finalize voting on a proposal.

        Determines outcome based on quorum and approval thresholds,
        then transitions the proposal accordingly.
        """
        result = self._get_or_create_result(proposal)

        if result.finalized:
            raise VotingError(f"Proposal #{proposal.id} already finalized")

        # Refresh eligible supply
        result.total_eligible_supply = self.get_total_eligible()

        result.finalized = True
        result.finalized_at = time.time()

        if not result.quorum_reached:
            proposal.mark_expired()
            logger.warning(
                f"Proposal #{proposal.id}: quorum not reached "
                f"({result.total_votes}/{result.total_eligible_supply})"
            )
        elif result.is_approved:
            proposal.mark_passed()
            logger.info(
                f"Proposal #{proposal.id}: PASSED "
                f"(approval={result.approval_rate:.2%})"
            )
        else:
            proposal.mark_defeated(
                f"Approval {result.approval_rate:.2%} < "
                f"threshold {result.approval_threshold:.0%}"
            )
            logger.info(
                f"Proposal #{proposal.id}: DEFEATED "
                f"(approval={result.approval_rate:.2%})"
            )

        return result

    # ── Queries ───────────────────────────────────────────────────────

    def has_voted(self, proposal_id: int, voter: str) -> bool:
        return voter in self._voters.get(proposal_id, set())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "activeProposals": len(self._results),
            "delegations": len(self._delegations),
            "results": {
                pid: r.to_dict() for pid, r in self._results.items()
            },
        }

    def __repr__(self) -> str:
        return f"<VotingEngine proposals={len(self._results)}>"
