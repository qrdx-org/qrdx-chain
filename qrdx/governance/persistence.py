"""
Governance State Persistence — SQLite Backend

Stores governance proposals, votes, and execution state.
No stubs — real SQL operations.
"""

import aiosqlite
from decimal import Decimal
from typing import Dict, List, Optional
import logging
import time

logger = logging.getLogger(__name__)

GOVERNANCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS governance_proposals (
    proposal_id TEXT PRIMARY KEY,
    proposer_address TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    proposal_type TEXT NOT NULL DEFAULT 'PARAMETER_CHANGE',
    deposit_amount TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'DISCUSSION',
    parameter_key TEXT,
    parameter_value TEXT,
    votes_for TEXT NOT NULL DEFAULT '0',
    votes_against TEXT NOT NULL DEFAULT '0',
    votes_abstain TEXT NOT NULL DEFAULT '0',
    voting_start_epoch INTEGER,
    voting_end_epoch INTEGER,
    execution_time INTEGER,
    executed_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS governance_votes (
    proposal_id TEXT NOT NULL,
    voter_address TEXT NOT NULL,
    vote_type INTEGER NOT NULL,
    voting_power TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (proposal_id, voter_address),
    FOREIGN KEY (proposal_id) REFERENCES governance_proposals(proposal_id)
);

CREATE TABLE IF NOT EXISTS governance_parameters (
    parameter_key TEXT PRIMARY KEY,
    parameter_value TEXT NOT NULL,
    updated_by_proposal TEXT,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_governance_proposals_status ON governance_proposals(status);
CREATE INDEX IF NOT EXISTS idx_governance_proposals_proposer ON governance_proposals(proposer_address);
CREATE INDEX IF NOT EXISTS idx_governance_votes_proposal ON governance_votes(proposal_id);
CREATE INDEX IF NOT EXISTS idx_governance_votes_voter ON governance_votes(voter_address);
"""

# Vote type constants (match constants.py)
VOTE_FOR = 1
VOTE_AGAINST = 2
VOTE_ABSTAIN = 3


class GovernancePersistence:
    """SQLite persistence for governance state."""

    def __init__(self, connection: aiosqlite.Connection):
        self.connection = connection

    async def initialize(self) -> None:
        """Create governance tables."""
        await self.connection.executescript(GOVERNANCE_SCHEMA)
        await self.connection.commit()
        logger.info("Governance persistence schema initialized")

    async def create_proposal(
        self,
        proposal_id: str,
        proposer_address: str,
        title: str,
        description: str,
        proposal_type: str,
        deposit_amount: Decimal,
        parameter_key: Optional[str] = None,
        parameter_value: Optional[str] = None,
    ) -> None:
        """Create a new governance proposal."""
        now = int(time.time())
        await self.connection.execute(
            """INSERT INTO governance_proposals
               (proposal_id, proposer_address, title, description, proposal_type,
                deposit_amount, status, parameter_key, parameter_value,
                votes_for, votes_against, votes_abstain, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, 'DISCUSSION', ?, ?, '0', '0', '0', ?, ?)""",
            (proposal_id, proposer_address, title, description, proposal_type,
             str(deposit_amount), parameter_key, parameter_value, now, now),
        )
        await self.connection.commit()

    async def get_proposal(self, proposal_id: str) -> Optional[dict]:
        """Get proposal details."""
        cursor = await self.connection.execute(
            "SELECT * FROM governance_proposals WHERE proposal_id = ?", (proposal_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def advance_to_voting(
        self, proposal_id: str, voting_start_epoch: int, voting_end_epoch: int
    ) -> None:
        """Advance proposal to voting phase."""
        now = int(time.time())
        await self.connection.execute(
            """UPDATE governance_proposals SET status = 'VOTING',
               voting_start_epoch = ?, voting_end_epoch = ?, updated_at = ?
               WHERE proposal_id = ?""",
            (voting_start_epoch, voting_end_epoch, now, proposal_id),
        )
        await self.connection.commit()

    async def cast_vote(
        self,
        proposal_id: str,
        voter_address: str,
        vote_type: int,
        voting_power: Decimal,
        signature: str,
    ) -> None:
        """Cast a vote on a proposal. Replaces existing vote."""
        now = int(time.time())

        # Remove old vote totals if re-voting
        old = await self._get_vote(proposal_id, voter_address)
        if old:
            await self._subtract_vote_power(proposal_id, old["vote_type"], Decimal(old["voting_power"]))

        await self.connection.execute(
            """INSERT INTO governance_votes
               (proposal_id, voter_address, vote_type, voting_power, signature, created_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(proposal_id, voter_address) DO UPDATE SET
                vote_type = ?, voting_power = ?, signature = ?, created_at = ?""",
            (proposal_id, voter_address, vote_type, str(voting_power), signature, now,
             vote_type, str(voting_power), signature, now),
        )

        # Add to totals
        col = {VOTE_FOR: "votes_for", VOTE_AGAINST: "votes_against", VOTE_ABSTAIN: "votes_abstain"}[vote_type]
        await self.connection.execute(
            f"""UPDATE governance_proposals
                SET {col} = CAST(CAST({col} AS DECIMAL) + ? AS TEXT), updated_at = ?
                WHERE proposal_id = ?""",
            (str(voting_power), now, proposal_id),
        )
        await self.connection.commit()

    async def _get_vote(self, proposal_id: str, voter_address: str) -> Optional[dict]:
        cursor = await self.connection.execute(
            "SELECT * FROM governance_votes WHERE proposal_id = ? AND voter_address = ?",
            (proposal_id, voter_address),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def _subtract_vote_power(self, proposal_id: str, vote_type: int, power: Decimal) -> None:
        col = {VOTE_FOR: "votes_for", VOTE_AGAINST: "votes_against", VOTE_ABSTAIN: "votes_abstain"}[vote_type]
        now = int(time.time())
        await self.connection.execute(
            f"""UPDATE governance_proposals
                SET {col} = CAST(MAX(0, CAST({col} AS DECIMAL) - ?) AS TEXT), updated_at = ?
                WHERE proposal_id = ?""",
            (str(power), now, proposal_id),
        )

    async def tally_and_finalize(self, proposal_id: str, quorum: Decimal, approval_threshold: Decimal) -> str:
        """
        Tally votes and finalize the proposal.
        Returns new status: 'PASSED', 'REJECTED', or 'QUORUM_NOT_MET'.
        """
        proposal = await self.get_proposal(proposal_id)
        if not proposal:
            raise ValueError(f"Proposal not found: {proposal_id}")

        total_for = Decimal(proposal["votes_for"])
        total_against = Decimal(proposal["votes_against"])
        total_abstain = Decimal(proposal["votes_abstain"])
        total_votes = total_for + total_against + total_abstain

        deposit = Decimal(proposal["deposit_amount"])

        if total_votes < quorum:
            status = "QUORUM_NOT_MET"
        elif total_for / (total_for + total_against) >= approval_threshold if (total_for + total_against) > 0 else False:
            status = "PASSED"
        else:
            status = "REJECTED"

        now = int(time.time())
        await self.connection.execute(
            "UPDATE governance_proposals SET status = ?, updated_at = ? WHERE proposal_id = ?",
            (status, now, proposal_id),
        )
        await self.connection.commit()
        return status

    async def execute_proposal(self, proposal_id: str) -> None:
        """Mark proposal as executed and apply parameter change."""
        proposal = await self.get_proposal(proposal_id)
        if not proposal or proposal["status"] != "PASSED":
            raise ValueError(f"Proposal {proposal_id} is not in PASSED state")

        now = int(time.time())

        # Apply parameter change if applicable
        if proposal["parameter_key"] and proposal["parameter_value"]:
            await self.connection.execute(
                """INSERT INTO governance_parameters (parameter_key, parameter_value, updated_by_proposal, updated_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(parameter_key) DO UPDATE SET
                    parameter_value = ?, updated_by_proposal = ?, updated_at = ?""",
                (proposal["parameter_key"], proposal["parameter_value"], proposal_id, now,
                 proposal["parameter_value"], proposal_id, now),
            )

        await self.connection.execute(
            "UPDATE governance_proposals SET status = 'EXECUTED', executed_at = ?, updated_at = ? WHERE proposal_id = ?",
            (now, now, proposal_id),
        )
        await self.connection.commit()

    async def get_parameter(self, key: str) -> Optional[str]:
        """Get a governance-controlled parameter value."""
        cursor = await self.connection.execute(
            "SELECT parameter_value FROM governance_parameters WHERE parameter_key = ?", (key,)
        )
        row = await cursor.fetchone()
        return row["parameter_value"] if row else None

    async def list_proposals(self, status: Optional[str] = None) -> List[dict]:
        """List proposals, optionally filtered by status."""
        if status:
            cursor = await self.connection.execute(
                "SELECT * FROM governance_proposals WHERE status = ? ORDER BY created_at DESC",
                (status,),
            )
        else:
            cursor = await self.connection.execute(
                "SELECT * FROM governance_proposals ORDER BY created_at DESC"
            )
        return [dict(r) for r in await cursor.fetchall()]
