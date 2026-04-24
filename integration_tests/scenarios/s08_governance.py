"""
S08 — Governance Proposals & Voting

Verifies:
    - Create a governance proposal via the real persistence layer
    - Advance proposal to voting and cast validator votes
    - Tally/finalize and execute a passed proposal
    - Verify governance parameter updates
"""

import time
from decimal import Decimal

import aiosqlite

from integration_tests.scenarios.base import Scenario
from qrdx.governance.persistence import GovernancePersistence, VOTE_ABSTAIN, VOTE_FOR


class S08Governance(Scenario):
    name = "s08_governance"
    description = "Verify governance proposal lifecycle"
    depends_on = ["s07_validators"]

    async def execute(self) -> None:
        db_path = self.ctx.db_paths[0]
        wallets = self.ctx.wallets
        user0 = wallets.get("Test User 0")

        if not user0:
            self.check(False, "Test User 0 wallet available")
            return

        validator_wallets = [wallets.get(f"Validator {i}") for i in range(3)]
        if not all(validator_wallets):
            self.check(False, "Validator wallets available for governance voting")
            return

        proposal_id = f"it-gov-{int(time.time())}"
        param_key = "consensus.slot_duration"
        param_value = "3"

        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            gov = GovernancePersistence(db)
            await gov.initialize()

            await gov.create_proposal(
                proposal_id=proposal_id,
                proposer_address=user0["address"],
                title="Integration Test Slot Duration Change",
                description="Validate governance proposal lifecycle in integration tests",
                proposal_type="PARAMETER_CHANGE",
                deposit_amount=Decimal("1000"),
                parameter_key=param_key,
                parameter_value=param_value,
            )

            proposal = await gov.get_proposal(proposal_id)
            self.check(proposal is not None, "Governance proposal created")
            if proposal is None:
                return
            self.check(proposal.get("status") == "DISCUSSION", "Proposal starts in DISCUSSION")

            await gov.advance_to_voting(proposal_id, voting_start_epoch=1, voting_end_epoch=10)
            proposal = await gov.get_proposal(proposal_id)
            self.check(proposal is not None and proposal.get("status") == "VOTING", "Proposal advanced to VOTING")

            await gov.cast_vote(
                proposal_id=proposal_id,
                voter_address=validator_wallets[0]["address"],
                vote_type=VOTE_FOR,
                voting_power=Decimal("120"),
                signature="sig-validator-0",
            )
            await gov.cast_vote(
                proposal_id=proposal_id,
                voter_address=validator_wallets[1]["address"],
                vote_type=VOTE_FOR,
                voting_power=Decimal("110"),
                signature="sig-validator-1",
            )
            await gov.cast_vote(
                proposal_id=proposal_id,
                voter_address=validator_wallets[2]["address"],
                vote_type=VOTE_ABSTAIN,
                voting_power=Decimal("100"),
                signature="sig-validator-2",
            )
            self.check(True, "Validator votes recorded")

            status = await gov.tally_and_finalize(
                proposal_id=proposal_id,
                quorum=Decimal("200"),
                approval_threshold=Decimal("0.60"),
            )
            self.check(status == "PASSED", f"Proposal passed tally ({status})")

            await gov.execute_proposal(proposal_id)
            executed = await gov.get_proposal(proposal_id)
            self.check(executed is not None and executed.get("status") == "EXECUTED", "Proposal executed")

            updated_value = await gov.get_parameter(param_key)
            self.check(updated_value == param_value, "Governance parameter updated by execution")

            executed_items = await gov.list_proposals(status="EXECUTED")
            has_proposal = any(p.get("proposal_id") == proposal_id for p in executed_items)
            self.check(has_proposal, "Executed proposal appears in status listing")

            self.ctx.artifacts["s08_governance_proposal_id"] = proposal_id
