"""
JSON-RPC for on-chain governance — ``governance_*`` (docs/GOVERNANCE.md). Read-only: proposals,
votes and vetoes are exchange transactions (GOV_PROPOSE / GOV_VOTE / GOV_VETO / GOV_EXECUTE),
submitted with ``exchange_sendTransaction`` like any other.

    governance_getStatus()               → parameters, the master controller's authority, fork
                                           approvals, open proposal count, the current height
    governance_getProposals(status, limit) → proposals, newest first (status: "open", or one of
                                           voting/passed/rejected/vetoed/executed/expired)
    governance_getProposal(id)           → one proposal, with its status at the current height
    governance_getForkApprovalParams(fork) → the exact params an approve_fork proposal for one of
                                           this node's scheduled forks must carry
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..server import RPCError, RPCErrorCode, RPCModule, rpc_method


def _manager():
    from ...exchange import ExchangeStateManager
    return ExchangeStateManager.get_instance()


class GovernanceModule(RPCModule):
    """Context: ``db`` (for the chain height)."""

    namespace = "governance"

    async def _height(self) -> int:
        db = getattr(self.context, "db", None)
        if db is None:
            raise RPCError(RPCErrorCode.RESOURCE_UNAVAILABLE, "Node not ready")
        # Judged as the next block would judge it.
        return int(await db.get_next_block_id())

    @rpc_method
    async def getStatus(self) -> Dict[str, Any]:
        from ... import chain_spec, constants
        from ...exchange.governance import OPEN_STATUSES, master_authority, veto_escrow_address
        height = await self._height()
        gov = _manager().governance
        authority, why = master_authority(height)
        return {
            "height": height,
            "params": {k: getattr(constants, k) for k in (
                "GOV_VOTING_PERIOD_BLOCKS", "GOV_TIMELOCK_BLOCKS", "GOV_EXECUTION_WINDOW_BLOCKS",
                "GOV_APPROVAL_THRESHOLD_BPS", "GOV_VETO_THRESHOLD_QRDX",
                "GOV_FORK_APPROVAL_LEAD_BLOCKS", "SYSTEM_WALLET_MASTER_SUNSET_HEIGHT")},
            "master_controller": {"authority": authority, "reason": why,
                                  "frozen_at": gov.master_frozen_at,
                                  "sunset_height": constants.SYSTEM_WALLET_MASTER_SUNSET_HEIGHT},
            "fork_approvals": sorted(gov.fork_approvals.values(), key=lambda a: a["approved_at"]),
            "open_proposals": sum(1 for p in gov.proposals.values()
                                  if gov.effective_status(p, height) in OPEN_STATUSES),
            "veto_escrow": veto_escrow_address(),
            "committee": {a: str(w) for a, w in sorted((_manager().oracle_committee or {}).items())},
            "scheduled_forks": [
                {**f, "approval": chain_spec.fork_approval(chain_spec.active(), f)}
                for f in chain_spec.active().forks],
        }

    @rpc_method
    async def getProposals(self, status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        from ...exchange.governance import OPEN_STATUSES
        height = await self._height()
        gov = _manager().governance
        out = []
        for pid in sorted(gov.proposals, reverse=True):
            view = gov.view(gov.proposals[pid], height)
            if status == "open" and view["status"] not in OPEN_STATUSES:
                continue
            if status not in (None, "open") and view["status"] != status:
                continue
            out.append(view)
            if len(out) >= max(1, min(int(limit), 500)):
                break
        return out

    @rpc_method
    async def getProposal(self, proposal_id: int) -> Dict[str, Any]:
        height = await self._height()
        gov = _manager().governance
        p = gov.proposals.get(int(proposal_id))
        if p is None:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, f"no proposal {proposal_id}")
        return gov.view(p, height)

    @rpc_method
    async def getForkApprovalParams(self, fork: str) -> Dict[str, Any]:
        """What a validator puts in GOV_PROPOSE to approve one of this node's scheduled forks —
        so nobody has to recompute the definition hash by hand."""
        from ... import chain_spec
        spec = chain_spec.active()
        match = next((f for f in spec.forks if f["name"] == fork), None)
        if match is None:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, f"this node's chain spec schedules no fork {fork!r}")
        approval = chain_spec.fork_approval(spec, match)
        return {"action": "approve_fork", "fork": match["name"], "height": match["height"],
                "definition_hash": approval["definition_hash"],
                "approve_by": approval["approve_by"]}
