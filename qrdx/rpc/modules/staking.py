"""
JSON-RPC reads for staking and delegation pools — ``staking_*`` (docs/STAKING.md). Writes are
exchange transactions (STAKE_DEPOSIT / STAKE_EXIT / STAKE_DELEGATE / STAKE_UNDELEGATE /
STAKE_SET_COMMISSION), submitted with ``exchange_sendTransaction``.

    staking_getValidators()         → every validator in the set in force at the tip: status,
                                      stake, weight (own effective stake + delegated), earned
    staking_getPools()              → every delegation pool: validator, commission, value,
                                      shares, share price, delegators, warming-up delegations
    staking_getDelegations(address) → the address's stake in each pool (shares and their value,
                                      warming-up delegations) and the payouts owed to it
    staking_getParams()             → the reward rate, default commission, minimum delegation,
                                      warm-up, unbonding and withdrawal delay

All from the validator set computed from the chain (qrdx/validator/epoch_state.py).
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, List

from ..server import RPCError, RPCErrorCode, RPCModule, rpc_method


class StakingModule(RPCModule):
    """Context: ``db``."""

    namespace = "staking"

    async def _state(self):
        from ...validator.epoch_state import state_at_tip

        db = getattr(self.context, "db", None)
        if db is None:
            raise RPCError(RPCErrorCode.RESOURCE_UNAVAILABLE, "Node not ready")
        return await state_at_tip(db)

    @rpc_method
    async def getValidators(self) -> List[Dict[str, Any]]:
        state = await self._state()
        return [
            {
                "address": v.address,
                "status": v.status,
                "stake": str(v.stake),
                "effective_stake": str(v.effective_stake),
                "delegated": str(state.pools[a].value) if a in state.pools else "0",
                "weight": str(state.weight(a)),
                "earned": str(v.earned),
                "activation_epoch": v.activation_epoch,
                "exit_epoch": v.exit_epoch,
                "slashed": v.slashed,
            }
            for a, v in sorted(state.items())
        ]

    @rpc_method
    async def getPools(self) -> List[Dict[str, Any]]:
        state = await self._state()
        return [
            {
                "validator": p.validator,
                "commission_bps": p.commission_bps,
                "next_commission_bps": p.next_commission,
                "value": str(p.value),
                "total_shares": str(p.total_shares),
                "share_price": str(p.price()),
                "delegators": len(p.shares),
                "warming_up": str(sum((amt for _a, amt, _e in p.pending), Decimal(0))),
            }
            for _v, p in sorted(state.pools.items())
        ]

    @rpc_method
    async def getDelegations(self, address: str) -> Dict[str, Any]:
        state = await self._state()
        who = str(address).lower()
        stakes = []
        for _v, p in sorted(state.pools.items()):
            shares = next((n for a, n in p.shares.items() if a.lower() == who), Decimal(0))
            warming = [(amt, at) for a, amt, at in p.pending if a.lower() == who]
            if shares or warming:
                stakes.append(
                    {
                        "validator": p.validator,
                        "shares": str(shares),
                        "value": str(shares * p.price()),
                        "warming_up": [
                            {"amount": str(amt), "active_from_epoch": at + 1} for amt, at in warming
                        ],
                    }
                )
        owed = [
            {
                "id": p.id,
                "kind": p.kind,
                "amount": str(p.amount),
                "due_epoch": p.due_epoch,
                "validator": p.validator,
            }
            for p in state.payouts
            if p.address.lower() == who
        ]
        return {"address": address, "stakes": stakes, "payouts": owed}

    @rpc_method
    async def getParams(self) -> Dict[str, Any]:
        from ... import constants
        from ...validator.epoch_state import reward_rate_per_epoch

        return {
            "reward_rate_bps_per_year": int(constants.STAKING_REWARD_RATE_BPS),
            "reward_rate_per_epoch": str(reward_rate_per_epoch()),
            "default_commission_bps": int(constants.STAKING_DEFAULT_COMMISSION_BPS),
            "min_delegation": str(constants.STAKE_MIN_DELEGATION),
            "min_validator_stake": str(constants.MIN_VALIDATOR_STAKE),
            "warmup_epochs": int(constants.ACTIVATION_DELAY_EPOCHS),
            "unbonding_epochs": int(constants.UNBONDING_PERIOD_EPOCHS),
            "withdrawal_delay_epochs": int(constants.WITHDRAWAL_DELAY_EPOCHS),
        }
