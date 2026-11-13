"""
JSON-RPC reads for the consensus bridge — ``bridge_*`` (docs/BRIDGE.md). Withdrawals are
exchange transactions (``BRIDGE_WITHDRAW``); deposits are attested by validators' votes.

    bridge_getAssets()                    → the bridged tokens: source chain and token, decimals,
                                            the QRDX token address, supply minted so far
    bridge_getDeposit(id)                 → "<chain>:<lockbox deposit id>": minted, or the
                                            attestations it has so far
    bridge_getWithdrawals(from_id, limit) → recorded withdrawals from ``from_id``, oldest first
                                            — what the lockbox's custodian releases
    bridge_getGuardrails()                → the deposit window (what the custodian's refunds
                                            wait for), the mint limits and today's use, and
                                            whether governance paused minting
    bridge_getHeads(chain)                → the source chain's attested finalized heads (the
                                            last 64), oldest first: what BRIDGE_PROVE_DEPOSIT
                                            proves a deposit against
    bridge_getDoomsday()                  → whether the Doomsday Protocol triggered (its time,
                                            block and cause) and each chain's canary
                                            (docs/QUANTUM_MIGRATION.md)
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..server import RPCError, RPCErrorCode, RPCModule, rpc_method


def _manager():
    from ...exchange import ExchangeStateManager

    return ExchangeStateManager.get_instance()


class BridgeLedgerModule(RPCModule):
    namespace = "bridge"

    @rpc_method
    async def getAssets(self) -> List[Dict[str, Any]]:
        from ...exchange.bridge import BRIDGE_AUTHORITY, configured_assets

        tokens = _manager().tokens
        out = []
        for asset in configured_assets().values():
            t = tokens.get(asset.address)
            out.append(
                dict(
                    asset.summary(),
                    supply=str(t.supply) if t is not None else "0",
                    mint_authority=BRIDGE_AUTHORITY,
                )
            )
        return out

    @rpc_method
    async def getDeposit(self, deposit_id: str) -> Dict[str, Any]:
        return _manager().bridge.status(str(deposit_id).lower())

    @rpc_method
    async def getWithdrawals(self, from_id: int = 1, limit: int = 100) -> List[Dict[str, Any]]:
        try:
            from_id, limit = int(from_id), int(limit)
        except (TypeError, ValueError) as exc:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, "from_id and limit are integers") from exc
        return _manager().bridge.list_withdrawals(from_id, max(1, min(limit, 1000)))

    @rpc_method
    async def getGuardrails(self) -> Dict[str, Any]:
        return _manager().bridge.guardrails()

    @rpc_method
    async def getHeads(self, chain: int) -> List[Dict[str, Any]]:
        try:
            chain = int(chain)
        except (TypeError, ValueError) as exc:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, "chain is an integer") from exc
        bridge = _manager().bridge
        heights = sorted(
            int(k.split("|", 1)[1])
            for k in dict.keys(bridge.head_history)
            if k.split("|", 1)[0] == str(chain)
        )
        out = []
        for height in heights:
            head = bridge.head_at(chain, height)
            if head is not None:
                out.append(
                    {
                        "chain": chain,
                        "height": head.height,
                        "hash": head.hash,
                        "state_root": head.state_root,
                        "timestamp": head.timestamp,
                    }
                )
        return out

    @rpc_method
    async def getDoomsday(self) -> Dict[str, Any]:
        from ...exchange.doomsday import configured_canaries

        return {
            "triggered": _manager().bridge.doomsday,
            "canaries": {str(c): a for c, a in sorted(configured_canaries().items())},
        }
