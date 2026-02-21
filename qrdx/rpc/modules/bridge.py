"""
QRDX bridge_* RPC Methods

Exposes doomsday status, canary info, attestation submission, and
shielding statistics via the JSON-RPC interface.

Namespace: ``bridge``  (methods are ``bridge_getDoomsdayStatus``, etc.)
"""

import json
import logging
from decimal import Decimal
from typing import Any, Dict, List, Optional

from ..server import RPCModule, rpc_method, rpc_admin_method, RPCError, RPCErrorCode

logger = logging.getLogger(__name__)


class BridgeModule(RPCModule):
    """
    Bridge / Doomsday RPC methods (bridge_* namespace).

    These methods expose the state of the cross-chain bridge and the
    Doomsday Protocol (Whitepaper §8.5) so that wallets, block
    explorers, and monitoring tools can query protocol status.

    Context expectations (set during RPC server bootstrap):
        self.context.shielding_manager — ShieldingManager instance
        self.context.doomsday          — DoomsdayProtocol instance
        self.context.eth_adapter       — EthereumAdapter (optional)
    """

    namespace = "bridge"

    # ── Public queries ──────────────────────────────────────────────

    @rpc_method
    async def getDoomsdayStatus(self) -> Dict[str, Any]:
        """
        Return the full doomsday protocol status.

        Matches Whitepaper §8.5 ``getDoomsdayStatus()`` external view.

        Returns:
            doomsday_active, triggered_at, trigger_block_height,
            verification_hash, shield_allowed, unshield_allowed, bounty,
            attestation_progress, registered_bridges count.
        """
        doomsday = self._get_doomsday()
        return doomsday.get_status()

    @rpc_method
    async def getCanaryInfo(self) -> Dict[str, Any]:
        """
        Return canary wallet information including on-chain balance
        (if an Ethereum adapter is available).

        Returns:
            canary_address, expected_balance, live_balance (or null),
            is_safe (boolean), doomsday_active.
        """
        doomsday = self._get_doomsday()
        status = doomsday.get_status()

        live_balance = None
        adapter = self._get_eth_adapter()
        if adapter is not None:
            try:
                live_balance = adapter.check_canary_balance()
            except Exception as exc:
                logger.warning(f"Failed to fetch canary balance: {exc}")

        from ...constants import DOOMSDAY_CANARY_BOUNTY
        expected = DOOMSDAY_CANARY_BOUNTY

        return {
            "canary_address": status["canary_address"],
            "expected_balance": str(expected),
            "live_balance": str(live_balance) if live_balance is not None else None,
            "is_safe": (
                live_balance >= expected
                if live_balance is not None
                else None
            ),
            "doomsday_active": status["doomsday_active"],
        }

    @rpc_method
    async def getAttestationProgress(self) -> Dict[str, Any]:
        """
        Return current doomsday attestation count vs threshold.

        Returns:
            received, threshold, total_validators, validators_attested.
        """
        doomsday = self._get_doomsday()
        return doomsday.get_attestation_progress()

    @rpc_method
    async def getShieldingStats(self) -> Dict[str, Any]:
        """
        Return comprehensive shielding statistics.

        Returns:
            total_records, pending, doomsday status, minter stats, etc.
        """
        manager = self._get_shielding_manager()
        return manager.get_stats()

    @rpc_method
    async def getBountyInfo(self) -> Dict[str, Any]:
        """
        Return the doomsday bounty status.

        Returns:
            amount, recipient, paid.
        """
        doomsday = self._get_doomsday()
        return doomsday.get_bounty_info()

    # ── Admin methods ───────────────────────────────────────────────

    @rpc_admin_method
    async def submitDoomsdayAttestation(
        self,
        attestation_json: str,
    ) -> Dict[str, Any]:
        """
        Submit a doomsday attestation (admin only).

        The attestation must be a JSON-encoded DoomsdayAttestation dict.
        This endpoint is for validators that observe canary drain from
        their own Ethereum adapter and want to broadcast via RPC.

        Args:
            attestation_json: JSON-encoded DoomsdayAttestation

        Returns:
            accepted (bool), triggered (bool), message (str)
        """
        doomsday = self._get_doomsday()

        from ...bridge.shielding import DoomsdayAttestation

        try:
            data = json.loads(attestation_json)
            attestation = DoomsdayAttestation.from_dict(data)
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise RPCError(
                RPCErrorCode.INVALID_PARAMS,
                f"Malformed attestation: {exc}",
            )

        triggered = doomsday.submit_canary_attestation(attestation)

        progress = doomsday.get_attestation_progress()
        return {
            "accepted": True,
            "triggered": triggered,
            "message": (
                "DOOMSDAY TRIGGERED — shield operations blocked"
                if triggered
                else f"Attestation recorded ({progress['received']}/{progress['threshold']})"
            ),
        }

    @rpc_admin_method
    async def triggerDoomsdayBySignature(
        self,
        message_hex: str,
        signature_hex: str,
        block_height: int = 0,
    ) -> Dict[str, Any]:
        """
        Trigger doomsday via canary ECDSA signature (admin, Path A).

        Args:
            message_hex: Hex-encoded message that was signed
            signature_hex: Hex-encoded ECDSA signature
            block_height: Block height at trigger time

        Returns:
            triggered (bool), message (str)
        """
        doomsday = self._get_doomsday()

        try:
            message = bytes.fromhex(message_hex)
        except ValueError:
            raise RPCError(RPCErrorCode.INVALID_PARAMS, "Invalid message hex")

        triggered = doomsday.trigger_by_canary_signature(
            message=message,
            signature=signature_hex,
            block_height=block_height,
        )

        return {
            "triggered": triggered,
            "message": (
                "DOOMSDAY TRIGGERED via canary signature"
                if triggered
                else "Trigger rejected — check logs for reason"
            ),
        }

    # ── Helpers ─────────────────────────────────────────────────────

    def _get_doomsday(self):
        """Resolve DoomsdayProtocol from context."""
        # Try direct attribute first, then through shielding manager
        if hasattr(self.context, "doomsday") and self.context.doomsday is not None:
            return self.context.doomsday
        if (
            hasattr(self.context, "shielding_manager")
            and self.context.shielding_manager is not None
        ):
            return self.context.shielding_manager.doomsday
        raise RPCError(
            RPCErrorCode.INTERNAL_ERROR,
            "Doomsday protocol not available — bridge not initialized",
        )

    def _get_shielding_manager(self):
        """Resolve ShieldingManager from context."""
        if (
            hasattr(self.context, "shielding_manager")
            and self.context.shielding_manager is not None
        ):
            return self.context.shielding_manager
        raise RPCError(
            RPCErrorCode.INTERNAL_ERROR,
            "Shielding manager not available — bridge not initialized",
        )

    def _get_eth_adapter(self):
        """Resolve EthereumAdapter from context (returns None if absent)."""
        if hasattr(self.context, "eth_adapter") and self.context.eth_adapter is not None:
            return self.context.eth_adapter
        return None
