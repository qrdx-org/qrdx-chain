"""
S09 — Bridge Events & Attestations

Verifies:
    - Record bridge deposit event in persistence
    - Add validator attestations
    - Confirm and finalize event lifecycle
    - Validate doomsday canary persistence hooks
"""

import time
from decimal import Decimal

import aiosqlite

from integration_tests.scenarios.base import Scenario
from qrdx.bridge.persistence import BridgePersistence


class S09Bridge(Scenario):
    name = "s09_bridge"
    description = "Verify bridge persistence lifecycle"
    depends_on = ["s03_block_production"]

    async def execute(self) -> None:
        db_path = self.ctx.db_paths[0]
        wallets = self.ctx.wallets
        user0 = wallets.get("Test User 0")
        validator0 = wallets.get("Validator 0")
        validator1 = wallets.get("Validator 1")

        if not user0 or not validator0 or not validator1:
            self.check(False, "User and validator wallets available")
            return

        event_id = f"it-bridge-deposit-{int(time.time())}"

        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            bridge = BridgePersistence(db)
            await bridge.initialize()

            await bridge.record_deposit(
                event_id=event_id,
                source_chain="ethereum",
                from_address="0x" + "11" * 20,
                to_address=user0["address"],
                token_symbol="qETH",
                amount=Decimal("12.5"),
                required_confirmations=2,
                source_tx_hash="0x" + "ab" * 32,
            )

            event = await bridge.get_event(event_id)
            self.check(event is not None, "Bridge deposit event recorded")
            if event is None:
                return
            self.check(event.get("status") == "PENDING", "Bridge event starts PENDING")

            count1 = await bridge.add_attestation(
                event_id=event_id,
                validator_address=validator0["address"],
                signature="attest-sig-validator-0",
            )
            count2 = await bridge.add_attestation(
                event_id=event_id,
                validator_address=validator1["address"],
                signature="attest-sig-validator-1",
            )
            self.check(count1 >= 1 and count2 >= 2, "Bridge attestations recorded")

            await bridge.update_confirmations(event_id=event_id, confirmations=2)
            confirmed = await bridge.get_event(event_id)
            self.check(confirmed is not None and confirmed.get("status") == "CONFIRMED", "Event auto-confirms at threshold")

            await bridge.finalize_event(event_id=event_id, dest_tx_hash="0x" + "cd" * 32)
            finalized = await bridge.get_event(event_id)
            self.check(finalized is not None and finalized.get("status") == "FINALIZED", "Event finalized")
            self.check(int(finalized.get("attestation_count", 0)) >= 2, "Finalized event stores attestations")

            await bridge.initialize_canary(
                address=user0["address"],
                balance=Decimal("1.0"),
                bounty=Decimal("100.0"),
            )
            canary = await bridge.check_canary()
            self.check(canary is not None and int(canary.get("is_triggered", 0)) == 0, "Canary initialized")

            await bridge.trigger_canary()
            triggered = await bridge.check_canary()
            self.check(triggered is not None and int(triggered.get("is_triggered", 0)) == 1, "Canary trigger persisted")

            self.ctx.artifacts["s09_bridge_event_id"] = event_id
