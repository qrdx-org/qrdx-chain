"""
Doppelganger protection: stop signing when the same key is signing somewhere else.

The slashing-protection record (slashing_protection.py) stops a validator from contradicting what
it has itself signed. It cannot see a second machine running the same key with its own record:
a hot standby, a restored backup left running, a migration where the old host never stopped.
Together those two machines sign two blocks for a slot, or two votes for an epoch, and the chain
slashes the stake.

So a validator, once started, watches the chain for its own key:

* Every epoch it looks at the blocks and votes the chain carries from the moment it started. Any
  that its record does not hold were signed by another holder of the key. It then stops signing
  for good (until an operator restarts it) and says so at CRITICAL.
* For the first ``QRDX_DOPPELGANGER_EPOCHS`` epochs (3 by default, 0 on dev networks) it signs
  nothing at all, so a second instance already running shows itself before this one adds a
  conflicting signature. Its votes are expected once an epoch, and its blocks in its slots.

Restarting costs those epochs' rewards. It is the price Lighthouse and Teku also ask for this
check.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from ..logger import get_logger

logger = get_logger(__name__)

EPOCHS_ENV = "QRDX_DOPPELGANGER_EPOCHS"
DEFAULT_EPOCHS = 3


def configured_epochs(dev: bool) -> int:
    raw = os.environ.get(EPOCHS_ENV)
    if raw is None or raw == "":
        return 0 if dev else DEFAULT_EPOCHS
    epochs = int(raw)
    if epochs < 0:
        raise ValueError(f"{EPOCHS_ENV} must be 0 or more")
    return epochs


class DoppelgangerGuard:
    """Decides, per slot, whether the validator may sign (see the module docstring)."""

    def __init__(
        self, db: Any, protection: Any, address: str, epochs: int, slots_per_epoch: int
    ) -> None:
        self.db = db
        self.protection = protection
        self.address = address
        self.epochs = int(epochs)
        self.slots_per_epoch = int(slots_per_epoch)
        self.start_slot: Optional[int] = None
        self.detected: Optional[str] = None
        self._scanned_epoch = -1
        self._scan_from_slot = 0
        self._last_slot: Optional[int] = None

    def status(self) -> dict:
        """For monitoring: whether a doppelganger was seen, and whether the validator is still
        listening before its first signature."""
        return {
            "detected": self.detected is not None,
            "listening": self._last_slot is None or self._last_slot < self.listen_until,
        }

    async def hold(self, slot: int) -> Optional[str]:
        """None if signing at ``slot`` is allowed; else why not."""
        self._last_slot = int(slot)
        if self.detected:
            return self.detected
        if self.start_slot is None:
            self.start_slot = self._scan_from_slot = int(slot)
            if self.epochs:
                logger.info(
                    "Doppelganger check: listening for %d epochs (until slot %d) before signing",
                    self.epochs,
                    self.listen_until,
                )
        epoch = int(slot) // self.slots_per_epoch
        if epoch != self._scanned_epoch:
            self._scanned_epoch = epoch
            found = await self.scan()
            if found:
                self.detected = (
                    f"doppelganger: {found} — another machine is signing with this validator's "
                    "key; this one has stopped signing. Stop one of them, then restart."
                )
                logger.critical(self.detected)
                return self.detected
        if int(slot) < self.listen_until:
            return f"doppelganger check: listening until slot {self.listen_until}"
        return None

    @property
    def listen_until(self) -> int:
        return (self.start_slot or 0) + self.epochs * self.slots_per_epoch

    async def scan(self) -> Optional[str]:
        """What the chain carries, signed by this key since the start, that the record does not
        hold; None if nothing."""
        if self.start_slot is None:
            return None
        start, conn = self._scan_from_slot, self.db.connection
        cur = await conn.execute(
            "SELECT ci.slot, b.block_hash FROM blocks b JOIN chain_index ci"
            " ON ci.height = b.block_height WHERE b.validator_address = ? AND ci.slot >= ?",
            (self.address, start),
        )
        blocks = await cur.fetchall()
        if blocks:
            mine = await self.protection.signed_block_roots(self.address, start)
            for slot, block_hash in blocks:
                if mine.get(int(slot)) != str(block_hash).lower().removeprefix("0x"):
                    return f"block {block_hash} at slot {slot}, which this validator did not sign"

        from .attestation import Attestation

        start_epoch = self.start_slot // self.slots_per_epoch
        cur = await conn.execute(
            "SELECT slot, epoch, block_hash, source_epoch, target_epoch, source_root, target_root"
            " FROM attestation_votes WHERE validator_address = ? AND target_epoch >= ?",
            (self.address, start_epoch),
        )
        votes = await cur.fetchall()
        if votes:
            mine = await self.protection.signed_vote_roots(self.address, start_epoch)
            for slot, epoch, block_hash, source, target, source_root, target_root in votes:
                root = Attestation(
                    slot=int(slot),
                    epoch=int(epoch),
                    block_hash=str(block_hash),
                    validator_address=self.address,
                    validator_index=0,
                    signature=b"",
                    source_epoch=int(source),
                    target_epoch=int(target),
                    source_root=str(source_root or ""),
                    target_root=str(target_root or ""),
                ).signing_root.hex()
                if mine.get(int(target)) != root:
                    return f"a vote for target epoch {target}, which this validator did not sign"
        # The next scan starts a little before this one's end: blocks can land late.
        tip = max((int(s) for s, _ in blocks), default=start)
        self._scan_from_slot = max(start, tip - self.slots_per_epoch)
        return None
