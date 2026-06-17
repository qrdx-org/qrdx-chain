"""
Consensus validator-set epoch processing — runs on EVERY node (validator or full).

The validator-lifecycle reward/penalty/activation updates to the consensus
``validators`` table must be applied by every node, not just validators: a full node
verifies proposer eligibility off this table, so if only validators evolved their set
the full nodes would (once stake changes alter stake-weighted selection) reject
validator blocks. This standalone loop — started for all nodes — processes each
FINALIZED epoch exactly once. Finalized ⇒ that epoch's attestations have converged
network-wide, so ``compute_epoch_reward_deltas`` yields identical deltas on every node
and the ``validators`` table stays byte-identical (the safety property — eligibility is
enforced off it). Pure function of the chain; no wall-clock, no validator context.

Observe→enforce via ``_ENFORCE_EPOCH_VALIDATOR_UPDATES``.
"""

from __future__ import annotations

import asyncio
import logging

from ..constants import SLOT_DURATION
from .epoch_rewards import compute_epoch_reward_deltas
from .epoch_processing import MAX_EFFECTIVE_BALANCE
from .finality import update_finality

logger = logging.getLogger(__name__)

_SLEEP = SLOT_DURATION if isinstance(SLOT_DURATION, int) and SLOT_DURATION > 0 else 2

# Observe-first gate (mirrors node_integration). False = compute + log the would-be
# validators-table updates without writing; True = write them at each finalized epoch.
_ENFORCE_EPOCH_VALIDATOR_UPDATES = True


async def apply_epoch_validator_update(db, epoch: int, enforce: bool) -> None:
    """Apply (or, in observe, log) the deterministic reward/penalty deltas for one
    finalized ``epoch`` to the consensus ``validators`` table. Logs the table hash so
    cross-node convergence is observable."""
    active = await db.get_validators(status="active")
    attesters = await db.get_epoch_attesters(epoch)
    rewards, penalties = compute_epoch_reward_deltas(active, attesters)
    # Phase 3 membership: activate pending validators whose scheduled activation
    # epoch has arrived, and finalize exits whose exit epoch has arrived. Both are
    # deterministic (canonical-ordered DB reads keyed on the finalized epoch), so
    # the membership change is identical on every node.
    activated = await db.get_validators_to_activate(epoch)
    exited = await db.get_validators_to_exit(epoch)
    res = await db.apply_epoch_validator_updates(
        rewards, penalties, activated=activated, exited=exited, activation_epoch=epoch,
        max_effective_balance=MAX_EFFECTIVE_BALANCE, enforce=enforce,
    )
    if enforce:
        await db.connection.commit()
    vhash = await db.get_validators_table_hash()
    logger.info(
        "[epoch-validators %s] epoch=%d active=%d rewarded=%d penalized=%d validators_hash=%s",
        "ENFORCE" if enforce else "observe", epoch, len(active),
        res["rewarded"], res["penalized"], vhash[:16],
    )


async def epoch_validator_update_loop(db, enforce: bool = None) -> None:
    """Background loop (all nodes): drain finalized epochs, applying the consensus
    validator-set update to each exactly once, in order."""
    if enforce is None:
        enforce = _ENFORCE_EPOCH_VALIDATOR_UPDATES
    last_processed = -1
    logger.info("Consensus epoch validator-update loop started (enforce=%s)", enforce)
    while True:
        try:
            fin = await update_finality(db)
            finalized_epoch = int(fin.get("finalized_epoch", -1))
            while last_processed < finalized_epoch:
                ep = last_processed + 1
                await apply_epoch_validator_update(db, ep, enforce)
                last_processed = ep
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("epoch validator-update loop error: %s", e)
        await asyncio.sleep(_SLEEP)
