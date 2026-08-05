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

# Slashing penalty enforce gate. The deterministic slash (effective_stake reduction + eject)
# at the finalized epoch keeps the validators table byte-identical across nodes ONLY if every
# node holds the SAME slashing_events by then — which now holds: DOUBLE_SIGN evidence rides the
# canonical chain (evidence-in-blocks, validator/slashing_block.py), so every node records
# identical evidence + applies the identical penalty. ENABLED after:
#   • the enforce path proven byte-identical convergent across nodes (tests/test_slashing_
#     enforce_convergence.py) — the halt risk (divergent eligible set) is settled;
#   • the transport confirmed LIVE-wired (proposer propose_block includes evidence; every
#     import path records it via record_finality_from_block — same mechanism as attestations);
#   • a false-positive soak (4 honest runs incl. 2 at ~50 reorgs) recording 0 double-sign
#     detections → enforce is a no-op on an honest network, no false slashes;
#   • the penalty itself unit-tested (test_slashing_detection, enforce=True → 50% + eject).
# A slash requires two VALIDLY-SIGNED conflicting blocks by the same proposer for one slot, so
# an honest validator (which signs once per slot) is never slashed. A live malicious-node soak
# remains a nice-to-have to exercise detection under adversarial load, but the halt risk is
# settled deterministically.
_ENFORCE_SLASHING = True


async def apply_epoch_validator_update(db, epoch: int, enforce: bool) -> None:
    """Apply (or, in observe, log) the deterministic reward/penalty deltas for one
    finalized ``epoch`` to the consensus ``validators`` table. Logs the table hash so
    cross-node convergence is observable."""
    active = await db.get_validators(status="active")
    attesters = await db.get_epoch_attesters(epoch)
    rewards, penalties = compute_epoch_reward_deltas(active, attesters)
    # Phase 3 membership: activation_epoch / exit_epoch were assigned DETERMINISTICALLY
    # at deposit/exit-import time (block_epoch + delay; see flush_validator_lifecycle_deltas)
    # — NOT scheduled here. Scheduling at the epoch-loop tick was non-deterministic: a
    # node assigned the epoch based on when IT happened to observe the pending validator,
    # so two nodes diverged. Now the loop only ACTIVATES / REMOVES validators whose
    # pre-assigned epoch the FINALIZED epoch has reached — identical on every node.
    activated = await db.get_validators_to_activate(epoch)
    exited = await db.get_validators_to_exit(epoch)
    res = await db.apply_epoch_validator_updates(
        rewards, penalties, activated=activated, exited=exited, activation_epoch=epoch,
        max_effective_balance=MAX_EFFECTIVE_BALANCE, enforce=enforce,
    )
    # Slashing penalties for offences in finalized epochs ≤ this one (own observe/enforce
    # gate — see _ENFORCE_SLASHING; stays observe until evidence is cross-node deterministic).
    await apply_epoch_slashings(db, epoch, enforce=(enforce and _ENFORCE_SLASHING))
    if enforce:
        await db.connection.commit()
    vhash = await db.get_validators_table_hash()
    logger.info(
        "[epoch-validators %s] epoch=%d active=%d rewarded=%d penalized=%d validators_hash=%s",
        "ENFORCE" if enforce else "observe", epoch, len(active),
        res["rewarded"], res["penalized"], vhash[:16],
    )


async def apply_epoch_slashings(db, epoch: int, enforce: bool) -> None:
    """Apply (or, in observe, log) deterministic slashing penalties for offences in
    finalized epochs ≤ ``epoch``. Each offending validator is penalised by the WORST
    applicable fraction of its current effective_stake (SLASHING_PENALTIES) and ejected
    (status='slashed'); its evidence is then marked processed (penalty applied once).
    Pure function of the recorded evidence — identical on every node that holds it."""
    events = await db.get_unprocessed_slashing_events(up_to_epoch=epoch)
    if not events:
        return
    from decimal import Decimal
    from .slashing import SLASHING_PENALTIES, SlashingConditions
    # Worst penalty fraction per offending validator across its recorded conditions.
    worst: dict = {}
    for ev in events:
        try:
            frac = SLASHING_PENALTIES.get(SlashingConditions(ev["condition"]), Decimal("0.10"))
        except Exception:
            frac = Decimal("0.10")
        addr = ev["validator_address"]
        if addr not in worst or frac > worst[addr]:
            worst[addr] = frac
    for addr, frac in worst.items():
        c = await db.connection.execute(
            "SELECT effective_stake FROM validators WHERE address = ?", (addr,))
        row = await c.fetchone()
        if not row:
            continue
        penalty = (Decimal(str(row[0] or 0)) * frac)
        res = await db.apply_validator_slash(addr, penalty, enforce=enforce)
        if enforce:
            await db.mark_slashing_events_processed(addr, epoch)
        logger.warning(
            "[slashing %s] epoch=%d validator=%s penalty=%s new_stake=%s (ejected → 'slashed')",
            "ENFORCE" if enforce else "observe", epoch, str(addr)[:20],
            res["penalty"], res["new_stake"])


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
