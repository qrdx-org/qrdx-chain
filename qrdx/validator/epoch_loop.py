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

from ..constants import (
    SLOT_DURATION,
    UNBONDING_PERIOD_EPOCHS,
    VALIDATOR_EJECTION_STAKE,
)
from .epoch_rewards import compute_epoch_reward_deltas
from .epoch_processing import MAX_EFFECTIVE_BALANCE
from .finality import update_finality

logger = logging.getLogger(__name__)

_SLEEP = SLOT_DURATION if isinstance(SLOT_DURATION, int) and SLOT_DURATION > 0 else 2

# Observe-first gate (mirrors node_integration). False = compute + log the would-be
# validators-table updates without writing; True = write them at each finalized epoch.
_ENFORCE_EPOCH_VALIDATOR_UPDATES = True

# Eject an ACTIVE validator whose effective_stake has fallen below
# VALIDATOR_EJECTION_STAKE. Before this there was NO maintenance threshold at all: a
# validator could decay toward zero under sustained inactivity penalties and keep its full
# stake-weighted influence over proposer selection and fork choice.
#
# Note this is deliberately NOT the activation threshold (MIN_VALIDATOR_STAKE) — ejecting
# there would churn the set on ordinary missed attestations. See the constant's comment.
#
# The validator leaves through 'exiting' + unbonding, exactly like a voluntary STAKE_EXIT,
# so it stays eligible until its deterministic finalized exit_epoch and its stake is
# refunded then (it is not slashed — it was merely inactive).
_ENFORCE_STAKE_FLOOR_EJECTION = True

# Refund exited validators' principal from THIS loop. DISABLED, and must stay disabled.
#
# The refund credits account_state, which is bound into the E-D4 unified state root. This
# loop runs asynchronously, not at block boundaries, so two nodes would hold different
# account_state depending on whether their loop had processed the exit yet — and the next
# block import would fail the root check. Rewards and slashing are safe here only because
# they touch the validators table alone.
#
# It was also dead code while reconstruction is on (the live configuration never reaches
# this incremental path) — but it would have come alive, and broken E-D4, the moment anyone
# switched reconstruction off. A correct refund must be applied INSIDE block application,
# like Ethereum's EIP-4895 withdrawals — which is now how principal is returned
# (qrdx/validator/withdrawals.py). This path stays disabled.
_ENFORCE_EXIT_REFUND_IN_EPOCH_LOOP = False

# Never eject down to fewer than this many active validators, whatever the stakes say. A
# liveness backstop: an empty (or one-member) active set halts the chain, and a mass
# ejection is exactly the scenario where that could happen — so if honest validators have
# all decayed together, keeping them is strictly better than halting.
_MIN_ACTIVE_AFTER_EJECTION = 3

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

# Item 3 — validators reorg-reconstruction composition fix. The incremental per-epoch mutation
# below diverges when a deposit was seen on an orphaned block (frozen schedule + topped-up stake),
# because the schedule it reads was set at import time, not re-derived from the canonical chain.
# When True (+ enforce), the loop instead REBUILDS the whole validators dynamic state as a pure
# function of the canonical chain each time finality advances (validator_reconstruction), making it
# the SINGLE writer — so it is import-history-independent and converges across nodes. This replaces
# (does not compose with) the incremental path; the reorg-path reconstruction call in node/main is
# left OFF (a second writer is exactly what diverged the first enable). Finalized-epoch state is
# immutable (the finality reorg guard refuses reorgs below it), so a full rebuild each finalized
# epoch is deterministic on every node. Gated for observe/soak before enable.
_RECONSTRUCT_VALIDATORS = True  # SOAK: fixes item-3 SCHEDULE divergence (deposited validator
# converges byte-identically both runs), but full-table convergence is blocked by a SEPARATE issue
# it surfaced — attestation_votes is not reorg-deterministic (a node had an extra epoch-0 vote → a
# one-epoch reward diff → effective_stake diverges ~20 on that node). Reconstruction reads
# attestation_votes as INPUT so it inherits that; closing item 3 fully also needs the reward input
# made deterministic (rewards from FINALIZED canonical-block attestations, or attestation_votes as a
# reorg-reconstructed domain). KEPT OFF until then; severity stays BENIGN (0 eligibility halts).


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
    # Read the refundable principals BEFORE the update flips status to 'exited'.
    refunds = (await _collect_exit_stake_refunds(db, exited)
               if enforce and _ENFORCE_EXIT_REFUND_IN_EPOCH_LOOP else {})
    res = await db.apply_epoch_validator_updates(
        rewards, penalties, activated=activated, exited=exited, activation_epoch=epoch,
        max_effective_balance=MAX_EFFECTIVE_BALANCE, enforce=enforce,
    )
    if refunds:
        await _refund_exited_validator_stakes(db, refunds, epoch)
    if enforce and _ENFORCE_STAKE_FLOOR_EJECTION:
        await _eject_validators_below_stake_floor(db, epoch)
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




async def _eject_validators_below_stake_floor(db, epoch: int, log: bool = True) -> int:
    """
    Move any ACTIVE validator whose ``effective_stake`` has fallen below
    ``VALIDATOR_EJECTION_STAKE`` to 'exiting', scheduled to leave at a deterministic
    finalized epoch.

    Runs AFTER this epoch's rewards and penalties are applied, so it reads the settled
    stake. Deterministic: a pure function of the validators table, which every node agrees
    on at a finalized epoch, plus a constant — so the table stays byte-identical and
    eligibility (enforced off that table) cannot diverge.

    Exit, not removal: the validator was inactive, not slashed, so it leaves the way a
    voluntary ``STAKE_EXIT`` does — staying eligible through unbonding and getting its
    principal back at its exit epoch. A slashed validator is already ejected by
    ``apply_epoch_slashings`` and never reaches here.

    **Liveness backstop.** Ejection is skipped entirely if it would leave fewer than
    ``_MIN_ACTIVE_AFTER_EJECTION`` active validators. An empty or near-empty active set
    halts the chain, and a mass ejection is precisely when that could happen — if every
    honest validator has decayed together, keeping them is strictly better than halting.
    Candidates are taken in canonical (lowest-stake-first, then address) order so that
    when the cap binds, every node ejects the same subset.

    Does not commit; the caller commits the epoch's writes.

    Returns the number of validators moved to 'exiting'.
    """
    from decimal import Decimal

    try:
        active = await db.get_validators(status="active")
    except Exception as e:
        logger.warning("[stake-floor] cannot read the active set: %s", e)
        return 0
    if not active:
        return 0

    def _eff(v):
        try:
            return Decimal(str(v.get("effective_stake") or v.get("stake") or 0))
        except Exception:
            return Decimal(0)

    below = [v for v in active if _eff(v) < VALIDATOR_EJECTION_STAKE]
    if not below:
        return 0

    # Canonical order: lowest stake first, address as the tie-break, so a capped
    # ejection picks the same subset on every node.
    below.sort(key=lambda v: (_eff(v), str(v.get("address"))))

    room = len(active) - _MIN_ACTIVE_AFTER_EJECTION
    if room <= 0:
        if not log:
            return 0
        logger.warning(
            "[stake-floor] %d validator(s) below the %s ejection floor at epoch %d, but "
            "the active set is only %d — keeping them: ejecting would drop below the "
            "%d-validator liveness backstop",
            len(below), VALIDATOR_EJECTION_STAKE, epoch, len(active),
            _MIN_ACTIVE_AFTER_EJECTION)
        return 0
    if len(below) > room:
        if log:
            logger.warning(
                "[stake-floor] %d validator(s) below the floor at epoch %d but only %d can "
                "be ejected without breaching the %d-validator backstop — ejecting the %d "
                "lowest-staked",
                len(below), epoch, room, _MIN_ACTIVE_AFTER_EJECTION, room)
        below = below[:room]

    exit_epoch = int(epoch) + UNBONDING_PERIOD_EPOCHS
    ejected = 0
    for v in below:
        address = v.get("address")
        if not address:
            continue
        try:
            if await db.mark_validator_exiting(address, exit_epoch=exit_epoch):
                ejected += 1
                if not log:
                    continue
                logger.warning(
                    "[stake-floor] ejecting %s at epoch %d: effective_stake %s < %s "
                    "(exiting, leaves at epoch %d)",
                    str(address)[:24], epoch, _eff(v), VALIDATOR_EJECTION_STAKE, exit_epoch)
        except Exception as e:
            logger.error("[stake-floor] could not eject %s: %s", str(address)[:24], e)
    return ejected


async def _collect_exit_stake_refunds(db, exiting_addresses) -> dict:
    """
    The staked principal to return to each validator completing its exit.

    Read BEFORE ``apply_epoch_validator_updates`` flips the rows to 'exited'.
    Refunds the deposited PRINCIPAL (``validators.stake``), not ``effective_stake``:
    effective_stake also carries accrued attestation rewards, and paying those out here
    would mint them into ``account_state`` — a supply change that is a separate
    decision. Principal-only keeps the refund exactly supply-neutral against the
    deposit's debit, so staking neither burns nor mints.

    Returns ``{address: Decimal(principal)}``, empty when validator-stake enforcement
    is off (nothing was ever debited, so nothing is owed).
    """
    from decimal import Decimal
    from ..exchange.block_processor import ENFORCE_VALIDATOR_STAKE

    if not exiting_addresses or not ENFORCE_VALIDATOR_STAKE:
        return {}

    refunds: dict = {}
    for addr in exiting_addresses:
        try:
            cur = await db.connection.execute(
                "SELECT stake FROM validators WHERE address = ?", (addr,))
            row = await cur.fetchone()
        except Exception as e:
            logger.warning("[exit-refund] cannot read stake for %s: %s", str(addr)[:20], e)
            continue
        if not row or row[0] is None:
            continue
        try:
            principal = Decimal(str(row[0]))
        except Exception:
            continue
        if principal > 0:
            refunds[addr] = principal
    return refunds


async def _refund_exited_validator_stakes(db, refunds: dict, epoch: int) -> None:
    """
    Return each completed exit's staked principal to ``account_state``.

    This is the counterpart to the STAKE_DEPOSIT debit, and this is the ONLY point at
    which it is safe: the validator has served its full unbonding period and is leaving
    the eligible set at a FINALIZED epoch, so it can no longer be slashed for anything
    it did while active. Every node runs this loop at the same finalized epoch off the
    same table, so the credit is deterministic and the ledger stays convergent.

    A SLASHED validator is never refunded — slashing moves it to status 'slashed', which
    ``get_validators_to_exit`` does not select, so its stake is forfeited. That is what
    makes the penalty real rather than a label.

    Does not commit: the caller commits the epoch's writes together.
    """
    for addr, principal in refunds.items():
        try:
            await db.apply_account_balance_delta(addr, principal)
            logger.info("[exit-refund] epoch=%d returned %s QRDX stake to %s",
                        epoch, principal, str(addr)[:20])
        except Exception as e:
            logger.error("[exit-refund] FAILED to refund %s to %s: %s",
                         principal, str(addr)[:20], e)


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
            if _RECONSTRUCT_VALIDATORS and enforce:
                # Single-writer reconstruction: rebuild the validators dynamic state from the
                # canonical chain each time finality advances (import-history-independent).
                if finalized_epoch >= 0 and finalized_epoch > last_processed:
                    from .validator_reconstruction import reconstruct_validators_live
                    await reconstruct_validators_live(db, finalized_epoch)
                    last_processed = finalized_epoch
                    vhash = await db.get_validators_table_hash()
                    logger.info(
                        "[epoch-validators RECONSTRUCT] finalized=%d validators_hash=%s",
                        finalized_epoch, vhash[:16])
            else:
                while last_processed < finalized_epoch:
                    ep = last_processed + 1
                    await apply_epoch_validator_update(db, ep, enforce)
                    last_processed = ep
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("epoch validator-update loop error: %s", e)
        await asyncio.sleep(_SLEEP)
