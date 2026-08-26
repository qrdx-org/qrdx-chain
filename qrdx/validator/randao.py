"""
RANDAO mix accumulation (observe-first).

Proposer selection currently uses a constant all-zero RANDAO mix
(`block_verification.PROPOSER_RANDAO_MIX`), so the schedule is deterministic but
PREDICTABLE — an adversary can compute all future proposers and grind / target
them. Fixing that means folding each block proposer's RANDAO reveal into an
accumulating mix and selecting from it.

This module provides the accumulation as a **pure, deterministic function of the
canonical chain** — `mix(H) = fold(reveals of blocks 1..H)` from a fixed seed.
Two consequences make it safe to introduce ahead of wiring it into selection:

  * **Cross-node convergence is automatic.** Every node with the same canonical
    chain computes the identical mix; there is no separate transport to wire and
    no per-node accumulator state to drift.
  * **Reorg safety is automatic.** The mix is recomputed from the (new) canonical
    blocks, so orphaned reveals simply vanish — no rollback bookkeeping.

OBSERVE phase: nothing here changes proposer selection yet (selection still uses
the zero constant). It exposes the would-be mix so its cross-node consistency can
be confirmed before a later increment switches selection over (the same
observe→soak→enforce discipline used for finality + the unified state root).

ENFORCE GATE (found in the observe phase, 2026-06-14): the mix folds EVERY
historical block's reveal, so it is sensitive to block-level history divergence
that the cumulative *state* roots mask. A 4-node run that converged on one
unified state root nonetheless showed one node on a different block at height 2
(an equivalent-state fork at a genesis-slot proposer race that never reconciled,
since reorg has no incentive to switch between equal-length/equal-state chains).
Folding that node's divergent reveal yields a different mix. Therefore RANDAO must
NOT drive proposer selection until block history converges to a single canonical
block per height (e.g. a canonical-block tie-break, or the finality reorg guard
extended to reconcile equivalent-state forks). Enforcing selection on a diverged
mix would make that node compute a different proposer → eligibility mismatch →
its blocks rejected. The observe phase exists precisely to catch this.

O(H) per call today; an incremental persisted running-mix is a later optimization.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Optional

from ..constants import DOMAIN_RANDAO, SLOTS_PER_EPOCH

logger = logging.getLogger(__name__)

# Lookback (in blocks) for the proposer-selection CHECKPOINT mix. ~1 epoch of blocks —
# below the observed tip-fork depth (≤4 from the fork-choice observe), so the checkpoint
# height is SETTLED (all nodes agree on it), while keeping proposers unpredictable until
# ~1 epoch out. This is the cross-time-stable selection input (see checkpoint_mix_for_block).
RANDAO_SELECTION_LOOKBACK = SLOTS_PER_EPOCH

# Lookback (in EPOCHS) for the per-epoch selection checkpoint (epoch_checkpoint_mix /
# selection_mix_for_slot) — the selection boundary is the end of epoch(S)-LOOKBACK, settled
# below the tip-fork depth so all validators agree on a slot's proposer regardless of tip.
# NOTE: widening this to 2 did NOT cure the enforce liveness dip (a lookback=2 soak run hit
# 81% / block 49 — worse), so the dip is not reorg-boundary instability; kept at 1.
RANDAO_SELECTION_LOOKBACK_EPOCHS = 1

# Size of the per-slot ELIGIBLE proposer set under enforced RANDAO selection: the primary
# plus (K-1) deterministic backups. Any of the K may validly propose the slot (primary
# first; a backup fills in if the primary misses), so one slow/offline validator doesn't
# leave a slot unproposed — the liveness layer that the single-eligible-proposer soak needed.
RANDAO_PROPOSER_ELIGIBLE_K = 2

# ENFORCE gate (observe→soak→enforce; default OFF = zero mix = today's behaviour). When
# True, ALL proposer-selection sites compute the height-checkpoint mix instead of the zero
# constant: manager.is_proposer + manager.validate_block (via manager._selection_mix) and
# block_verification.verify_proposer_eligibility.
#
# Selection keys off the SLOT's EPOCH (selection_mix_for_slot → epoch_checkpoint_mix) — a
# per-epoch checkpoint that is TIP-INDEPENDENT, so validators a block apart still agree on a
# slot's proposer. (An earlier HEIGHT-based version keyed off next_block_id and HALTED the
# chain — tip-dependent.)
#
# STILL OFF, but the CONSENSUS is now SOLVED — the residual is a testnet-scale/harness matter,
# not a correctness bug (diagnosed 2026-08-26; see docs item 5).
#
# A K=1 and a K=2 enforce diagnostic (3 runs each) established:
#   • SAFE + CONVERGENT: 0 "not eligible" rejects in ANY run (selection is stable network-wide),
#     and with K=2 the per-node final-height spread was 0–1 (block history converges TIGHTLY —
#     the old K=2 reorg churn is GONE, fixed by this session's reorg-safety work: the equal-tip
#     divergence fix 9649931 + bulk-sync trust-replay 800f614). So enforce does NOT halt or
#     diverge — the reason it was gated.
#   • The ONLY residual is THROUGHPUT variance: with 3 validators + a 2s slot, the single
#     eligible proposer occasionally misses its short slot → fewer blocks. K=2 backups recover
#     most of it (2/3 runs 17/17, ~110 blocks) but 1/3 dipped (81 blocks) and timed out two
#     THROUGHPUT-heavy scenarios (s13/s14) — a scenario-timeout artifact (the chain converged
#     fine, spread 0), NOT a consensus failure.
# So RANDAO selection is production-correct + safe; enabling it just needs a config where its
# proposer variance doesn't starve throughput: a production-scale validator set (variance
# averages out) OR a slot sized above worst-case block-production time OR throughput-tolerant
# (convergence-polled, not fixed-attempt) integration scenarios. Kept OFF only to avoid a
# ~1/3-flaky CI on the small testnet. K=2 retained (strictly better than K=1, neutral when off).
ENFORCE_RANDAO_SELECTION = False

# Genesis seed for the fold. Equal to the current constant proposer mix, so the
# accumulated mix at height 0 (no reveals) reproduces today's selection input —
# the switch-over increment can then move selection onto the live mix cleanly.
RANDAO_SEED = b"\x00" * 32


def _mix_in(mix: bytes, reveal: bytes) -> bytes:
    """Fold one proposer reveal into the running mix (domain-separated BLAKE-free
    SHA-256 to match `consensus.compute_new_randao_mix`'s hash family)."""
    return hashlib.sha256(DOMAIN_RANDAO + mix + reveal).digest()


def _extract_reveal(block: dict) -> Optional[bytes]:
    """The proposer's RANDAO reveal from a stored block, or None if absent/empty."""
    from .block_verification import _parse_block_content
    content = block.get("content") or block.get("block_content")
    if not content:
        return None
    try:
        bc = _parse_block_content(content)
    except Exception:
        return None
    hexrev = bc.get("randao_reveal")
    if not hexrev:
        return None
    try:
        raw = bytes.fromhex(hexrev)
    except (ValueError, TypeError):
        return None
    return raw or None


async def compute_randao_mix(db: Any, up_to_height: Optional[int] = None) -> bytes:
    """
    The accumulated RANDAO mix after folding every canonical block's reveal in
    height order, from genesis up to ``up_to_height`` (default: current tip).

    Pure function of the canonical chain → identical on every node, reorg-safe.
    Blocks without a reveal (e.g. genesis) are skipped. Returns the 32-byte mix.
    """
    if up_to_height is None:
        try:
            up_to_height = (await db.get_next_block_id()) - 1
        except Exception:
            return RANDAO_SEED

    mix = RANDAO_SEED
    folded = 0
    for height in range(0, up_to_height + 1):
        try:
            block = await db.get_block_by_id(height)
        except Exception:
            block = None
        if not block:
            continue
        reveal = _extract_reveal(block)
        if reveal is None:
            continue
        mix = _mix_in(mix, reveal)
        folded += 1
    logger.debug("compute_randao_mix: folded %d reveal(s) up to height %s", folded, up_to_height)
    return mix


async def checkpoint_mix_for_block(db: Any, height: int, lookback: Optional[int] = None) -> bytes:
    """The deterministic RANDAO CHECKPOINT mix for selecting the proposer of the block at
    ``height``: the mix folded up to ``height - lookback``.

    A fixed function of the block's OWN height (not of wall-clock finality), so the proposer
    building H and every importer verifying H fold the identical prefix → the SAME mix
    regardless of WHEN (cross-time stable). With ``lookback`` ~1 epoch the checkpoint height
    sits below the churning tip, so all nodes agree on that prefix (cross-node stable). Early
    blocks (height ≤ lookback) use the seed. This is the enforce-ready selection input;
    proposer selection still uses the zero constant until ``_ENFORCE_RANDAO_SELECTION`` flips
    the proposer + verifier together. See docs/CONSENSUS_REMAINING_WORK.md item 5."""
    if lookback is None:
        lookback = RANDAO_SELECTION_LOOKBACK
    cp = int(height) - int(lookback)
    if cp < 0:
        return RANDAO_SEED
    return await compute_randao_mix(db, cp)


async def _block_slot(db: Any, height: int) -> Optional[int]:
    """The slot of the block at ``height`` (parsed from its content), or None."""
    from .block_verification import _parse_block_content
    try:
        b = await db.get_block_by_id(height)
    except Exception:
        b = None
    if not b:
        return None
    try:
        bc = _parse_block_content(b.get("content") or b.get("block_content") or "{}")
        s = bc.get("slot")
        return int(s) if s is not None else None
    except Exception:
        return None


async def _boundary_height_for_slot(db: Any, boundary_slot: int) -> int:
    """Highest block height whose slot is < ``boundary_slot``. Block slot is strictly
    increasing with height on any single chain (each block is proposed at a later slot
    than its parent), so a binary search over heights is correct and O(log n). Returns -1
    if no such block."""
    try:
        tip = (await db.get_next_block_id()) - 1
    except Exception:
        return -1
    lo, hi, ans = 0, tip, -1
    while lo <= hi:
        mid = (lo + hi) // 2
        s = await _block_slot(db, mid)
        if s is None:
            hi = mid - 1  # missing/unparseable → search lower (conservative)
            continue
        if s < boundary_slot:
            ans = mid
            lo = mid + 1
        else:
            hi = mid - 1
    return ans


async def epoch_checkpoint_mix(db: Any, epoch: int, lookback_epochs: int = 1) -> bytes:
    """The proposer-selection RANDAO mix for slots in ``epoch``: the mix folded up to the
    LAST block of epoch ``epoch - lookback_epochs``.

    Keyed off the EPOCH (a fixed function of the slot), NOT a node's current height — so it
    is TIP-INDEPENDENT: validators a block apart still compute the identical mix for the same
    slot (the flaw the height-based `checkpoint_mix_for_block` had, which halted the chain in
    the 2026-06-28 trial). The checkpoint epoch ended ``lookback_epochs`` epochs ago → settled
    below the fork tip → all nodes agree (cross-node) and it does not move over time
    (cross-time). Early epochs (≤ lookback) use the seed. See docs item 5 ("Corrected design").
    """
    cp_epoch = int(epoch) - int(lookback_epochs)
    if cp_epoch < 0:
        return RANDAO_SEED
    boundary_slot = (cp_epoch + 1) * SLOTS_PER_EPOCH  # first slot of cp_epoch+1
    h = await _boundary_height_for_slot(db, boundary_slot)
    if h < 0:
        return RANDAO_SEED
    return await compute_randao_mix(db, h)


async def selection_mix_for_slot(db: Any, slot: int,
                                 lookback_epochs: int = RANDAO_SELECTION_LOOKBACK_EPOCHS) -> bytes:
    """The proposer-selection mix for a given SLOT = `epoch_checkpoint_mix(epoch(slot))`.
    The SINGLE entry point used by both the proposer (`manager._selection_mix`) and the
    importer (`verify_proposer_eligibility`), so the slot→epoch conversion uses ONE
    `SLOTS_PER_EPOCH` (this module's) — a proposer/verifier mismatch there would halt."""
    return await epoch_checkpoint_mix(db, int(slot) // SLOTS_PER_EPOCH, lookback_epochs)
