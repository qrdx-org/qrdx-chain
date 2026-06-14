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

from ..constants import DOMAIN_RANDAO

logger = logging.getLogger(__name__)

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
