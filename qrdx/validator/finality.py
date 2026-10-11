"""
Finality: the entry points the node calls, and attestation-vote recording.

The rules — Casper FFG over checkpoint-bound votes taken from canonical blocks — are in
qrdx/validator/ffg.py: ``update_finality`` and ``finalized_block_height`` delegate there.

What stays here is each node's ``attestation_votes`` table: every verified vote it has seen in
an imported block, which equivocation detection compares new votes against (a double or
surround vote becomes slashing evidence that rides the chain).
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, Tuple

from ..logger import get_logger
from .attestation_block import extract_attestations_from_dict

logger = get_logger(__name__)

# ── Surround/double-vote slashing DETECTION gate (observe-first) ──────────────────────────────
# When an imported attestation conflicts (double- or surround-vote) with a vote this node has
# already retained for the same validator, we build SELF-VALIDATING evidence (the two signed
# attestations + the offender's pubkey — the enforce-ready proof from slashing_block). Because
# `_ENFORCE_SLASHING` is already True, RECORDING that evidence would immediately enforce the 50%
# +eject penalty. ENABLED (2026-08-27): the corrected SLOT-keyed rule (see attestation_equivocation)
# is false-positive-free by CONSTRUCTION — an honest validator attests exactly once per slot, so a
# same-slot/different-head pair is impossible without malicious software, and honest source/target
# spans are width-1 so they can never surround. Empirically confirmed by 4 honest --force soaks
# (2 heavy-churn, ~100+ reorgs/node): 18/18, converged, ZERO detections + ZERO slashing_events on
# every node. (The earlier enable that misfired used the OLD target-keyed rule; a clean-only soak
# had masked it — hence the two-heavy-churn bar here, matching DOUBLE_SIGN's enable evidence.)
_ENFORCE_SURROUND_DETECTION = True


async def _detect_attestation_equivocation(db, new_att, pub: bytes) -> bool:
    """Compare a freshly-verified attestation against the validator's RETAINED votes; on a genuine
    double/surround conflict, build self-validating evidence and (when enforce-gated on) record it
    as a SURROUND_VOTE slashing_event so it rides the chain to every node. Returns True if a
    conflict was detected. Best-effort — never raises into the import path."""
    from .slashing_block import (
        attestation_equivocation,
        make_attestation_evidence,
        verify_attestation_evidence,
    )

    try:
        new_dict = new_att.to_dict()
        for stored in await db.get_validator_votes(new_att.validator_address):
            if attestation_equivocation(new_dict, stored) is None:
                continue
            ev = make_attestation_evidence(new_dict, stored, pub.hex())
            ok, why = verify_attestation_evidence(ev)
            if not ok:
                # Never record what does not prove itself: every node verifies carried evidence
                # the same way, and a local record that others reject slashes on one node only.
                logger.debug("attestation conflict not provable, ignored: %s", why)
                continue
            logger.warning(
                "SLASHABLE attestation-equivocation DETECTED for %s (%s) — targets %s/%s%s",
                new_att.validator_address,
                ev.get("detected_kind"),
                new_dict.get("target_epoch"),
                stored.get("target_epoch"),
                "" if _ENFORCE_SURROUND_DETECTION else " [observe: not recorded]",
            )
            if _ENFORCE_SURROUND_DETECTION:
                await db.record_slashing_event(
                    ev["proposer"],
                    ev["condition"],
                    int(ev["slot"]),
                    int(ev["epoch"]),
                    __import__("json").dumps(ev),
                )
            return True
    except Exception as e:
        logger.debug("attestation-equivocation detection skipped: %s", e)
    return False


async def _validator_stakes_and_keys(db) -> Tuple[Dict[str, Decimal], Dict[str, bytes]]:
    """{address: effective_stake} and {address: public_key_bytes} from the
    consistent `validators` table (same source as proposer selection/eligibility)."""
    stakes: Dict[str, Decimal] = {}
    keys: Dict[str, bytes] = {}
    try:
        for r in await db.get_validators():
            addr = r.get("address")
            if not addr or str(r.get("status", "active")).upper() not in ("ACTIVE", "PENDING"):
                continue
            stakes[addr] = Decimal(str(r.get("effective_stake") or r.get("stake") or 0))
            pk = r.get("public_key")
            if pk:
                try:
                    keys[addr] = bytes.fromhex(pk) if isinstance(pk, str) else bytes(pk)
                except Exception:
                    pass
    except Exception as e:
        logger.debug("finality: could not load validators: %s", e)
    return stakes, keys


async def record_block_attestations(db, block: Dict[str, Any]) -> int:
    """
    Record the attestation votes carried in an imported block (verifying each
    against the attester's public key from the `validators` table). Returns the
    number of new votes recorded. Best-effort: bad/unknown/duplicate attestations
    are skipped, never raised.
    """
    attestations = extract_attestations_from_dict(block)
    if not attestations:
        return 0
    _stakes, keys = await _validator_stakes_and_keys(db)
    recorded = 0
    for att in attestations:
        pub = keys.get(att.validator_address)
        if not pub:
            continue  # unknown validator — cannot verify
        try:
            if not att.verify(pub):
                continue
        except Exception:
            continue
        # Compare against retained votes BEFORE recording — a double-vote is same-target, and
        # the INSERT OR IGNORE below keeps only the first per target, so the conflict must be
        # caught here (the incoming vote isn't stored yet, so we compare it vs the retained one).
        try:
            await _detect_attestation_equivocation(db, att, pub)
        except Exception:
            pass
        try:
            await db.record_attestation_vote(
                att.validator_address,
                att.target_epoch,
                att.source_epoch,
                att.slot,
                att.block_hash,
                epoch=att.epoch,
                validator_index=att.validator_index,
                signature=att.signature.hex(),
                source_root=att.source_root,
                target_root=att.target_root,
            )
            recorded += 1
        except Exception:
            continue
    return recorded


async def update_finality(db) -> Dict[str, int]:
    """Recompute justified/finalized checkpoints and persist them: Casper FFG over the votes
    canonical blocks carry (qrdx/validator/ffg.py). Returns
    ``{"justified_epoch": j, "finalized_epoch": f}``. Cheap: it resumes from the last finalized
    checkpoint. Safe to call after every block.

    (It used to justify an epoch on 2/3 of *any* votes for it, whichever branch they were for —
    so a long fork finalized on both sides. See docs/KNOWN_ISSUES.md.)"""
    from .ffg import update

    return await update(db)


async def finalized_block_height(db) -> int:
    """Height of the finalized checkpoint's block: nothing at or below it is ever reorged.
    (It used to be "the height 2/3 of the stake had attested at least as deep", which honest
    validators switching forks could reach on both sides.)"""
    from .ffg import finalized_height

    return await finalized_height(db)


async def record_finality_from_block(db, block_content) -> Dict[str, int]:
    """
    Convenience entry point for the block produce/import paths: parse a block's
    serialized content (``str(PoSBlock.to_dict())``), record its attestation
    votes, and recompute finality. Best-effort — never raises into the caller.
    """
    try:
        from .block_verification import _parse_block_content

        bc = _parse_block_content(block_content)
        if not isinstance(bc, dict):
            return {}
        await record_block_attestations(db, bc)
        # Record any DOUBLE_SIGN evidence the block carries (deterministic on every node) so the
        # finalized-epoch slash can be enforced off identical slashing_events. Self-verifying.
        try:
            from .slashing_block import record_block_slashing_evidence

            await record_block_slashing_evidence(db, bc)
        except Exception as e:
            logger.debug("finality: slashing-evidence record skipped: %s", e)
        return await update_finality(db)
    except Exception as e:
        logger.debug("finality: record_from_block skipped: %s", e)
        return {}
