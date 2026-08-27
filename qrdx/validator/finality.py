"""
Finality computation (links 2–4, OBSERVE-only).

Every node records the attestation votes carried in imported block bodies, then
derives justified/finalized epochs from the accumulated per-epoch attesting stake
— the Casper-FFG idea, simplified:

  * **justified(E)**  — ≥ 2/3 of total validator stake cast an attestation whose
    *target* is epoch E.
  * **finalized(E)**  — E is justified AND E+1 is justified (consecutive
    justification finalizes the earlier epoch).

This is OBSERVE-only: it computes + persists finality so `get_pos_chain_head`
reports a real finalized boundary, but nothing consumes it for fork-choice or
E-D4 sync enforcement yet (that is the later, behaviour-changing link). Computing
from the DB (not an in-memory pool) means full nodes derive the same finality as
validators.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, Tuple

from ..constants import SLOTS_PER_EPOCH, ATTESTATION_THRESHOLD
from ..logger import get_logger
from .attestation_block import extract_attestations_from_dict

logger = get_logger(__name__)

# ── Surround/double-vote slashing DETECTION gate (observe-first) ──────────────────────────────
# When an imported attestation conflicts (double- or surround-vote) with a vote this node has
# already retained for the same validator, we build SELF-VALIDATING evidence (the two signed
# attestations + the offender's pubkey — the enforce-ready proof from slashing_block). Because
# `_ENFORCE_SLASHING` is already True, RECORDING that evidence would immediately enforce the 50%
# +eject penalty. So detection is OBSERVE-gated: with the flag False we detect + WARN but do NOT
# record, so an honest-network soak can prove zero false positives before we flip it. Honest
# validators attest once per target and never surround, so a true detection means a real offence.
_ENFORCE_SURROUND_DETECTION = False


async def _detect_attestation_equivocation(db, new_att, pub: bytes) -> bool:
    """Compare a freshly-verified attestation against the validator's RETAINED votes; on a genuine
    double/surround conflict, build self-validating evidence and (when enforce-gated on) record it
    as a SURROUND_VOTE slashing_event so it rides the chain to every node. Returns True if a
    conflict was detected. Best-effort — never raises into the import path."""
    from .slashing_block import attestation_equivocation, make_attestation_evidence
    try:
        new_dict = new_att.to_dict()
        for stored in await db.get_validator_votes(new_att.validator_address):
            if attestation_equivocation(new_dict, stored) is None:
                continue
            ev = make_attestation_evidence(new_dict, stored, pub.hex())
            logger.warning(
                "SLASHABLE attestation-equivocation DETECTED for %s (%s) — targets %s/%s%s",
                new_att.validator_address, ev.get("detected_kind"),
                new_dict.get("target_epoch"), stored.get("target_epoch"),
                "" if _ENFORCE_SURROUND_DETECTION else " [observe: not recorded]")
            if _ENFORCE_SURROUND_DETECTION:
                await db.record_slashing_event(
                    ev["proposer"], ev["condition"], int(ev["slot"]), int(ev["epoch"]),
                    __import__("json").dumps(ev))
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
                att.validator_address, att.target_epoch, att.source_epoch,
                att.slot, att.block_hash,
                epoch=att.epoch, validator_index=att.validator_index,
                signature=att.signature.hex(),
            )
            recorded += 1
        except Exception:
            continue
    return recorded


async def update_finality(db) -> Dict[str, int]:
    """
    Recompute justified/finalized for every epoch that has votes and persist it.
    Returns ``{"justified_epoch": j, "finalized_epoch": f}`` (highest of each, or
    -1 if none). Idempotent and cheap; safe to call after each block import.
    """
    stakes, _keys = await _validator_stakes_and_keys(db)
    total = sum(stakes.values()) if stakes else Decimal(0)
    if total <= 0:
        return {"justified_epoch": -1, "finalized_epoch": -1}

    try:
        cur = await db.connection.execute(
            "SELECT DISTINCT target_epoch FROM attestation_votes ORDER BY target_epoch ASC")
        epochs = [int(r[0]) for r in await cur.fetchall()]
    except Exception:
        epochs = []

    justified: Dict[int, bool] = {}
    for e in epochs:
        attesters = await db.get_epoch_attesters(e)
        attesting = sum(stakes.get(a, Decimal(0)) for a in attesters)
        justified[e] = (attesting / total) >= ATTESTATION_THRESHOLD

    max_j = max((e for e, j in justified.items() if j), default=-1)
    max_f = -1
    for e in epochs:
        # FFG: E finalizes when E and E+1 are both justified.
        finalized = justified.get(e, False) and justified.get(e + 1, False)
        if justified.get(e, False) or finalized:
            await db.set_epoch_finality(
                e, e * SLOTS_PER_EPOCH, (e + 1) * SLOTS_PER_EPOCH - 1,
                justified=justified.get(e, False), finalized=finalized,
            )
        if finalized:
            max_f = max(max_f, e)

    if max_f >= 0:
        logger.info(f"[finality] justified_epoch={max_j} finalized_epoch={max_f}")
    return {"justified_epoch": max_j, "finalized_epoch": max_f}


async def finalized_block_height(db) -> int:
    """
    Deepest block height that is irreversibly finalized: the greatest height H such
    that validators holding ≥ 2/3 of total stake have each attested to a CANONICAL
    block at height ≥ H. Reverting below H would require > 1/3 of stake to have
    attested deeper than the canonical chain supports — i.e. to have equivocated
    (slashable) — so it is safe for fork-choice to refuse reorgs below H (link 5).

    Stake-weighted depth (not same-block supermajority): validators attest to their
    own heads, which differ by propagation timing, so requiring ≥2/3 on the *same*
    block_hash almost never holds. The 2/3-deep height is well-defined whenever
    enough stake has attested to canonical blocks. Returns -1 if unreached.
    OBSERVE foundation — only computes the boundary; nothing consumes it yet.
    """
    stakes, _keys = await _validator_stakes_and_keys(db)
    total = sum(stakes.values()) if stakes else Decimal(0)
    if total <= 0:
        return -1

    try:
        cur = await db.connection.execute(
            "SELECT validator_address, block_hash FROM attestation_votes")
        rows = await cur.fetchall()
    except Exception:
        return -1

    # Each validator's DEEPEST attested canonical height (skip non-canonical hashes).
    height_cache: Dict[str, int] = {}
    deepest: Dict[str, int] = {}
    for addr, block_hash in rows:
        if block_hash not in height_cache:
            try:
                c = await db.connection.execute(
                    "SELECT block_height FROM blocks WHERE block_hash = ?", (block_hash,))
                r = await c.fetchone()
                height_cache[block_hash] = int(r[0]) if r and r[0] is not None else -1
            except Exception:
                height_cache[block_hash] = -1
        h = height_cache[block_hash]
        if h >= 0 and (addr not in deepest or h > deepest[addr]):
            deepest[addr] = h
    if not deepest:
        return -1

    # Walk validators from deepest height down, accumulating stake; the height at
    # which cumulative stake first reaches ≥2/3 is the finalized boundary.
    cumulative = Decimal(0)
    for addr, h in sorted(deepest.items(), key=lambda kv: kv[1], reverse=True):
        cumulative += stakes.get(addr, Decimal(0))
        if (cumulative / total) >= ATTESTATION_THRESHOLD:
            return h
    return -1


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
