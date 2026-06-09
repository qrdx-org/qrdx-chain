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
        try:
            await db.record_attestation_vote(
                att.validator_address, att.target_epoch, att.source_epoch,
                att.slot, att.block_hash,
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
