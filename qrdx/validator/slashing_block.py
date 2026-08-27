"""
Slashing evidence in block bodies — the deterministic transport that makes slashing
ENFORCEABLE (validator-slashing subsystem, enforce prerequisite).

The finalized-epoch slash (``epoch_loop.apply_epoch_slashings``) reduces effective_stake and
EJECTS the offender (status='slashed'), mutating the validators-table hash + the eligible set.
So it can only be enforced if EVERY node holds the SAME evidence by that epoch — otherwise
nodes disagree on who is eligible and a divergent-set halt follows (the exact failure the
convergence work avoids). Local detection via the p2p equal-height fork is eventually-
consistent gossip; the deterministic source of truth is the CANONICAL CHAIN. So — exactly like
attestations (see ``attestation_block``) — a proposer includes pending DOUBLE_SIGN evidence in
the block body, and every importer VERIFIES it self-containedly and records it, giving all nodes
identical ``slashing_events``. Only then is the penalty a pure function of the chain.

A DOUBLE_SIGN proof carries the two conflicting SIGNED block headers. ``verify_double_sign_
evidence`` validates it with NO external state: both headers are validly Dilithium-signed by
their claimed proposer (via ``verify_pos_block_proposer``), share the proposer + slot, and have
different hashes → the eligible proposer signed two blocks for its slot (slashable). Two DISTINCT
proposers at adjacent slots (the benign equal-height race) fail the same-proposer check, so they
can never be smuggled in as a slash.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .block_verification import verify_pos_block_proposer

# Block-body key carrying the slashing-evidence section (parallels BLOCK_ATTESTATIONS_KEY).
BLOCK_SLASHING_KEY = "slashing_evidence"


def make_double_sign_evidence(header_a: Dict[str, Any], header_b: Dict[str, Any]) -> Dict[str, Any]:
    """Build a canonical DOUBLE_SIGN evidence dict from two signed block-content headers.

    The two headers are ordered by hash so the evidence is byte-identical regardless of which
    block a node saw first — the same offence yields the same evidence on every node
    (deterministic, so ``INSERT OR IGNORE`` on (validator, slot, condition) dedups cleanly)."""
    ha = str(header_a.get("hash") or header_a.get("block_hash") or "")
    hb = str(header_b.get("hash") or header_b.get("block_hash") or "")
    if ha > hb:
        header_a, header_b = header_b, header_a
    return {
        "condition": "double_sign",
        "proposer": header_a.get("proposer_address"),
        "slot": header_a.get("slot"),
        "epoch": header_a.get("epoch"),
        "header_a": header_a,
        "header_b": header_b,
    }


def verify_double_sign_evidence(evidence: Dict[str, Any]) -> Tuple[bool, str]:
    """Self-validate a DOUBLE_SIGN proof with NO external state. Returns ``(ok, error)``.

    Slashable iff the two carried headers are each validly signed by the SAME proposer for the
    SAME slot with DIFFERENT hashes. A malicious proposer cannot fabricate a slash for an honest
    validator: it would need that validator's Dilithium signature over two distinct blocks."""
    if not isinstance(evidence, dict):
        return False, "evidence is not a dict"
    ha = evidence.get("header_a")
    hb = evidence.get("header_b")
    if not isinstance(ha, dict) or not isinstance(hb, dict):
        return False, "evidence missing header_a/header_b"
    pa = ha.get("proposer_address")
    pb = hb.get("proposer_address")
    if not pa or pa != pb:
        return False, "headers have absent/different proposers (not a double-sign)"
    if ha.get("slot") is None or ha.get("slot") != hb.get("slot"):
        return False, "headers are for different slots"
    hash_a = ha.get("hash") or ha.get("block_hash")
    hash_b = hb.get("hash") or hb.get("block_hash")
    if not hash_a or not hash_b or hash_a == hash_b:
        return False, "headers have equal/absent hashes (not conflicting)"
    ok_a, err_a = verify_pos_block_proposer(ha, pa)
    if not ok_a:
        return False, f"header_a signature invalid: {err_a}"
    ok_b, err_b = verify_pos_block_proposer(hb, pb)
    if not ok_b:
        return False, f"header_b signature invalid: {err_b}"
    return True, ""


def decode_slashing_evidence(items: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Normalize a block's slashing-evidence section to a list of dicts (empty if absent)."""
    return [e for e in items if isinstance(e, dict)] if isinstance(items, list) else []


def extract_slashing_evidence_from_dict(block: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pull the slashing-evidence section from a parsed block dict (empty if none)."""
    if not isinstance(block, dict):
        return []
    return decode_slashing_evidence(block.get(BLOCK_SLASHING_KEY))


def attestation_equivocation(a: Dict[str, Any], b: Dict[str, Any]) -> Optional[str]:
    """Casper FFG attestation-slashing relationship between two attestations BY THE SAME
    validator, or None if they don't conflict:
      - 'double_vote'   : same target_epoch, DIFFERENT block_hash (two blocks for one target).
      - 'surround_vote' : one's (source,target) span STRICTLY surrounds the other's.
    Requires the two to be distinct (different block_hash or different epochs). An honest
    validator makes at most one attestation per target and never surrounds, so neither fires on
    honest voting."""
    try:
        sa, ta = int(a["source_epoch"]), int(a["target_epoch"])
        sb, tb = int(b["source_epoch"]), int(b["target_epoch"])
    except (KeyError, TypeError, ValueError):
        return None
    ha, hb = a.get("block_hash"), b.get("block_hash")
    if ta == tb and ha != hb:
        return "double_vote"
    if (sa < sb and ta > tb) or (sb < sa and tb > ta):
        return "surround_vote"
    return None


def make_attestation_evidence(att_a: Dict[str, Any], att_b: Dict[str, Any],
                              public_key_hex: str) -> Dict[str, Any]:
    """Build canonical attestation-equivocation evidence: the two conflicting attestation dicts
    plus the offending validator's public key (attestations carry no pubkey, so — like a
    DOUBLE_SIGN proof's proposer_public_key — the pubkey rides the evidence so importers can
    verify with no external state). Ordered by (target_epoch, block_hash) for determinism."""
    if (int(att_a.get("target_epoch", 0)), str(att_a.get("block_hash", ""))) > \
       (int(att_b.get("target_epoch", 0)), str(att_b.get("block_hash", ""))):
        att_a, att_b = att_b, att_a
    # Record under SURROUND_VOTE (the 50% attestation-equivocation SlashingConditions) for BOTH
    # double- and surround-votes — they are the same offence class + penalty; the precise kind is
    # inferable from the two attestations. detected_kind is kept for logs/clarity.
    return {
        "condition": "surround_vote",
        "detected_kind": attestation_equivocation(att_a, att_b) or "surround_vote",
        "proposer": att_a.get("validator_address"),
        "slot": min(int(att_a.get("slot", 0)), int(att_b.get("slot", 0))),
        "epoch": min(int(att_a.get("target_epoch", 0)), int(att_b.get("target_epoch", 0))),
        "public_key": public_key_hex,
        "att_a": att_a,
        "att_b": att_b,
    }


def verify_attestation_evidence(evidence: Dict[str, Any]) -> Tuple[bool, str]:
    """Self-validate an attestation-slashing proof with NO external state. Slashable iff the two
    carried attestations are each validly Dilithium-signed by the SAME validator (whose pubkey,
    carried in the evidence, derives to their validator_address) and they form a double/surround
    vote. A malicious proposer cannot fabricate one for an honest validator — it would need that
    validator's signature over two conflicting attestations."""
    from .attestation import Attestation
    from ..crypto.pq.dilithium import PQPublicKey
    a, b = evidence.get("att_a"), evidence.get("att_b")
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False, "evidence missing att_a/att_b"
    va, vb = a.get("validator_address"), b.get("validator_address")
    if not va or va != vb:
        return False, "attestations are from different/absent validators"
    cond = attestation_equivocation(a, b)
    if cond is None:
        return False, "attestations do not conflict (not a double/surround vote)"
    pub_hex = evidence.get("public_key")
    if not pub_hex:
        return False, "evidence missing validator public_key"
    try:
        pub = bytes.fromhex(pub_hex)
        if PQPublicKey.from_bytes(pub).to_address() != va:
            return False, "public_key does not derive to the validator address"
    except Exception as e:
        return False, f"bad validator public_key: {e}"
    try:
        if not Attestation.from_dict(a).verify(pub):
            return False, "att_a signature invalid"
        if not Attestation.from_dict(b).verify(pub):
            return False, "att_b signature invalid"
    except Exception as e:
        return False, f"attestation verification error: {e}"
    return True, ""


async def record_block_slashing_evidence(db, block: Dict[str, Any]) -> int:
    """Record the DOUBLE_SIGN evidence carried in an imported block — the RECEIVING side of the
    block-body transport, run on EVERY node from the shared produce/import hook so all nodes end
    up with identical ``slashing_events`` (the determinism the finalized-epoch penalty needs).

    Each proof is VERIFIED self-containedly before recording (``verify_double_sign_evidence``),
    so a malicious proposer cannot record a fabricated slash for an honest validator — the proof
    would need that validator's signature over two blocks. ``record_slashing_event`` is
    INSERT-OR-IGNORE on (validator, slot, condition), so re-inclusion across blocks is a harmless
    no-op. Best-effort: a bad proof is skipped, never raised. Returns the count newly recorded."""
    import json
    from ..constants import SLOTS_PER_EPOCH
    evidence_list = extract_slashing_evidence_from_dict(block)
    if not evidence_list:
        return 0
    recorded = 0
    for ev in evidence_list:
        cond = str(ev.get("condition", "double_sign"))
        # Dispatch verification by condition — each proof self-validates (no external state), so a
        # malicious proposer can never record a fabricated slash for an honest validator.
        if cond in ("surround_vote", "double_vote"):
            ok, _err = verify_attestation_evidence(ev)
        else:
            ok, _err = verify_double_sign_evidence(ev)
        if not ok:
            continue  # unverifiable proof — never record
        proposer = ev.get("proposer") or (ev.get("header_a") or {}).get("proposer_address")
        slot = ev.get("slot")
        if slot is None:
            slot = (ev.get("header_a") or {}).get("slot")
        if not proposer or slot is None:
            continue
        epoch = ev.get("epoch")
        if epoch is None:
            epoch = int(slot) // SLOTS_PER_EPOCH
        try:
            new = await db.record_slashing_event(
                proposer, str(ev.get("condition", "double_sign")),
                int(slot), int(epoch), json.dumps(ev))
            if new:
                recorded += 1
        except Exception:
            continue
    return recorded
