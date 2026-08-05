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
