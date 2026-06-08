"""
Attestation block-section codec (finality, link 1).

Finality (justified/finalized checkpoints) needs attestations to propagate across
the network and become part of the canonical record. We reuse the proven
block-section pattern (cf. `qrdx.contracts.evm_block`,
`qrdx.exchange.block_processor`): a proposer attaches the attestations it holds to
the block body under a dedicated, backward-compatible key:

    block["attestations"] = [ <attestation dict>, ... ]

Importers extract + verify them and feed their local `AttestationPool`, so
attestations spread across the network via blocks (no separate gossip transport
needed) and accumulate into the per-epoch attesting stake that drives finality.

This module is the pure wire codec only — it does NOT verify signatures, select,
include, or compute finality (those are the later links). An attestation is a
small signed record; its wire form is its ``to_dict()`` and authenticity survives
the round trip because the signature is verified against the attester's public key
on the far side (see the importer, link 3).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .attestation import Attestation

BLOCK_ATTESTATIONS_KEY = "attestations"


def encode_attestations(attestations: List[Attestation]) -> List[Dict[str, Any]]:
    """Encode attestations for the block body, preserving order."""
    return [a.to_dict() for a in attestations]


def decode_attestations(items: Optional[List[Dict[str, Any]]]) -> List[Attestation]:
    """
    Decode the block-body attestation section. Missing/empty ⇒ empty list.

    Malformed entries are skipped (never raise) so a bad entry can't break import;
    a skipped attestation simply doesn't count toward finality.
    """
    if not items:
        return []
    out: List[Attestation] = []
    for item in items:
        try:
            out.append(Attestation.from_dict(item))
        except Exception:
            continue
    return out


def attestations_canonical_bytes(attestations: List[Attestation]) -> bytes:
    """
    Deterministic digest of the attestation section, for hashing / equality.

    Uses each attestation's signing root + signature in order, so any reordering
    or mutation changes the result. BLAKE3 per Whitepaper §3.6.
    """
    import blake3

    h = blake3.blake3()
    for a in attestations:
        h.update(a.signing_root)
        h.update(a.signature or b"")
    return h.digest(length=32)


def extract_attestations_from_dict(block: Dict[str, Any]) -> List[Attestation]:
    """Recover the attestation section from a serialized block dict (wire form)."""
    if not isinstance(block, dict):
        return []
    return decode_attestations(block.get(BLOCK_ATTESTATIONS_KEY))
