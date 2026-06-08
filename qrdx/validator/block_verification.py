"""
PoS block proposer authentication for the import path.

Until now the import paths (sync, p2p `submitBlock`, REST `/submit_block`) accepted
any height-correct block whose claimed ``proposer_address`` merely existed in the
validator table — the proposer's Dilithium signature was never verified, and
``validate_pos_block`` was dead code. This module provides the missing check.

``verify_pos_block_proposer`` authenticates that a block was genuinely produced by
the validator it claims, by:

  1. **Identity binding** — deriving the 0xPQ address from the block's carried
     ``proposer_public_key`` and requiring it to equal ``validator_address``. This
     closes the impersonation vector: you cannot claim a victim validator's
     address with your own key.
  2. **Signature** — reconstructing the proposer's ``signing_root`` from the
     block's own header fields (the exact bytes ``PoSBlock.signing_root`` signs)
     and verifying the Dilithium signature over it with that public key.

This is *authenticity* only — it does NOT enforce slot-proposer eligibility (which
validator is scheduled for the slot). That is intentionally separate: the network
runs validators that produce competing blocks at the tip, all of which are validly
signed by their respective proposers, so authenticity verification accepts them
and does not harm liveness. Slot-eligibility + RANDAO + attestation checks
(`consensus.validate_pos_block`) are a heavier, liveness-sensitive follow-up.
"""

from __future__ import annotations

import ast
import hashlib
from typing import Any, Dict, Tuple

from ..logger import get_logger

logger = get_logger(__name__)

# Header fields the proposer signs (see manager.PoSBlock.signing_root).
_SIGNING_FIELDS = (
    "number", "parent_hash", "state_root", "transactions_root",
    "timestamp", "slot", "epoch", "randao_reveal",
)


def _parse_block_content(block_content: Any) -> Dict[str, Any]:
    """Block content is ``str(block.to_dict())`` — a Python-dict repr."""
    if isinstance(block_content, dict):
        return block_content
    if not isinstance(block_content, str) or not block_content:
        raise ValueError("empty/invalid block_content")
    return ast.literal_eval(block_content)


def reconstruct_signing_root(bc: Dict[str, Any]) -> bytes:
    """Reproduce ``PoSBlock.signing_root`` from a block-content dict."""
    data = (
        int(bc["number"]).to_bytes(8, "little") +
        bytes.fromhex(bc["parent_hash"]) +
        bytes.fromhex(bc["state_root"]) +
        bytes.fromhex(bc["transactions_root"]) +
        int(bc["timestamp"]).to_bytes(8, "little") +
        int(bc["slot"]).to_bytes(8, "little") +
        int(bc["epoch"]).to_bytes(8, "little") +
        bytes.fromhex(bc["randao_reveal"])
    )
    return hashlib.sha256(data).digest()


def verify_pos_block_proposer(
    block_content: Any,
    validator_address: str,
) -> Tuple[bool, str]:
    """
    Authenticate a PoS block's proposer. Returns ``(ok, error)``.

    On ``False`` the block MUST be rejected. Requires the block to carry
    ``proposer_public_key`` + ``proposer_signature`` and the signed header fields
    (all present in ``str(PoSBlock.to_dict())``).
    """
    try:
        bc = _parse_block_content(block_content)
    except Exception as e:
        return False, f"unparseable block_content: {e}"
    if not isinstance(bc, dict):
        return False, "block_content is not a dict"

    pubkey_hex = bc.get("proposer_public_key")
    sig_hex = bc.get("proposer_signature")
    if not pubkey_hex or not sig_hex:
        return False, "block missing proposer_public_key/proposer_signature"

    for f in _SIGNING_FIELDS:
        if f not in bc:
            return False, f"block missing signed header field '{f}'"

    try:
        pubkey = bytes.fromhex(pubkey_hex)
        sig = bytes.fromhex(sig_hex)
    except Exception as e:
        return False, f"malformed proposer key/signature hex: {e}"

    # 1. Identity binding: pubkey must derive to the claimed validator address.
    try:
        from ..crypto.pq.dilithium import PQPublicKey
        derived = PQPublicKey.from_bytes(pubkey).to_address()
    except Exception as e:
        return False, f"could not derive address from proposer pubkey: {e}"
    if derived != validator_address:
        return False, (
            f"proposer pubkey does not match address "
            f"(derived {derived[:20]}..., claimed {str(validator_address)[:20]}...)"
        )

    # 2. Dilithium signature over the reconstructed signing root.
    try:
        signing_root = reconstruct_signing_root(bc)
    except Exception as e:
        return False, f"could not reconstruct signing root: {e}"
    try:
        from ..crypto.pq import PQPublicKey as PK, PQSignature, verify as pq_verify
        ok = pq_verify(PK.from_bytes(pubkey), signing_root, PQSignature.from_bytes(sig))
    except Exception as e:
        return False, f"signature verification error: {e}"
    if not ok:
        return False, "invalid proposer Dilithium signature"

    return True, ""
