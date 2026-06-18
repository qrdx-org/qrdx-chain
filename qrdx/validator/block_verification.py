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
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from ..logger import get_logger

logger = get_logger(__name__)

# RANDAO mix used for proposer selection. The validator manager keeps this at
# all-zeros network-wide (it is never reassigned), so importers must use the
# same value to reproduce the proposer. If RANDAO accumulation is ever turned on,
# the importer must track the identical mix per slot/epoch.
PROPOSER_RANDAO_MIX = b"\x00" * 32


def expected_proposer_for_slot(
    slot: int,
    validators: List[Tuple[str, Decimal]],
    randao_mix: bytes = PROPOSER_RANDAO_MIX,
) -> Optional[str]:
    """
    Deterministically reproduce the eligible proposer address for ``slot``.

    ``validators`` is ``[(address, effective_stake), ...]`` reconstructed the same
    way the proposer builds its set (every active/pending validator from
    ``validator_stakes``, ``effective_stake = stake / 1e8``, all proposable). The
    selection is order-independent (canonicalised by address in
    ``ValidatorSelector``), so every node derives the same proposer. Returns the
    address, or ``None`` if no eligible validators.
    """
    from .selection import ValidatorSelector
    from .types import Validator, ValidatorStatus

    vals = [
        Validator(
            address=addr,
            public_key=b"",
            stake=stake,
            effective_stake=stake,
            status=ValidatorStatus.ACTIVE,
            activation_epoch=0,
        )
        for addr, stake in validators
    ]
    chosen = ValidatorSelector().select_proposer(slot, vals, randao_mix)
    return chosen.address if chosen else None

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


def epoch_from_block(block_like: Dict[str, Any]) -> Optional[int]:
    """Robustly extract a PoS block's epoch from any of the dict shapes the import
    paths carry: a parsed block dict (epoch/slot top-level), or a wire envelope whose
    header fields live inside a ``block_content`` repr string. Returns the epoch as an
    int, or ``None`` if it cannot be determined. Used to schedule validator
    activation/exit DETERMINISTICALLY from the carrying block (identical on every node)
    — see flush_validator_lifecycle_deltas."""
    if not isinstance(block_like, dict):
        return None
    # 1. Top-level epoch (parsed block dict).
    ep = block_like.get("epoch")
    if ep is not None:
        try:
            return int(ep)
        except (TypeError, ValueError):
            pass
    # 2. Header fields nested in a block_content repr (the p2p/REST wire envelope).
    bc = block_like.get("block_content")
    if bc is not None:
        try:
            content = _parse_block_content(bc)
            if content.get("epoch") is not None:
                return int(content["epoch"])
            if content.get("slot") is not None:
                from ..constants import SLOTS_PER_EPOCH
                return int(content["slot"]) // SLOTS_PER_EPOCH
        except Exception:
            pass
    # 3. Top-level slot fallback.
    if block_like.get("slot") is not None:
        try:
            from ..constants import SLOTS_PER_EPOCH
            return int(block_like["slot"]) // SLOTS_PER_EPOCH
        except (TypeError, ValueError):
            pass
    return None


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


async def verify_proposer_eligibility(
    db: Any,
    block_content: Any,
    enforce: bool = False,
) -> Tuple[bool, str]:
    """
    Verify the block's proposer is the validator selected for its slot.

    Reconstructs the proposer's validator set from the ``validators`` table (the
    exact source `node_integration` builds from — seeded identically on every node
    from genesis, with ``effective_stake`` already in QRDX), derives the
    deterministic slot proposer, and compares to the block's claimed
    ``proposer_address``. This catches a registered validator proposing
    out-of-turn (signature-valid but not its slot).

    Safe for liveness: a propagation-latency fork block still carries a *valid*
    (slot, proposer) pair, so it passes — only genuinely out-of-turn blocks fail.

    ``enforce=False`` (observe): a mismatch only warns and returns ``ok=True``.
    Returns ``(True, "")`` when the set can't be reconstructed (never reject a
    block we can't check).
    """
    try:
        bc = _parse_block_content(block_content)
    except Exception:
        return True, ""
    try:
        slot = int(bc["slot"])
        proposer = bc.get("proposer_address")
    except Exception:
        return True, ""
    if not proposer:
        return True, ""

    try:
        rows = await db.get_validators()
        validators = [
            (r["address"], Decimal(str(r.get("effective_stake") or r.get("stake") or 0)))
            for r in rows
            if r.get("address") and str(r.get("status", "active")).upper() in ("ACTIVE", "PENDING", "EXITING")
        ]
    except Exception as e:
        logger.debug("eligibility: could not load validator set: %s", e)
        return True, ""
    if not validators:
        return True, ""

    expected = expected_proposer_for_slot(slot, validators)
    if expected and expected != proposer:
        msg = (f"proposer {str(proposer)[:20]}... not eligible for slot {slot} "
               f"(expected {expected[:20]}...)")
        if enforce:
            return False, msg
        logger.warning(f"[eligibility observe] {msg}")
        return True, ""
    return True, ""


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
