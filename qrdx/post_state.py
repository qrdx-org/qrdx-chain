"""
Deferred execution: a block commits to the state its parent left (chain-spec feature
``deferred_execution``; docs/PERFORMANCE.md, "Pipelined execution").

A block's signed ``state_root`` used to be the unified root after the block itself, so a proposer
ran its block before it could sign it: selection, execution, the flush to the database and the
roots all stood between the slot's start and the block leaving for its peers, and the next
proposer could not build until the block had arrived and it had run it too. Under the feature,
block N's signed root is the unified root after block N−1:

* **A proposer signs before it runs its block.** It judges its transactions on the state its
  parent left (``exchange_inclusion``), signs with the root of that state (computed when it
  applied the parent, and kept here), sends the block, and then runs it.
* **An importer checks the root before it runs the block,** against the state it holds (the
  parent's), then runs it; the root of what the block leaves is computed then and kept here for
  the next block.
* **Running a signed block cannot make it invalid** in a way its proposer could not foresee:
  the exchange section was judged before it was signed, and an EVM transaction that cannot run
  is skipped (``evm_block_apply.apply_block_evm_section_total``).
* **What a block leaves is bound by the next block's root.** State proofs and snapshots of the
  state after block h are therefore checked against block h + 1's signed root
  (``signed_root_of_state``).

The root of the state after block h is computed with block h's own height and slot: exactly what
block h would have signed without the feature, one block later.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from typing import Any, Optional, Tuple

logger = logging.getLogger(__name__)

FEATURE = "deferred_execution"

# block hash → the unified root after that block. A reorg leaves the orphans' entries behind;
# they are keyed by hash, so they are never read for another block.
KEEP = 512
_ROOTS: "OrderedDict[str, str]" = OrderedDict()


def active(height: Optional[int]) -> bool:
    """Is block ``height`` under the feature?"""
    if height is None:
        return False
    from . import chain_spec

    return chain_spec.is_active(FEATURE, int(height))


def forget() -> None:
    """Drop every kept root (derived state was rebuilt; they are recomputed on demand)."""
    _ROOTS.clear()


def remember(block_hash: str, root: str) -> None:
    _ROOTS[block_hash] = root
    _ROOTS.move_to_end(block_hash)
    while len(_ROOTS) > KEEP:
        _ROOTS.popitem(last=False)


def kept(block_hash: Optional[str]) -> Optional[str]:
    return _ROOTS.get(block_hash) if block_hash else None


async def unified_root(db: Any, height: int, slot: Optional[int]) -> str:
    """The unified state root of the state now, under the rules of block ``height`` (its slot
    for the validators' domain), recording the state-proof parts under that height. The
    computation a block's root has always had (``ValidatorNode._compute_unified_state_root``),
    shared here by the proposer and every import path."""
    from . import state_proofs
    from .crypto.hashing import TOKEN_ZERO_ROOT, unified_state_root
    from .exchange.state_manager import ExchangeStateManager
    from .validator import validator_root as vroot

    try:
        utxo_root = await db.get_unspent_outputs_hash(height)
    except Exception:
        utxo_root = "0" * 64
    try:
        account_root = await db.get_account_state_root(height)
    except Exception:
        account_root = "0" * 128
    mgr = ExchangeStateManager.get_instance()
    try:
        exchange_root = mgr.compute_state_root()
    except Exception:
        exchange_root = "0" * 128
    try:
        token_root = await db.get_token_balances_root(height)
    except Exception:
        token_root = TOKEN_ZERO_ROOT
    validators = None
    if slot is not None and vroot.active(height):
        validators = await vroot.compute(db, height, slot)
    proof_root = None
    if state_proofs.scheduled():
        xroot = mgr.exchange_proof_root(height)
        proof_root = await state_proofs.proof_root(db, height, xroot)
        await state_proofs.record_parts(
            db,
            height,
            {
                "utxo": utxo_root or "0" * 64,
                "account": account_root,
                "exchange": exchange_root,
                "token": token_root,
                "proof": proof_root,
                "xtree": xroot.hex(),
                "validators": validators,
            },
        )
    return unified_state_root(
        utxo_root or "0" * 64, account_root, exchange_root, token_root, proof_root, validators
    )


async def _slot_of(db: Any, height: int) -> Optional[int]:
    from . import chain_index

    try:
        slot = await chain_index.slot_at(db, height)
    except Exception:
        slot = None
    return None if slot is None else int(slot)


async def settle(db: Any, height: int, block_hash: str, slot: Optional[int] = None) -> str:
    """Block ``height`` has just been applied: compute the root of the state it leaves and keep
    it for the block that will sign it."""
    if slot is None:
        slot = await _slot_of(db, height)
    root = await unified_root(db, height, slot)
    remember(block_hash, root)
    return root


async def root_after(db: Any, height: int, block_hash: Optional[str] = None) -> str:
    """The root of the state block ``height`` (hash ``block_hash``, default the chain's) left —
    which must be the state now. Kept when the block was applied; computed now when it was not
    (a restart, a rebuild)."""
    if block_hash is None:
        block_hash = (await db.get_block_hashes(height, height)).get(height)
    root = kept(block_hash)
    if root is not None:
        return root
    root = await unified_root(db, height, await _slot_of(db, height))
    if block_hash:
        remember(block_hash, root)
    return root


async def check(db: Any, block_content: Any, height: int) -> Tuple[bool, str]:
    """Before block ``height`` runs: its signed root must be the root of the state its parent
    left, which is the state this node holds (the block's parent is its tip)."""
    from .validator.block_verification import _parse_block_content

    try:
        declared = _parse_block_content(block_content).get("state_root")
    except Exception:
        return False, "unreadable block content"
    if not declared:
        return False, "the block signs no state root"
    expected = await root_after(db, height - 1)
    if declared != expected:
        return False, (
            f"state root mismatch: the block signs {str(declared)[:16]}…, the state block "
            f"{height - 1} left is {expected[:16]}…"
        )
    return True, ""


async def signed_root_of_state(db: Any, height: int) -> Tuple[Optional[str], Optional[int]]:
    """The signed root of the state after block ``height``, and the height of the block that
    signs it: the next block under the feature (None until it exists), the block itself
    otherwise."""
    from .validator.block_verification import _parse_block_content

    signer = height + 1 if active(height + 1) else height
    block = await db.get_block_by_id(signer)
    if not block:
        return None, signer
    try:
        root = _parse_block_content(block.get("content")).get("state_root")
    except Exception:
        root = None
    return (str(root) if root else None), signer
