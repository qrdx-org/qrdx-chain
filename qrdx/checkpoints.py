"""
Trusted checkpoints: weak subjectivity (docs/WEAK_SUBJECTIVITY.md).

A running node never reorganizes below finality, but a node syncing from genesis has no
finality of its own yet. Validators that left long ago — their stake withdrawn, nothing left to
slash — can still sign: together they can build another history from an old block onward, with
votes and finality of its own, and a new node cannot tell it from the real one. Proof of stake
answers this the same way everywhere: a node trusts one recent block hash it got from outside
the protocol (a signed release, or its operator), and follows only chains that contain it.

Trusted checkpoints are ``(height, hash)`` pairs from:

* the network's chain spec (``"checkpoints"``), appended by each signed release, and
* ``QRDX_TRUSTED_CHECKPOINT`` (``height:hash``, comma-separated), the operator's own.

They are enforced on every path: a block at a checkpoint height must be the checkpoint
(``checkpoint_error``, in ``_verify_chain_rules``); no reorganization goes below the highest one
the node holds (``reorg_floor``); and a node whose database contradicts one refuses to start
(``startup_error``). A node that has been offline longer than the weak-subjectivity period —
the unbonding and withdrawal delays, after which the stake behind old signatures is gone — and
holds no newer checkpoint is warned (``staleness_warning``).
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional, Tuple

ENV = "QRDX_TRUSTED_CHECKPOINT"


class CheckpointError(ValueError):
    """Trusted checkpoints that contradict each other, or a malformed one."""


def _parse_env(raw: str) -> Dict[int, str]:
    out: Dict[int, str] = {}
    for item in (part.strip() for part in raw.split(",")):
        if not item:
            continue
        try:
            height_s, block_hash = item.split(":", 1)
            height = int(height_s)
        except ValueError as e:
            raise CheckpointError(f"{ENV}: {item!r} is not height:hash") from e
        block_hash = block_hash.strip().lower().removeprefix("0x")
        if (
            height < 1
            or len(block_hash) != 64
            or any(c not in "0123456789abcdef" for c in block_hash)
        ):
            raise CheckpointError(f"{ENV}: {item!r} is not height:hash (64 hex characters)")
        if out.get(height, block_hash) != block_hash:
            raise CheckpointError(f"{ENV}: two hashes for height {height}")
        out[height] = block_hash
    return out


def trusted(environ: Optional[Dict[str, str]] = None) -> Dict[int, str]:
    """{height: hash} of every trusted checkpoint: the chain spec's and the operator's."""
    from . import chain_spec

    out: Dict[int, str] = dict(chain_spec.active().checkpoints())
    env = os.environ if environ is None else environ
    for height, block_hash in _parse_env(env.get(ENV, "")).items():
        if out.get(height, block_hash) != block_hash:
            raise CheckpointError(
                f"{ENV} trusts {block_hash[:16]}… at height {height}; the chain spec trusts "
                f"{out[height][:16]}…"
            )
        out[height] = block_hash
    return out


def checkpoint_error(
    height: int, block_hash: str, checkpoints: Optional[Dict[int, str]] = None
) -> str:
    """Why a block at ``height`` with ``block_hash`` is not on the trusted chain, or ""."""
    cps = trusted() if checkpoints is None else checkpoints
    want = cps.get(int(height))
    if want is None:
        return ""
    if str(block_hash).lower().removeprefix("0x") != want:
        return f"block {str(block_hash)[:16]}… at height {height} is not the trusted checkpoint {want[:16]}…"
    return ""


def highest_at_or_below(height: int, checkpoints: Optional[Dict[int, str]] = None) -> int:
    """The highest trusted checkpoint height at or below ``height`` (-1 if none)."""
    cps = trusted() if checkpoints is None else checkpoints
    return max((h for h in cps if h <= int(height)), default=-1)


async def reorg_floor(db: Any) -> int:
    """No reorganization may roll back below this height: the finalized block, or the highest
    trusted checkpoint this node holds, whichever is higher."""
    from .validator.finality import finalized_block_height

    tip = int(await db.get_next_block_id()) - 1
    try:
        finalized = int(await finalized_block_height(db))
    except Exception:
        finalized = -1
    return max(finalized, highest_at_or_below(tip))


async def startup_error(db: Any) -> str:
    """Why this node's database is not on the trusted chain, or "": every checkpoint it already
    holds a block for must be that block."""
    tip = int(await db.get_next_block_id()) - 1
    cps = trusted()
    held = [h for h in sorted(cps) if h <= tip]
    if not held:
        return ""
    stored = await db.get_block_hashes(held[0], held[-1])
    for height in held:
        error = checkpoint_error(height, stored.get(height, ""), cps)
        if error:
            return (
                f"this database follows another chain: {error}. It cannot be used on this network "
                "(remove it and sync again)."
            )
    return ""


def weak_subjectivity_seconds() -> float:
    """How long the stake behind a validator's signatures stays slashable after it leaves: the
    unbonding period and the withdrawal delay. Beyond it, old keys sign for free."""
    from .constants import (
        SLOT_DURATION,
        SLOTS_PER_EPOCH,
        UNBONDING_PERIOD_EPOCHS,
        WITHDRAWAL_DELAY_EPOCHS,
    )

    return (
        (UNBONDING_PERIOD_EPOCHS + WITHDRAWAL_DELAY_EPOCHS) * SLOTS_PER_EPOCH * float(SLOT_DURATION)
    )


def staleness_warning(tip_height: int, tip_time: Optional[float], now: float) -> Optional[str]:
    """A warning when this node's newest block is older than the weak-subjectivity period and
    it trusts no checkpoint above it: whatever it syncs next could be a long-range fork."""
    if tip_time is None:
        return None
    period = weak_subjectivity_seconds()
    if now - float(tip_time) <= period:
        return None
    if any(h > tip_height for h in trusted()):
        return None
    days = (now - float(tip_time)) / 86400
    return (
        f"this node's newest block is {days:.1f} days old, older than the weak-subjectivity "
        f"period ({period / 86400:.1f} days): validators who have since left could have signed "
        f"another history. Set {ENV}=height:hash to a recent finalized block from a source you "
        "trust (another node operator, the release notes) before syncing."
    )


def describe(checkpoints: Optional[Dict[int, str]] = None) -> Tuple[int, str]:
    """(height, hash) of the highest trusted checkpoint, or (-1, "")."""
    cps = trusted() if checkpoints is None else checkpoints
    if not cps:
        return -1, ""
    height = max(cps)
    return height, cps[height]
