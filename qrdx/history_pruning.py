"""
History pruning (docs/CHECKPOINT_SYNC.md, "History pruning"): a full node keeps what it needs to
follow the chain, and drops what only an archive needs.

``QRDX_HISTORY_RETENTION_BLOCKS`` unset or 0: an archive node (everything is kept, the default).
N: the bodies of blocks more than N below the finalized block are pruned, as finality moves.
N is at least ``MIN_RETENTION``.

What a pruned block loses — most of history's growth:

* the proposer's signature (3.3 KB of ML-DSA-65 per block, ~1.1 GB a day at 250 ms slots). A
  block's hash is its signing root, which does not cover the signature: the chain of hashes
  still verifies;
* the signatures of the votes it carried (the votes themselves stay: the chain index, finality
  and the validator set read them);
* its exchange and EVM sections (each transaction carries a post-quantum signature and key).

It keeps every field its hash covers, its votes and slashing evidence, and ``"pruned": True``.
The chain index, the staking logs, the validator states and every state table are untouched.

The window: a node restarts and reorganizes from its persisted exchange checkpoint, replaying
the blocks above it (persisted every PERSIST_INTERVAL_BLOCKS of finality), and a snapshot made
from it must carry verifiable votes for the next validator-set transition. ``MIN_RETENTION``
covers both with room to spare.

What a pruned node cannot do any more:

* replay from genesis (a lost checkpoint is recovered from a snapshot instead);
* serve the blocks below its pruning point to a node syncing from genesis (an archive node
  does: a peer asking is told so);
* answer for the transactions in pruned sections.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Mapping, Optional

from .logger import get_logger

logger = get_logger(__name__)

ENV = "QRDX_HISTORY_RETENTION_BLOCKS"
KEY = "history_pruned_below"
BATCH = 2_000  # blocks pruned per finality step (the catch-up of a long chain takes many)


class HistoryPruned(RuntimeError):
    """What this node needs is below its pruning point."""


def min_retention() -> int:
    from .constants import SLOTS_PER_EPOCH
    from .derived_state_rebuild import PERSIST_INTERVAL_BLOCKS
    from .validator.ffg import INCLUSION_EPOCHS

    return max(4_096, 2 * PERSIST_INTERVAL_BLOCKS + (INCLUSION_EPOCHS + 4) * SLOTS_PER_EPOCH)


def retention(environ: Optional[Mapping[str, str]] = None) -> int:
    """The configured window (0: an archive node). Raises ValueError for a window too short."""
    raw = (os.environ if environ is None else environ).get(ENV, "").strip()
    if not raw or raw == "0":
        return 0
    try:
        n = int(raw)
    except ValueError:
        raise ValueError(f"{ENV} is a number of blocks, not {raw!r}") from None
    if n < min_retention():
        raise ValueError(f"{ENV}={n} is below the minimum window of {min_retention()} blocks")
    return n


async def pruned_below(db: Any) -> int:
    """Blocks below this height are pruned (0: none)."""
    try:
        cur = await db.connection.execute("SELECT value FROM chain_metadata WHERE key = ?", (KEY,))
        row = await cur.fetchone()
    except Exception:
        return 0
    return int(row[0]) if row else 0


def strip(bc: Dict[str, Any]) -> Dict[str, Any]:
    """A block body without what pruning drops (the header and the votes stay)."""
    out = {k: v for k, v in bc.items() if k != "proposer_signature"}
    # A vote keeps its fields with an empty signature: the chain index decodes it as any vote.
    out["attestations"] = [
        {**a, "signature": ""} if isinstance(a, dict) else a for a in (bc.get("attestations") or [])
    ]
    out["pruned"] = True
    return out


async def prune(db: Any, finalized_height: int, window: int = -1) -> int:
    """Prune the next blocks below ``finalized_height - window`` (``window``: the configured one
    by default; nothing on an archive node). At most BATCH blocks a call. Returns how many."""
    from . import block_codec
    from .validator.block_verification import _parse_block_content

    window = retention() if window < 0 else window
    if not window:
        return 0
    target = int(finalized_height) - window
    done = max(1, await pruned_below(db))
    if target <= done:
        return 0
    upto = min(target, done + BATCH)
    conn = db.connection
    cur = await conn.execute(
        "SELECT block_height, block_hash, content FROM blocks "
        "WHERE block_height >= ? AND block_height < ? ORDER BY block_height",
        (done, upto),
    )
    count = 0
    for height, block_hash, content in await cur.fetchall():
        bc = _parse_block_content(block_codec.decode(content))
        if not bc.get("pruned"):
            await conn.execute(
                "UPDATE blocks SET content = ?, validator_signature = NULL WHERE block_height = ?",
                (block_codec.encode(repr(strip(bc))), int(height)),
            )
        for table in ("block_exchange_transactions", "block_evm_transactions"):
            await conn.execute(f"DELETE FROM {table} WHERE block_hash = ?", (block_hash,))
        count += 1
    await conn.execute(
        "INSERT OR REPLACE INTO chain_metadata (key, value) VALUES (?, ?)", (KEY, str(upto))
    )
    await conn.commit()
    if count:
        logger.info("history pruned below block %d (%d blocks this step)", upto, count)
    return count


async def require_history(db: Any, from_height: int, what: str) -> None:
    """Raise HistoryPruned if blocks from ``from_height`` are pruned here."""
    below = await pruned_below(db)
    if below and int(from_height) < below:
        raise HistoryPruned(
            f"{what} needs block {from_height} onward, but this node pruned history below "
            f"block {below} ({ENV}): restore from a snapshot (scripts/node/snapshot.py), or ask "
            "an archive node"
        )
