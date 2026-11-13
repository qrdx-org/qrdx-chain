"""
Per-block undo journal for the derived database state — reorgs without a replay from genesis.

A reorg used to delete the orphaned blocks and rebuild every derived domain by replaying the
whole chain (derived_state_rebuild.rebuild_derived_state_interleaved): about 26 µs a block, so
~9 s after one day of 250 ms blocks — and at short slots reorgs are routine. Instead, the store
(qrdx/store.py) records every change a block makes to the journaled tables, keyed by the block's
height: the first time a block changes a row, the row as it was (or that there was none).

``rollback_to(h)`` writes back every row the blocks above ``h`` changed, newest first, inside the
caller's transaction (the store's commitments and proof-tree marks follow the rows, so the state
roots come back too). Entries at or below the finalized checkpoint can never be needed and are
pruned.

Every block-application path wraps its writes in ``recording(db, height)``. A write to a
journaled table outside it is recorded as UNATTRIBUTED; while one exists the journal cannot
vouch for exactness and ``rollback_to`` refuses, so the caller falls back to the full rebuild —
a write path that forgot to record costs time, never correctness. A full rebuild resets the
journal and re-records every block it replays.
"""

from __future__ import annotations

import contextlib
from typing import Any, AsyncIterator, Optional

from .logger import get_logger

logger = get_logger(__name__)

# The derived tables blocks change and the rollback used to rebuild: account and contract
# state, the token ledger and its registry mirror, and the EVM balance-sync bookkeeping (the
# store's specs mark them journaled: qrdx/store.py).
JOURNALED = (
    "account_state",
    "contract_storage",
    "token_balances",
    "token_registry",
    "evm_balance_sync_registry",
    "evm_balance_changes",
)

UNATTRIBUTED = -1

_FLOOR = "undo_floor"


@contextlib.asynccontextmanager
async def recording(db: Any, height: int) -> AsyncIterator[None]:
    """Attribute every journaled write inside the block to block ``height``."""
    with db.store.recording(int(height)):
        yield


@contextlib.asynccontextmanager
async def suspended(db: Any) -> AsyncIterator[None]:
    """Writes that are not a block's — a clear before a full rebuild, genesis seeding — are not
    journaled (and are not unattributed: the caller resets the journal around them)."""
    with db.store.suspended():
        yield


async def reset(db: Any) -> None:
    """Forget the journal (before a full rebuild, which re-records what it replays)."""
    db.store.native.undo_reset()


def floor(db: Any) -> Optional[int]:
    row = db.store["store_meta"].get(_FLOOR)
    return None if row is None else int(row.value)


async def can_roll_back_to(db: Any, height: int) -> bool:
    """Whether ``rollback_to(height)`` would be exact: the journal holds no unattributed write,
    and covers every block above ``height``."""
    if db.store.native.undo_has(UNATTRIBUTED):
        return False
    lowest = floor(db)
    return lowest is not None and lowest <= int(height)


async def set_floor(db: Any, height: int) -> None:
    """The journal covers every block above ``height`` from now on."""
    db.store["store_meta"].put(_FLOOR, str(int(height)))


async def rollback_to(db: Any, height: int) -> Optional[int]:
    """Reverse every journaled change made by blocks above ``height``. Returns the number of
    entries reversed, or None (nothing done) when the journal cannot vouch for exactness."""
    if not await can_roll_back_to(db, height):
        return None
    return db.store.native.undo_rollback(int(height))


async def prune(db: Any, finalized_height: int) -> None:
    """Drop entries no reorg can reach (the finalized checkpoint is never rolled back)."""
    db.store.native.undo_prune(int(finalized_height))
    lowest = floor(db)
    if lowest is not None and lowest < int(finalized_height):
        await set_floor(db, finalized_height)
