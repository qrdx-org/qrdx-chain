"""
The all-nodes epoch loop: finality, and the display copy of the validator set.

The validator set itself is not maintained here any more. It is a pure function of the chain
(qrdx/validator/epoch_state.py): ``S_E`` for each epoch, from the genesis set and the chain's
blocks, computed on demand by whoever needs it — eligibility on every import path, the
proposer, Casper FFG's weights — and cached per (epoch, checkpoint). This loop used to rebuild
the ``validators`` table from the chain each time *this node's* finality advanced, and
eligibility was judged against that table — so a block judged during a sync, or on a branch
being adopted, was judged against the wrong set, and those paths could not enforce it.

Each pass, under the block-processing lock (it writes tables import paths read):

  1. Casper FFG: recompute and persist justified / finalized checkpoints (validator/ffg.py);
  2. write the state in force at the tip to the ``validators`` table — what the RPC, the CLI
     and the explorer show (consensus reads ``epoch_state``, never the table);
  3. drop cached epoch states far below finality.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from ..constants import SLOT_DURATION
from .finality import update_finality

logger = logging.getLogger(__name__)

# How often the loop runs: once a slot, but no more than once a second.
_SLEEP = max(float(SLOT_DURATION), 1.0)

# Cached epoch states kept below the finalized epoch (nothing below finality is reorged, so one
# would do; a few spare the recomputation should a node restart mid-epoch).
STATE_EPOCHS_BELOW_FINALITY = 4


async def epoch_validator_update_loop(db, enforce: Optional[bool] = None, lock=None) -> None:
    """Background loop (all nodes). ``lock``: main.block_processing_lock. (``enforce`` is
    accepted for the old signature; nothing is gated any more.)"""
    last: Optional[int] = None
    logger.info("Epoch loop started (finality, validator-set display copy)")
    while True:
        try:
            if lock is not None:
                async with lock:
                    last = await _drain_finalized(db, last)
            else:
                last = await _drain_finalized(db, last)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("epoch loop error: %s", e)
        await asyncio.sleep(_SLEEP)


async def _drain_finalized(db, last_finalized: Optional[int]) -> int:
    """One pass: finality, the display copy, pruning. Returns the finalized epoch."""
    from .epoch_state import materialize, prune

    fin = await update_finality(db)
    finalized = int(fin.get("finalized_epoch", -1))
    vhash = await materialize(db)
    if finalized >= 0 and finalized != last_finalized:
        await prune(db, finalized - STATE_EPOCHS_BELOW_FINALITY)
        logger.info(
            "[epoch] finalized=%d justified=%d validators_hash=%s",
            finalized,
            int(fin.get("justified_epoch", -1)),
            vhash[:16],
        )
    await db.connection.commit()
    return finalized
