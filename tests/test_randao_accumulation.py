"""
RANDAO mix accumulation (observe-first) — qrdx.validator.randao.

Pins the accumulation as a deterministic, reorg-safe pure function of the chain:
folding the same reveals yields the same mix; a different/extra reveal changes it;
the mix is a function of the (canonical) blocks present, so a rolled-back chain
recomputes a clean mix. Selection is NOT exercised here (still uses the zero
constant) — this is the observe-phase primitive.
"""

import json
from decimal import Decimal

import pytest

from qrdx.validator.randao import (
    compute_randao_mix, checkpoint_mix_for_block, epoch_checkpoint_mix,
    _boundary_height_for_slot, RANDAO_SEED, _mix_in,
)
from qrdx.constants import SLOTS_PER_EPOCH


class _SlotDB:
    """Block store with slot + reveal: height -> {'content': json(slot, randao_reveal)}."""
    def __init__(self, n_blocks, slot_of=lambda h: h):
        self._blocks = {}
        for h in range(n_blocks):
            self._blocks[h] = {"content": json.dumps(
                {"slot": slot_of(h), "randao_reveal": (f"{h:02x}" * 32)[:64]})}

    async def get_next_block_id(self):
        return (max(self._blocks) + 1) if self._blocks else 0

    async def get_block_by_id(self, height):
        return self._blocks.get(height)


class _FakeDB:
    """Minimal block store: height -> {'content': json with randao_reveal}."""
    def __init__(self, reveals_by_height):
        # reveals_by_height: dict height -> reveal hex (or None to omit reveal)
        self._blocks = {}
        for h, rev in reveals_by_height.items():
            content = {} if rev is None else {"randao_reveal": rev}
            self._blocks[h] = {"content": json.dumps(content)}

    async def get_next_block_id(self):
        return (max(self._blocks) + 1) if self._blocks else 0

    async def get_block_by_id(self, height):
        return self._blocks.get(height)


async def test_empty_chain_is_seed():
    db = _FakeDB({})
    assert await compute_randao_mix(db) == RANDAO_SEED


async def test_genesis_without_reveal_skipped():
    db = _FakeDB({0: None})  # genesis carries no reveal
    assert await compute_randao_mix(db) == RANDAO_SEED


async def test_folds_reveals_deterministically():
    reveals = {0: None, 1: "aa" * 32, 2: "bb" * 32, 3: "cc" * 32}
    db = _FakeDB(reveals)
    m1 = await compute_randao_mix(db)
    m2 = await compute_randao_mix(db)
    assert m1 == m2 != RANDAO_SEED  # deterministic + actually moved

    # Matches an explicit fold in height order.
    expected = RANDAO_SEED
    for h in (1, 2, 3):
        expected = _mix_in(expected, bytes.fromhex(reveals[h]))
    assert m1 == expected


async def test_order_matters():
    a = _FakeDB({1: "aa" * 32, 2: "bb" * 32})
    b = _FakeDB({1: "bb" * 32, 2: "aa" * 32})
    assert await compute_randao_mix(a) != await compute_randao_mix(b)


async def test_up_to_height_bounds_the_fold():
    db = _FakeDB({1: "aa" * 32, 2: "bb" * 32, 3: "cc" * 32})
    mix_2 = await compute_randao_mix(db, up_to_height=2)
    mix_3 = await compute_randao_mix(db, up_to_height=3)
    assert mix_2 != mix_3
    # mix_3 == folding cc into mix_2 (reorg/extension safety: prefix-consistent).
    assert mix_3 == _mix_in(mix_2, bytes.fromhex("cc" * 32))


async def test_checkpoint_mix_is_height_lookback():
    # Checkpoint for block H = mix folded up to H - lookback (a fixed function of H).
    db = _FakeDB({1: "aa" * 32, 2: "bb" * 32, 3: "cc" * 32, 4: "dd" * 32, 5: "ee" * 32})
    assert await checkpoint_mix_for_block(db, height=5, lookback=2) == \
        await compute_randao_mix(db, up_to_height=3)


async def test_checkpoint_mix_cross_time_stable():
    # The checkpoint for block H is IDENTICAL whether the chain currently ends at H
    # or has grown past it — proposer (at H) and importer (later) agree. This is the
    # cross-time-stability property the enforce path relies on.
    at_h = _FakeDB({1: "aa" * 32, 2: "bb" * 32, 3: "cc" * 32, 4: "dd" * 32})
    grown = _FakeDB({1: "aa" * 32, 2: "bb" * 32, 3: "cc" * 32, 4: "dd" * 32,
                     5: "ee" * 32, 6: "ff" * 32})
    assert await checkpoint_mix_for_block(at_h, height=4, lookback=2) == \
        await checkpoint_mix_for_block(grown, height=4, lookback=2)


async def test_checkpoint_mix_early_blocks_use_seed():
    db = _FakeDB({1: "aa" * 32, 2: "bb" * 32})
    assert await checkpoint_mix_for_block(db, height=1, lookback=8) == RANDAO_SEED


async def test_boundary_height_for_slot_binary_search():
    # slot == height (no empty slots): highest block with slot < B is height B-1.
    db = _SlotDB(50)
    assert await _boundary_height_for_slot(db, 40) == 39
    assert await _boundary_height_for_slot(db, 1) == 0
    assert await _boundary_height_for_slot(db, 0) == -1  # none below slot 0


async def test_epoch_checkpoint_mix_uses_prev_epoch_boundary():
    # epoch E with lookback L → mix folded up to the last block of epoch E-L. slot==height,
    # so the last block of epoch (E-L) is at height (E-L+1)*SPE - 1.
    db = _SlotDB(4 * SLOTS_PER_EPOCH)  # epochs 0..3
    boundary = 3 * SLOTS_PER_EPOCH - 1  # epoch 3, lookback 1 → checkpoint epoch 2's last block
    assert await epoch_checkpoint_mix(db, epoch=3, lookback_epochs=1) == \
        await compute_randao_mix(db, up_to_height=boundary)


async def test_epoch_checkpoint_mix_is_tip_independent():
    # The KEY property the height-based checkpoint lacked: epoch E's mix is identical
    # whether the chain currently sits in epoch E or several epochs later — so validators
    # a block apart compute the same proposer for a slot.
    short = _SlotDB(2 * SLOTS_PER_EPOCH + 1)   # just into epoch 2
    longer = _SlotDB(5 * SLOTS_PER_EPOCH)      # well into epoch 4
    assert await epoch_checkpoint_mix(short, epoch=2) == \
        await epoch_checkpoint_mix(longer, epoch=2)


async def test_epoch_checkpoint_mix_early_epochs_use_seed():
    db = _SlotDB(2 * SLOTS_PER_EPOCH)
    assert await epoch_checkpoint_mix(db, epoch=0, lookback_epochs=1) == RANDAO_SEED


async def test_reorg_recompute_drops_orphaned_reveals():
    # A chain that rolled back from height 3 to 2 recomputes as if block 3 never
    # existed — the mix is a pure function of the canonical blocks present.
    full = _FakeDB({1: "aa" * 32, 2: "bb" * 32, 3: "cc" * 32})
    rolled_back = _FakeDB({1: "aa" * 32, 2: "bb" * 32})
    assert await compute_randao_mix(full, up_to_height=2) == await compute_randao_mix(rolled_back)
