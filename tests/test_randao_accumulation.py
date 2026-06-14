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

from qrdx.validator.randao import compute_randao_mix, RANDAO_SEED, _mix_in


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


async def test_reorg_recompute_drops_orphaned_reveals():
    # A chain that rolled back from height 3 to 2 recomputes as if block 3 never
    # existed — the mix is a pure function of the canonical blocks present.
    full = _FakeDB({1: "aa" * 32, 2: "bb" * 32, 3: "cc" * 32})
    rolled_back = _FakeDB({1: "aa" * 32, 2: "bb" * 32})
    assert await compute_randao_mix(full, up_to_height=2) == await compute_randao_mix(rolled_back)
