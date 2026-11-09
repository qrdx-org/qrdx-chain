"""
Block production must not interleave with an import or a derived-state rebuild.

Every import path and the reorg rebuild hold ``main.block_processing_lock``; the proposer did
not. The rebuild yields at every database await, so a proposer selected mid-rebuild computed
its unified root over half-rebuilt state and importers rejected the declared root — seen in
a fault-injecting soak as the recurring E-D4 observe mismatch: node2 proposed block 123
between a rebuild's reset and its completion, declaring 369ea204… while every importer
computed 63e7b01c… (block 122's root; block 123 changed nothing), and node2's next block
declared 63e7b01c… again. A block's sections could equally be applied in the middle of a
replay, out of order.

Also pinned here: the proposer stamps the block with the timestamp it executed the sections
at, because importers execute them at the block's timestamp and the exchange judges time by
it (tests/test_exchange_block_clock.py).
"""
import contextlib
import inspect

from qrdx.validator import node_integration as NI
from qrdx.validator.manager import ValidatorManager


def _loop_lines():
    return inspect.getsource(NI.ValidatorNode._block_production_loop).splitlines()


def _indent(line):
    return len(line) - len(line.lstrip())


def _locked_region(lines):
    start = next(i for i, l in enumerate(lines) if "async with self._production_lock():" in l)
    depth = _indent(lines[start])
    end = next(i for i in range(start + 1, len(lines))
               if lines[i].strip() and _indent(lines[i]) <= depth)
    return start, end


def test_everything_from_the_tip_recheck_to_storing_the_block_is_locked():
    lines = _loop_lines()
    start, end = _locked_region(lines)
    region = "\n".join(lines[start:end])
    for step in ("get_next_block_id()) != next_block_id",   # tip re-check
                 "process_exchange_transactions(",
                 "self._evm_section_producer(",
                 "process_block_withdrawals(",
                 "self._compute_unified_state_root(",
                 "self.manager.propose_block(",
                 "self.db.add_block(",
                 "record_finality_from_block("):
        assert step in region, f"{step} runs outside the block-processing lock"


def test_broadcast_and_slot_sleep_happen_outside_the_lock():
    """The broadcast begins as soon as the block is signed (peers import while this node
    stores it), but it is awaited only once the lock is released: a slow peer never holds up
    imports."""
    lines = _loop_lines()
    start, end = _locked_region(lines)
    region = "\n".join(lines[start:end])
    after = "\n".join(lines[end:])
    assert "await self.broadcast_callback(" not in region, "a slow peer would hold up imports"
    begun = region.index("asyncio.ensure_future(\n") if "asyncio.ensure_future(\n" in region else -1
    assert begun > region.index("self.manager.propose_block("), "broadcast only a signed block"
    assert begun < region.index("self.db.add_block("), "the broadcast does not wait for storing"
    assert "await broadcast" in after
    assert "asyncio.sleep(" not in region, "never sleep while holding the lock"


def test_the_node_shares_mains_lock():
    from qrdx.node import main as node_main
    assert "set_block_processing_lock(block_processing_lock)" in inspect.getsource(node_main.startup)


def test_the_production_lock_is_the_shared_one():
    node = NI.ValidatorNode.__new__(NI.ValidatorNode)
    node._block_processing_lock = None
    assert isinstance(node._production_lock(), contextlib.nullcontext)
    import asyncio
    lock = asyncio.Lock()
    node.set_block_processing_lock(lock)
    assert node._production_lock() is lock


def test_the_block_carries_the_execution_timestamp():
    assert "timestamp=block_timestamp" in "\n".join(_loop_lines())
    params = inspect.signature(ValidatorManager.propose_block).parameters
    assert "timestamp" in params
    src = inspect.getsource(ValidatorManager.propose_block)
    assert "timestamp=int(timestamp) if timestamp is not None else int(time.time())" in src


def test_the_parent_is_re_checked_under_the_lock_before_any_section_runs():
    """The height can come back with a different tip: a reorg removes the tip read at the top of
    the iteration and applies another block at its height. The proposer then read the tip as
    missing and built on an all-zero parent, which every peer refused (seen in the 250 ms
    integration run). Under the lock it now re-reads the tip and skips unless it is exactly the
    parent the block is built on."""
    lines = _loop_lines()
    start, end = _locked_region(lines)
    region = lines[start:end]
    recheck = next(i for i, l in enumerate(region) if "tip_hash != parent_hash" in l)
    first_section = next(i for i, l in enumerate(region) if "process_exchange_transactions(" in l)
    assert recheck < first_section
    # (back to the top to build on the new tip, once a slot, or on to the next slot)
    assert sum("continue" in l for l in region[recheck + 1:recheck + 14]) == 2


def test_a_tip_that_moved_while_preparing_is_built_on_in_the_same_slot(monkeypatch):
    """An import that lands while the proposer waits for the lock (most often the previous
    slot's block) used to cost the proposer its slot. It now goes back to the top once, while
    enough of the slot is left — half, or a twentieth with a pipelined proposer next (whose
    import builds on a late block before running it) — and builds on the new tip after every
    check again."""
    from qrdx.validator import pipeline

    src = "\n".join(_loop_lines())
    for skip in ("was filled while preparing", "the tip changed while preparing"):
        before = src[: src.index(skip)]
        guard = before.rindex("retried_slot != current_slot")
        assert "await self._slot_left(current_slot) > self._retry_share()" in before[guard:]
        assert "retried_slot, last_slot = current_slot, current_slot - 1" in before[guard:]
    monkeypatch.setattr(pipeline, "enabled", lambda: True)
    assert NI.ValidatorNode._retry_share() == 0.05
    monkeypatch.setattr(pipeline, "enabled", lambda: False)
    assert NI.ValidatorNode._retry_share() == 0.5


async def test_the_share_of_a_slot_left():
    import time

    node = NI.ValidatorNode.__new__(NI.ValidatorNode)
    slot = NI.SLOT_DURATION_SECONDS

    async def genesis():
        return time.time() - 10 * slot - 0.25 * slot      # (a quarter into slot 10)

    node._genesis_timestamp = genesis
    assert abs(await node._slot_left(10) - 0.75) < 0.1
    assert await node._slot_left(9) == 0.0 and await node._slot_left(12) == 1.0
