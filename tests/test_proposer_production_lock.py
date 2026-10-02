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
    lines = _loop_lines()
    start, end = _locked_region(lines)
    region = "\n".join(lines[start:end])
    assert "broadcast_callback(" not in region, "a slow peer would hold up every import"
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
