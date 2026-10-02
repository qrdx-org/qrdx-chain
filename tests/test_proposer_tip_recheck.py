"""
A proposer must not build at a height it can already see is filled.

`next_height`/`parent_hash` are captured at the top of the block-production loop, and the
section work that follows (exchange execution, EVM execution, unified-root computation)
takes long enough for a block to land meanwhile. Proposing against the stale height then
creates a competing block at that height off the same parent — the adjacent-slot race that
leaves a permanent fork (docs/KNOWN_ISSUES.md, "Block history did not converge").

A tip re-check existed but applied only to BACKUP proposers (`rank > 0`); the primary
never re-checked. It now applies to every rank.

**Placement is the subtle part, and it is what this test guards.** The check must sit
BEFORE any section execution: the exchange and EVM sections commit as they execute, so
aborting after them would leave committed state with no block to carry it. A future edit
that moves the check later — to tighten the window, which is superficially attractive —
would reintroduce exactly that hazard.

Source-level assertions because the production loop is a long-running async method over
live database, validator-manager and network state; there is no seam to drive it through
without restructuring the very code under test. The invariant is positional, so position
is what is asserted.
"""
import inspect
import re

from qrdx.validator import node_integration


def _loop_source():
    src = inspect.getsource(node_integration)
    start = src.index("Block production loop started")
    end = src.index("Add block to database with sequential height", start)
    return src[start:end]


def test_the_tip_is_rechecked_before_proposing():
    body = _loop_source()
    assert "get_next_block_id()) != next_block_id" in body, (
        "the block-production loop no longer re-checks whether its target height was "
        "filled while it prepared — a stale height guarantees a competing block")


def test_the_recheck_is_not_limited_to_backup_proposers():
    """
    The original check lived inside `if rank > 0:`, so the PRIMARY proposer — the one
    that proposes immediately and therefore races hardest — never re-checked.
    """
    lines = _loop_source().splitlines()
    check_i = next(i for i, l in enumerate(lines) if "!= next_block_id" in l)
    rank_i = max(i for i, l in enumerate(lines[:check_i])
                 if l.strip().startswith("if rank > 0:"))

    def indent(line):
        return len(line) - len(line.lstrip())

    # The `if rank > 0:` block must have CLOSED before the re-check: some non-blank line in
    # between sits at its indentation or shallower. (The re-check itself may be nested
    # deeper for other reasons — it now runs under the block-processing lock.)
    closed = any(line.strip() and indent(line) <= indent(lines[rank_i])
                 for line in lines[rank_i + 1:check_i])
    assert closed, (
        "the tip re-check is nested inside `if rank > 0:` — the primary proposer, "
        "which races hardest, would skip it")


def test_the_recheck_runs_before_any_section_execution():
    """
    The exchange and EVM sections COMMIT as they execute. A re-check placed after them
    would abort with state already committed and no block to carry it — silently
    applying a block's effects without the block.
    """
    body = _loop_source()
    recheck = body.index("get_next_block_id()) != next_block_id")

    for marker in ("process_exchange_transactions(",
                   "produce_block_evm_section(",
                   "_compute_unified_state_root("):
        where = body.find(marker)
        if where == -1:
            continue
        assert recheck < where, (
            f"the tip re-check runs AFTER {marker!r}; that section commits as it "
            f"executes, so aborting there would leave committed state with no block")


def test_the_recheck_skips_rather_than_proposing_stale():
    """It must `continue` to the next slot, not fall through and propose anyway."""
    body = _loop_source()
    idx = body.index("get_next_block_id()) != next_block_id")
    following = body[idx:idx + 400]
    assert re.search(r"\bcontinue\b", following), (
        "the re-check does not skip the slot — it must not fall through and propose "
        "against a height it just learned was filled")
