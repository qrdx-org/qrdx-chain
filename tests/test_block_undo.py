"""
Taking a block back out of the in-memory exchange (qrdx/exchange/block_undo.py).

A reorg used to restore the exchange from its epoch checkpoint and replay up to an epoch of
blocks. Each block now runs in an undo scope, with what no scope records kept beside it, and is
taken back out at the cost of what it changed. What must hold, on a chain of every kind of
operation (token deploys and transfers, oracle votes, perp deposits and trades, pools and
liquidity):

* undoing a block gives back the whole exchange as the block found it, field for field (not
  only its root);
* blocks undo newest first, several at once;
* a missing record, or an undo that does not reproduce its root, says so: the caller then
  restores from the checkpoint.
"""

import os

import pytest

from qrdx.crypto.pq.dilithium import PQPrivateKey
from qrdx.exchange import block_processor as BP
from qrdx.exchange import block_undo
from qrdx.exchange.state_manager import ExchangeStateManager

import test_reorg_rebuild_equivalence as E

pytestmark = pytest.mark.usefixtures("genesis_btc")  # BTC from the first block (the perp trades)

# Caches the commitments and books keep beside the state (recomputed from it), and the indexes
# derived from it (an undo drops them: rebuilt in full on their next use).
CACHES = {"_digests", "_dirty", "_acc", "_tree", "_tree_on", "_changes", "_index_token",
          "_expiring_pairs", "_digest", "_digest_version", "_version"} | block_undo.DERIVED


def norm(x, depth=0, stack=frozenset()):
    """A structure equal for equal states, whatever the order of a dict's keys."""
    if depth > 30:
        return "<deep>"
    if not isinstance(x, (str, bytes, int, float, bool, type(None))):
        if id(x) in stack:
            return "<cycle>"
        stack = stack | {id(x)}
    if isinstance(x, dict):
        return ("dict", sorted((repr(norm(k, depth + 1, stack)), norm(v, depth + 1, stack))
                               for k, v in dict.items(x)))
    if isinstance(x, (set, frozenset)):
        return ("set", sorted(repr(norm(v, depth + 1, stack)) for v in set.__iter__(x)))
    if isinstance(x, (list, tuple)):
        return (type(x).__name__, [norm(v, depth + 1, stack) for v in x])
    d = getattr(x, "__dict__", None)
    if d is not None and not isinstance(x, type) and not callable(x):
        return (type(x).__name__,
                norm({k: v for k, v in d.items() if k not in CACHES}, depth + 1, stack))
    slots = getattr(type(x), "__slots__", None)
    if slots and not isinstance(x, type):
        return (type(x).__name__,
                [(s, norm(getattr(x, s, None), depth + 1, stack)) for s in slots if s not in CACHES])
    return repr(x)


def diff(a, b, path="", out=None):
    """Where two normalized states differ (for a failure's message)."""
    out = [] if out is None else out
    if a == b:
        return out
    if not (isinstance(a, tuple) and isinstance(b, tuple) and len(a) == 2 == len(b)):
        out.append(path)
        return out
    if isinstance(a[1], tuple) and isinstance(b[1], tuple):
        return diff(a[1], b[1], f"{path}.{a[0]}", out)
    if a[0] == "dict":
        da, dbb = dict(a[1]), dict(b[1])
        for k in sorted(set(da) | set(dbb)):
            if da.get(k) != dbb.get(k):
                if k in da and k in dbb:
                    diff(da[k], dbb[k], f"{path}/{k[:50]}", out)
                else:
                    out.append(f"{path}/{k[:50]} ({'added' if k in dbb else 'removed'})")
        return out
    if isinstance(a[1], list) and isinstance(b[1], list) and len(a[1]) == len(b[1]):
        for i, (x, y) in enumerate(zip(a[1], b[1])):
            diff(x, y, f"{path}[{i}]", out)
        return out
    out.append(f"{path} <{a[0]}>")
    return out


async def _run(db, mgr, h):
    section = await db.get_block_exchange_txs(f"{h:064x}")
    opened = block_undo.open_block(mgr, h)
    try:
        if section:
            txs = BP.decode_exchange_txs(section)
            await BP.preload_sender_balances(db, txs, mgr)
            await BP.preload_token_balances(db, txs, mgr)
            ok, err, _ = BP.process_exchange_transactions(h, float(1_700_000_000 + h), txs, mgr)
            assert ok, err
            mgr.commit_block()
            await BP.flush_exchange_balance_deltas(db, mgr, enforce=BP.ENFORCE_EXCHANGE_COLLATERAL)
            await BP.flush_token_balance_deltas(db, mgr)
        else:
            await BP.tick_and_flush(db, h, float(1_700_000_000 + h), mgr)
    finally:
        block_undo.close_block(opened, applied=True)


async def _chain():
    db, path = await E._db()
    k1, k2 = PQPrivateKey.generate(), PQPrivateKey.generate()
    tip = await E._build_chain(db, k1, k2)
    await db.seed_genesis_account_state()
    await db.connection.commit()
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    E._set_flags(mgr)
    block_undo.invalidate()
    return db, path, tip, mgr


async def test_undoing_each_block_gives_back_the_whole_exchange():
    db, path, tip, mgr = await _chain()
    try:
        for h in range(1, tip + 1):
            before, root = norm(mgr.capture()), mgr.compute_state_root()
            await _run(db, mgr, h)
            after = mgr.capture()
            assert block_undo.take_back(mgr, h - 1) == 1, f"block {h} did not undo"
            assert mgr.compute_state_root() == root
            now = norm(mgr.capture())
            assert now == before, f"block {h}: differs after undo at {diff(before, now)[:10]}"
            mgr._restore_snapshot(after)                   # (on to the next block)
            block_undo.invalidate()
        ch = mgr.clearinghouse
        assert ch.markets["BTC-QRDX-PERP"].open_interest == 1          # (the trade happened)
        assert any(p.state.liquidity > 0 for p in mgr.pool_manager._pools.values())
    finally:
        await db.close()
        os.remove(path)


async def test_blocks_undo_newest_first_several_at_once():
    db, path, tip, mgr = await _chain()
    try:
        states = {}
        for h in range(1, tip + 1):
            states[h - 1] = (norm(mgr.capture()), mgr.compute_state_root())
            await _run(db, mgr, h)
        assert sorted(block_undo.RECORDS) == list(range(1, tip + 1))
        assert block_undo.take_back(mgr, 3) == tip - 3
        assert (norm(mgr.capture()), mgr.compute_state_root()) == states[3]
        assert sorted(block_undo.RECORDS) == [1, 2, 3]
    finally:
        await db.close()
        os.remove(path)


async def test_a_missing_or_wrong_record_says_so():
    db, path, tip, mgr = await _chain()
    try:
        for h in range(1, 4):
            await _run(db, mgr, h)
        del block_undo.RECORDS[2]
        assert block_undo.take_back(mgr, 1) is None                 # (2 is missing: nothing done)
        assert sorted(block_undo.RECORDS) == [1, 3]
        block_undo.RECORDS[3].root = "not the root"                   # (an undo that is off)
        assert block_undo.take_back(mgr, 2) is None and block_undo.RECORDS == {}
        assert block_undo.TOP == [None]                                # (not known any more)
        assert block_undo.take_back(mgr, 2) is None
    finally:
        await db.close()
        os.remove(path)


def test_a_record_open_across_a_rebuild_is_not_kept():
    ExchangeStateManager.reset_instance()
    mgr = ExchangeStateManager.get_instance()
    block_undo.invalidate()
    opened = block_undo.open_block(mgr, 5)
    block_undo.invalidate()                                           # (a rebuild ran meanwhile)
    block_undo.close_block(opened, applied=True)
    assert 5 not in block_undo.RECORDS
    opened = block_undo.open_block(mgr, 6)
    block_undo.close_block(opened, applied=False)                     # (refused)
    assert 6 not in block_undo.RECORDS
    from qrdx.exchange import undo

    assert undo.active() is None


def test_every_derived_index_is_dropped_by_an_undo():
    """An index built on first use and kept up to date from its collection's tracked changes is
    not undone by a scope: an undo drops it (block_undo.DERIVED) and its next use rebuilds it. A
    new one must be listed there, or an undone block would leave it describing the block."""
    import pathlib
    import re

    root = pathlib.Path(block_undo.__file__).parent
    found = set()
    for path in root.rglob("*.py"):
        text = path.read_text()
        found |= set(re.findall(r'__dict__\["(_[a-z_]+)"\] = (?:index|state)$', text, re.M))
        found |= set(re.findall(r"self\.(_[a-z_]+) = index$", text, re.M))
    assert found and found <= block_undo.DERIVED, f"not dropped by an undo: {found - block_undo.DERIVED}"
