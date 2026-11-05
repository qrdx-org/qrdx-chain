"""
Taking a block back out of the in-memory exchange, at the cost of what it changed
(qrdx/derived_state_rebuild.py, ``rebuild_to_tip``).

A reorg used to restore the exchange from its newest epoch checkpoint and replay every block
above it: for a fork one block deep, up to an epoch of blocks, about a second under load,
holding the block lock. The database already undoes block by block (qrdx/undo_journal.py). Now
the exchange does too. Each block runs inside an undo scope (qrdx/exchange/undo.py): every
committed entry, book, market and pool the block changes records what it was, the first time.
What no scope records is kept beside it when the block starts:

* the manager's own fields (its block height and time, its counters, the oracle's committee,
  vote sequences and outliers);
* the plain attributes of each engine, and of the books and markets they hold (a flag, a set
  of what changed this block, a book's height, an index built on first use). Attributes the
  block adds are removed, plain containers are put back in place, so whoever shares them sees
  them as they were. An object the block created is dropped with the container entry that holds
  it, by the scope.

A record also holds the exchange root as the block found it. Undoing a block must reproduce it,
or the caller falls back to the checkpoint and replay; and tests/test_block_undo.py takes every
block of a chain of every kind of operation back out and compares the whole exchange, field for
field, with what it was.
"""

from __future__ import annotations

import copy
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from . import undo

# The manager's fields no scope records (ExchangeStateManager.capture lists the whole state).
MANAGER_FIELDS: Tuple[str, ...] = (
    "_current_block_height",
    "_current_block_timestamp",
    "_total_swaps",
    "_total_orders",
    "_total_pools",
    "_total_positions",
    "oracle_committee",
    "oracle_votes",
    "oracle_vote_seqs",
    "perp_votes",
    "oracle_outliers",
    "oracle_excluded",
    "fee_tokens",
)

# The engines whose plain attributes are kept (their committed collections undo themselves).
ENGINES: Tuple[str, ...] = (
    "clearinghouse",
    "governance",
    "tokens",
    "nfts",
    "bridge",
    "trading",
    "authority",
    "qns",
    "pool_manager",
    "router",
)

_IMMUTABLE = (int, float, str, bytes, bool, Decimal, type(None), tuple, frozenset)

# Indexes derived from committed state, never committed, built in full when missing (each kept up
# to date from the changes its collection tracks, tied to it by ``_index_token``): an undo drops
# them, so the next use builds them from the state as it was. tests/test_block_undo.py finds
# every one in the source.
DERIVED = frozenset(
    {
        "_liq",  # clearinghouse: where each account turns liquidatable
        "_by_owner",  # a perp market: open orders by owner
        "_trigger_index",  # a perp market: triggers by price
        "_twap_index",  # trading: TWAPs by when their next slice is due
        "_cancel_index",  # trading: scheduled cancels
        "_spot_index",  # trading: spot triggers
        "_index",  # bridge
        "_reverse",  # authority: who may act for whom
        "_due",  # authority: waiting changes by when they are due
        "_fee_index",  # the manager (handlers/spot.py)
    }
)


def _holders(mgr: Any) -> Dict[str, Any]:
    """The objects whose plain attributes are kept: the engines, and the books and markets they
    hold (a block sets a book's height, builds an index on first use)."""
    out: Dict[str, Any] = {}
    for name in ENGINES:
        engine = getattr(mgr, name, None)
        if engine is not None and hasattr(engine, "__dict__"):
            out[name] = engine
    for pair, book in dict.items(getattr(mgr, "_order_books", {}) or {}):
        out[f"book:{pair}"] = book
    markets = getattr(getattr(mgr, "clearinghouse", None), "markets", None) or {}
    for market_id, market in dict.items(markets):
        if hasattr(market, "__dict__"):
            out[f"market:{market_id}"] = market
        book = getattr(market, "book", None)
        if book is not None and hasattr(book, "__dict__"):
            out[f"perp-book:{market_id}"] = book
    return out


def _committed(value: Any) -> bool:
    return hasattr(value, "_mark") or hasattr(value, "_dirty")  # (CommittedDict, CommittedSet)


def _plain_attributes(obj: Any) -> Dict[str, Any]:
    """An engine's attributes no scope records, as they are now: immutable values as they are,
    plain containers copied one level."""
    out: Dict[str, Any] = {}
    for name, value in vars(obj).items():
        if isinstance(value, _IMMUTABLE):
            out[name] = value
        elif type(value) in (dict, set, list) and not _committed(value):
            out[name] = type(value)(value)
    return out


def _put_back(obj: Any, names: frozenset, saved: Dict[str, Any]) -> None:
    for name in [n for n in vars(obj) if n not in names or n in DERIVED]:
        delattr(obj, name)  # (added by the block: an index built on first use, say)
    for name, value in saved.items():
        current = vars(obj).get(name)
        if type(value) in (dict, set, list) and type(current) is type(value):
            undo.restore_into(current, type(value)(value))
        else:
            setattr(obj, name, type(value)(value) if type(value) in (dict, set, list) else value)


class BlockUndo:
    """How to take one block back out of the exchange (see the module's note)."""

    __slots__ = ("height", "scope", "root", "fields", "engines")

    def __init__(self, mgr: Any, height: int) -> None:
        self.height = int(height)
        self.scope = undo.Scope(None)
        self.root = mgr.compute_state_root()
        self.fields = {f: copy.deepcopy(getattr(mgr, f)) for f in MANAGER_FIELDS if hasattr(mgr, f)}
        self.engines: Dict[str, Tuple[Any, frozenset, Dict[str, Any]]] = {
            key: (obj, frozenset(vars(obj)), _plain_attributes(obj))
            for key, obj in _holders(mgr).items()
        }

    def undo(self, mgr: Any) -> bool:
        """Take the block back out. True if the exchange is then as the block found it (its
        root); False means the caller must restore it another way."""
        self.scope.rollback()
        for f, value in self.fields.items():
            setattr(mgr, f, copy.deepcopy(value))
        for obj, names, saved in self.engines.values():
            _put_back(obj, names, saved)
        mgr._expiring_pairs = None  # (derived from the books: rebuilt on next use)
        for name in DERIVED & set(vars(mgr)):
            delattr(mgr, name)
        try:
            return bool(mgr.compute_state_root() == self.root)
        except Exception:
            return False


# height → the record of the block applied there last, while it is kept.
RECORDS: Dict[int, BlockUndo] = {}
# The block being applied now, if any (a refused block is taken back out through it).
OPEN: List[Optional[BlockUndo]] = [None]
# The height of the last block applied to the exchange since it was last rebuilt (None: not
# known — after a restart, or a rebuild — and nothing is taken back until it is).
TOP: List[Optional[int]] = [None]
KEEP = 64
# Raised by every rebuild: a block whose record was open across one is not kept (the rebuild
# changed the exchange under it).
_GENERATION = [0]


def generation() -> int:
    return _GENERATION[0]


def invalidate() -> None:
    """The exchange was rebuilt, or restored from a checkpoint: no record describes it."""
    _GENERATION[0] += 1
    RECORDS.clear()
    TOP[0] = None


Opened = Tuple[BlockUndo, Any, int, Any]


def open_block(mgr: Any, height: int) -> Opened:
    """Before a block runs: its record, with its scope open (returns what ``close_block``
    takes)."""
    record = BlockUndo(mgr, height)
    token = undo._ACTIVE.set(record.scope)
    OPEN[0] = record
    return record, token, generation(), mgr


def close_block(opened: Opened, applied: bool) -> None:
    """After a block ran: close its scope; keep the record if the block is on the chain now and
    nothing rebuilt the exchange meanwhile. A block that ran (in part) and is not on the chain —
    refused, or failed — is taken back out of the exchange here, unless a rebuild already
    restored it."""
    record, token, gen, mgr = opened
    if OPEN[0] is record:
        OPEN[0] = None
    try:
        undo._ACTIVE.reset(token)
    except ValueError:
        undo._ACTIVE.set(None)
    if gen != generation():  # (a rebuild ran meanwhile: it restored the exchange)
        RECORDS.pop(record.height, None)
        if applied:
            TOP[0] = None  # (applied, but its record is not kept: the top is not known)
        return
    if not applied:
        RECORDS.pop(record.height, None)
        if not record.undo(mgr):
            invalidate()  # (not reproduced: the next restore goes through a checkpoint)
        return
    for h in [h for h in RECORDS if h >= record.height]:
        del RECORDS[h]
    RECORDS[record.height] = record
    TOP[0] = record.height
    for h in sorted(RECORDS)[:-KEEP]:
        del RECORDS[h]


def take_back(mgr: Any, tip: int) -> Optional[int]:
    """Take every block applied above ``tip`` back out of the exchange, newest first. Returns
    how many, or None if the last block applied is not known, a record is missing, or an undo
    does not reproduce its root (the exchange must then be restored another way; the records
    are dropped)."""
    top = TOP[0]
    if top is None or top < tip:
        return None
    if any(h not in RECORDS for h in range(tip + 1, top + 1)):
        return None
    done = 0
    for h in range(top, tip, -1):
        if not RECORDS.pop(h).undo(mgr):
            invalidate()
            return None
        done += 1
    TOP[0] = tip
    return done


def take_back_open(mgr: Any, tip: int) -> Optional[bool]:
    """A block being applied above ``tip`` (refused part-way, its state to be restored): take
    what it did so far back out. None if there is none; else whether it reproduced its root.
    Either way its record is not kept."""
    record = OPEN[0]
    if record is None or record.height <= tip:
        return None
    OPEN[0] = None
    _GENERATION[0] += 1  # (its context closes later: not kept)
    return record.undo(mgr)


def suspended() -> Any:
    """For a rebuild: no block's scope is open while it runs (the token ``resume`` takes)."""
    return undo._ACTIVE.set(None)


def resume(token: Any) -> None:
    try:
        undo._ACTIVE.reset(token)
    except ValueError:
        undo._ACTIVE.set(None)
