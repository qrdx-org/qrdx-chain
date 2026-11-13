"""
Chain index — a compact, reorg-safe summary of every canonical block, so that no consensus
helper ever has to re-read the chain from genesis.

Several consensus helpers need a few facts about every historical block: its slot and epoch,
the running RANDAO mix, the stake operations and attestation votes it carries, and the
offenders its slashing evidence proves. They used to fetch and parse every block body from
genesis on each call — ``ast.literal_eval`` of a ~60 KB body per block, on the event loop — so
the cost of a call grew with the chain, and with it the time a validator needed per slot. On a
testnet that had produced 75,000 blocks the block time had drifted from 2 s to 14.5 s.

The index stores those facts once per block and is extended lazily: ``sync`` indexes only the
blocks added since its last call. It never trusts itself across a reorg. A block's hash commits
to its whole ancestry, so the index is valid exactly up to the highest height whose recorded
hash still matches the ``blocks`` table; ``sync`` finds that height (one comparison in the
common case, a binary search after a reorg), drops everything above it, and re-derives.

The index lives in the node's store (qrdx/store.py: ``chain_index`` and its vote, offender and
FFG tables, each with the secondary indexes its questions need). Its writes join the store's
current transaction (no commit of their own): a block that is rolled back takes its index rows
with it, and a block deleted by a rollback is caught by the hash check on the next ``sync``.

Every derived value is what the original per-call walk computed (tests/test_chain_index.py
checks each against it, across reorgs).

**In memory.** Consensus code asks the index dozens of times a block — the validator set of an
epoch, finality, the validators' root — and each ask cost two round trips to the database's
thread: the check that the chain had not changed, then the read. Two things make most of them
free:

* the database counts every write to ``blocks`` (its block writers call ``blocks_changed``) and
  every rollback (``rolled_back``), so ``sync`` knows without a read when the chain is as it last
  checked it;
* the hash and slot of the newest ``RECENT`` heights are kept in memory, exactly as the index
  rows hold them: written beside each row, cut where rows are dropped, forgotten whole on a
  rollback (and re-read in one query).

So the index is still never trusted across a change: any write to ``blocks`` and any rollback
sends ``sync`` back to the store. That holds while the node's blocks are written only through
its database's methods (a snapshot is restored before the node starts). With
``QRDX_VERIFY_CHAIN_INDEX=1`` (the test suite) every answer from memory is checked against the
database.
"""

from __future__ import annotations

import asyncio
import bisect
import os
import weakref
from typing import Any, Dict, List, Optional, Tuple

from .logger import get_logger

logger = get_logger(__name__)

_TABLES = (
    "chain_index",
    "chain_index_votes",
    "chain_index_offenders",
    "chain_index_ffg",
)
_TOP = 2**62  # (above every height)
# Bumped whenever what is derived per block changes: an index written by an older version is
# dropped and re-derived (it is derived data; the chain is the source).
_VERSION = "4"  # 3: no stake-op index (it could not tell an executed deposit from a refused one)
# 4: in the store
_BATCH = 256  # blocks read per query while catching up

_locks: "weakref.WeakKeyDictionary[Any, asyncio.Lock]" = weakref.WeakKeyDictionary()
_ready: "weakref.WeakKeyDictionary[Any, bool]" = weakref.WeakKeyDictionary()
# db → (the height the index last covered, the hash of the block it indexed there)
_synced: "weakref.WeakKeyDictionary[Any, Tuple[int, str]]" = weakref.WeakKeyDictionary()


# The newest heights kept in memory (hash and slot): about an hour of 250 ms slots, where the
# validator set, finality and the validators' root look.
RECENT = 16_384


class _Recent:
    """The index rows of the heights ``base`` .. ``base + len - 1`` (the index's top), as the
    table holds them. Slot lookups are answered by bisection while the slots are ``ordered``: a
    run of unknown ones first (genesis has none), then each known and above the one before (a
    canonical chain's are)."""

    __slots__ = ("base", "hashes", "slots", "lead", "ordered")

    def __init__(self, base: int = 0) -> None:
        self.base = base
        self.hashes: List[str] = []
        self.slots: List[Optional[int]] = []
        self.lead = 0  # the leading heights without a slot
        self.ordered = True

    @property
    def top(self) -> int:
        return self.base + len(self.hashes) - 1

    def put(self, height: int, block_hash: str, slot: Optional[int]) -> None:
        if not self.hashes or height > self.top + 1 or height < self.base:
            self.__init__(height)  # type: ignore[misc]  # (not contiguous: start again here)
        elif height <= self.top:
            self.cut(height - 1)
        if slot is None:
            if self.lead == len(self.slots):
                self.lead += 1
            else:
                self.ordered = False
        elif self.ordered and len(self.slots) > self.lead and int(slot) <= self.slots[-1]:  # type: ignore[operator]
            self.ordered = False
        self.hashes.append(block_hash)
        self.slots.append(None if slot is None else int(slot))
        if len(self.hashes) > RECENT:
            drop = len(self.hashes) - RECENT
            del self.hashes[:drop], self.slots[:drop]
            self.base += drop
            self.lead = max(0, self.lead - drop)

    def cut(self, keep_to: int) -> None:
        """Keep the heights at or below ``keep_to``."""
        n = max(0, keep_to - self.base + 1)
        del self.hashes[n:], self.slots[n:]
        self.lead = min(self.lead, n)
        if not self.hashes:
            self.ordered = True

    def hash_at(self, height: int) -> Tuple[bool, Optional[str]]:
        """(answered, the hash): above the top there is none; below ``base``, unanswered."""
        if height > self.top:
            return True, None
        if height < self.base:
            return False, None
        return True, self.hashes[height - self.base]

    def slot_at(self, height: int) -> Tuple[bool, Optional[int]]:
        if height > self.top:
            return True, None
        if height < self.base:
            return False, None
        return True, self.slots[height - self.base]

    def before_slot(self, slot: int, max_height: Optional[int] = None) -> Tuple[bool, int]:
        """(answered, the highest height ≤ ``max_height`` whose slot is known and below
        ``slot``; -1 if none)."""
        if not self.ordered or not self.hashes:
            return False, -1
        end = len(self.hashes)
        if max_height is not None:
            end = min(end, int(max_height) - self.base + 1)
        if end <= 0:
            return (True, -1) if max_height is not None and max_height < 0 else (False, -1)
        if end <= self.lead:
            return (True, -1) if self.base == 0 else (False, -1)
        i = bisect.bisect_left(self.slots, int(slot), self.lead, end)  # type: ignore[type-var]
        if i > self.lead:
            return True, self.base + i - 1
        # (none kept qualifies: the answer is below the heights kept, if any are)
        return (True, -1) if self.base == 0 else (False, -1)


_recent: "weakref.WeakKeyDictionary[Any, _Recent]" = weakref.WeakKeyDictionary()


class _Watch:
    """The database's count of writes to ``blocks`` and rollbacks (see the module doc), and
    the count and tip at the last check that found the index in step with the chain."""

    __slots__ = ("count", "clean_at", "tip")

    def __init__(self) -> None:
        self.count = 0
        self.clean_at = -1
        self.tip = -1

    def bump(self) -> None:
        self.count += 1

    def clean(self) -> bool:
        return self.clean_at == self.count


# (by the database's store: every database object on one store shares its count)
_watches: "weakref.WeakKeyDictionary[Any, _Watch]" = weakref.WeakKeyDictionary()


def _watch_key(db: Any) -> Any:
    return getattr(db, "store", None) or db


# What else forgets on a rollback (a table created once per database: created again, since the
# rollback may have taken it). Each is called with the database.
_rollback_hooks: List[Any] = []


def on_rollback(hook: Any) -> None:
    """Call ``hook(db)`` after every rollback of ``db`` (once per hook)."""
    if hook not in _rollback_hooks:
        _rollback_hooks.append(hook)


def change_count(db: Any) -> Optional[int]:
    """A number that changes whenever ``blocks`` is written or ``db`` rolls back (None before
    the index has looked at ``db``)."""
    watch = _watches.get(_watch_key(db))
    return None if watch is None else watch.count


def _verifying() -> bool:
    return os.environ.get("QRDX_VERIFY_CHAIN_INDEX", "").lower() in ("1", "true", "yes")


def _forget(db: Any) -> None:
    """The index may differ from what memory holds of it (a rollback): ask the store."""
    _synced.pop(db, None)
    _recent.pop(db, None)
    _ready.pop(db, None)
    watch = _watches.get(_watch_key(db))
    if watch is not None:
        watch.bump()


def _watch_of(db: Any) -> "_Watch":
    watch = _watches.get(_watch_key(db))
    if watch is None:
        watch = _watches[_watch_key(db)] = _Watch()
    return watch


def blocks_changed(db: Any) -> None:
    """``db``'s block writers call this after writing to ``blocks`` (a block added, removed)."""
    _watch_of(db).bump()


def rolled_back(db: Any) -> None:
    """``db``'s rollback calls this: what memory holds may be gone from the store."""
    _forget(db)
    for hook in list(_rollback_hooks):
        try:
            hook(db)
        except Exception:
            pass


def _lock_for(db: Any) -> asyncio.Lock:
    lock = _locks.get(db)
    if lock is None:
        lock = _locks[db] = asyncio.Lock()
    return lock


async def _ensure(db: Any) -> None:
    if _ready.get(db):
        return
    _watch_of(db)
    meta = db.store["chain_index_meta"]
    row = meta.get("version")
    if row is None or row.value != _VERSION:
        for table in _TABLES:
            db.store[table].clear()
        meta.delete("unordered")
        _recent.pop(db, None)
        _synced.pop(db, None)
        meta.put("version", _VERSION)
        if row is not None:
            logger.info(
                "chain index: format changed (v%s → v%s) — re-deriving", row.value, _VERSION
            )
    _ready[db] = True


# ── deriving one block's facts ───────────────────────────────────────────────────────────


def _parse(content: Any) -> Optional[Dict[str, Any]]:
    from .validator.block_verification import _parse_block_content

    try:
        parsed = _parse_block_content(content)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def _reveal(bc: Optional[Dict[str, Any]]) -> Optional[bytes]:
    """The proposer's RANDAO reveal, exactly as randao._extract_reveal reads it."""
    if bc is None:
        return None
    hexrev = bc.get("randao_reveal")
    if not hexrev:
        return None
    try:
        raw = bytes.fromhex(hexrev)
    except (ValueError, TypeError):
        return None
    return raw or None


def _votes(bc: Optional[Dict[str, Any]], carry_epoch: Optional[int]) -> List[Tuple[int, str]]:
    """(target_epoch, validator) for each attestation the block carries — the reward input of
    the validator set (validator/epoch_state.py)."""
    if bc is None or carry_epoch is None:
        return []
    from .validator.attestation_block import extract_attestations_from_dict

    try:
        return [
            (int(a.target_epoch), a.validator_address) for a in extract_attestations_from_dict(bc)
        ]
    except Exception:
        return []


def _ffg(bc: Optional[Dict[str, Any]]) -> List[Tuple[str, int, str, int, str]]:
    """(validator, source epoch, source root, target epoch, target root) for each FFG vote the
    block carries. (Import accepts a block only if every carried vote is valid for its chain —
    validator/ffg.py verify_block_votes — so these are trusted here.)"""
    if bc is None:
        return []
    from .validator.attestation_block import extract_attestations_from_dict

    try:
        return [
            (
                a.validator_address,
                int(a.source_epoch),
                a.source_root,
                int(a.target_epoch),
                a.target_root,
            )
            for a in extract_attestations_from_dict(bc)
            if a.target_root
        ]
    except Exception:
        return []


def _offenders(bc: Optional[Dict[str, Any]]) -> List[str]:
    """Validators a verified slashing proof in the block convicts (lower-cased)."""
    if bc is None or not bc.get("slashing_evidence"):
        return []
    from .validator.slashing_block import extract_slashing_evidence_from_dict, verified_offender

    found = []
    try:
        for ev in extract_slashing_evidence_from_dict(bc):
            offender = verified_offender(ev)
            if offender:
                found.append(offender.lower())
    except Exception:
        return found
    return found


async def _index_block(db: Any, height: int, block_hash: str, content: Any, mix: bytes) -> bytes:
    """Index one block on top of ``mix`` (the mix after its predecessor); returns its mix."""
    from .validator.block_verification import epoch_from_block
    from .validator.randao import _mix_in

    bc = _parse(content)
    slot: Optional[int] = None
    epoch: Optional[int] = None
    if bc is not None:
        try:
            slot = int(bc["slot"]) if bc.get("slot") is not None else None
        except (TypeError, ValueError):
            slot = None
        epoch = epoch_from_block(bc)
    reveal = _reveal(bc)
    if reveal is not None:
        mix = _mix_in(mix, reveal)
    store = db.store
    index = store["chain_index"]
    if slot is not None:
        below = index.scan(hi=(height,), reverse=True, limit=1)
        if below and below[0].slot is not None and int(below[0].slot) >= slot:
            store["chain_index_meta"].put("unordered", "1")  # (only a contrived chain)
    index.put(height, block_hash, slot, epoch, mix.hex())
    recent = _recent.get(db)
    if recent is not None:
        recent.put(height, block_hash, slot)
    for seq, (te, v) in enumerate(_votes(bc, epoch)):
        store["chain_index_votes"].put(height, seq, epoch, te, v)
    for seq, offender in enumerate(_offenders(bc)):
        store["chain_index_offenders"].put(height, seq, offender)
    for seq, vote in enumerate(_ffg(bc)):
        store["chain_index_ffg"].put(height, seq, *vote)
    return mix


# ── keeping it in step with the chain ────────────────────────────────────────────────────


async def _chain_hash(db: Any, height: int) -> Optional[str]:
    row = db.store["blocks"].get(int(height))
    return row.block_hash if row is not None else None


async def _indexed_at_or_below(db: Any, height: int) -> Optional[Tuple[int, str, str]]:
    rows = db.store["chain_index"].scan(hi=(int(height) + 1,), reverse=True, limit=1)
    return (int(rows[0].height), rows[0].block_hash, rows[0].randao_mix) if rows else None


def _drop_above(db: Any, height: int) -> None:
    for table in _TABLES:
        db.store[table].delete_prefix(lo=(int(height) + 1,), hi=(_TOP,))


async def _valid_top(db: Any) -> int:
    """The highest indexed height still on the chain (-1 if none), dropping every row above
    it. Matching hashes form a prefix — a block's hash commits to its ancestry — so one
    comparison settles the usual case and a binary search finds the fork point after a
    reorg."""
    rows = db.store["chain_index"].scan(reverse=True, limit=1)
    if not rows:
        return -1
    top = int(rows[0].height)
    entry = await _indexed_at_or_below(db, top)
    if entry and await _chain_hash(db, entry[0]) == entry[1]:
        return entry[0]
    lo, hi, good = 0, int(top) - 1, -1
    while lo <= hi:
        mid = (lo + hi) // 2
        entry = await _indexed_at_or_below(db, mid)
        if entry is None:
            break
        if await _chain_hash(db, entry[0]) == entry[1]:
            good = entry[0]
            lo = mid + 1
        else:
            hi = entry[0] - 1
    _drop_above(db, good)
    recent = _recent.get(db)
    if recent is not None:
        recent.cut(good)
    logger.info("chain index: chain changed below the indexed tip — re-deriving above %d", good)
    return good


async def sync(db: Any, up_to: Optional[int] = None) -> int:
    """Index every block up to ``up_to`` (default: the tip). Returns the highest height the
    index now covers (-1 for an empty chain). One query when nothing is new: the chain still
    has, at the top the index last covered, the block it indexed there (matching hashes form a
    prefix), and the tip is not above it. Every chain-index read syncs first, many times a block
    (eligibility, the validators' root, finality), and the full check cost five or six round
    trips to the database each time: most of an empty block's."""
    async with _lock_for(db):
        await _ensure(db)
        known = _synced.get(db)
        watch = _watches.get(_watch_key(db))
        if known is not None and watch is not None and watch.clean():
            # (nothing written to blocks, nothing rolled back, since the check below last
            # found the index in step: no query)
            target = watch.tip if up_to is None else min(int(up_to), watch.tip)
            if known[0] >= target:
                return known[0]
        if known is not None:
            count = watch.count if watch is not None else None
            # (the index's own row too: a rollback of the store's transaction can take rows it
            # wrote while the block they index stays)
            tip = int(await db.get_block_height())
            target = tip if up_to is None else min(int(up_to), tip)
            indexed = db.store["chain_index"].get(known[0])
            if (
                await _chain_hash(db, known[0])
                == known[1]
                == (indexed.block_hash if indexed is not None else None)
            ):
                if watch is not None and count is not None:
                    # (counted before the query: a write since makes it unclean again)
                    watch.clean_at, watch.tip = count, tip
                if known[0] >= target:
                    return known[0]
        top = await _sync(db, up_to)
        entry = await _indexed_at_or_below(db, top) if top >= 0 else None
        if entry is not None and entry[0] == top:
            _synced[db] = (top, entry[1])
        else:
            _synced.pop(db, None)
        return top


async def _sync(db: Any, up_to: Optional[int]) -> int:
    """The full sync: check the index against the chain, drop what is no longer on it,
    and index what is new (under the lock)."""
    tip = int(await db.get_next_block_id()) - 1
    target = tip if up_to is None else min(int(up_to), tip)
    top = await _valid_top(db)
    if top >= target:
        return top
    from .validator.randao import RANDAO_SEED

    below = await _indexed_at_or_below(db, top) if top >= 0 else None
    mix = bytes.fromhex(below[2]) if below else RANDAO_SEED
    start = top + 1
    from . import block_codec

    blocks, bodies = db.store["blocks"], db.store["block_bodies"]
    while start <= target:
        end = min(target, start + _BATCH - 1)
        rows = blocks.scan(lo=(start,), hi=(end + 1,))
        contents = bodies.get_many((int(r.block_height),) for r in rows)
        for row, body in zip(rows, contents, strict=True):
            content = block_codec.decode(body.content) if body is not None else None
            mix = await _index_block(db, int(row.block_height), row.block_hash, content, mix)
        start = end + 1
        await asyncio.sleep(0)  # let the node run between batches while catching up
    return target


# ── what consumers ask ───────────────────────────────────────────────────────────────────


async def randao_mix(db: Any, up_to_height: int) -> bytes:
    """The RANDAO mix after folding every canonical block's reveal up to ``up_to_height``."""
    from .validator.randao import RANDAO_SEED

    if up_to_height < 0:
        return RANDAO_SEED
    await sync(db, up_to_height)
    entry = await _indexed_at_or_below(db, up_to_height)
    return bytes.fromhex(entry[2]) if entry else RANDAO_SEED


async def _kept(db: Any) -> Optional[_Recent]:
    """The recent heights in memory, if they are the index as ``sync`` last left it (read in
    one query when they are not)."""
    known = _synced.get(db)
    if known is None:
        return None
    recent = _recent.get(db)
    if recent is not None and recent.hashes and (recent.top, recent.hashes[-1]) == known:
        return recent
    rows = db.store["chain_index"].scan(lo=(known[0] - RECENT + 1,), hi=(known[0] + 1,))
    recent = _Recent()
    for r in rows:
        recent.put(int(r.height), r.block_hash, None if r.slot is None else int(r.slot))
    if (
        not recent.hashes
        or (recent.top, recent.hashes[-1]) != known
        or _synced.get(db) != known  # (the index moved while it was read)
    ):
        _recent.pop(db, None)
        return None
    _recent[db] = recent
    return recent


async def _checked(db: Any, kept: Any, what: str, stored: Any) -> Any:
    """``kept`` (an answer from memory), checked against the store's (``stored``, a function
    reading it) when verifying."""
    if _verifying():
        want = stored()
        if want != kept:
            raise AssertionError(f"chain index memory: {what} → {kept!r}, not {want!r}")
    return kept


def _stored_before_slot(db: Any, slot: int, max_height: Optional[int] = None) -> int:
    """The highest height (≤ ``max_height``) whose slot is known and below ``slot``, from the
    store (-1 if none): by the slot index — on a chain whose slots rise with its heights (every
    canonical one: a block's slot is after its parent's) the first such row down from ``slot``
    — else by every row."""
    index = db.store["chain_index"]
    floor = -(2**62)  # (an unknown slot sorts below every number)
    if db.store["chain_index_meta"].get("unordered") is None:
        for r in index.scan_index("by_slot", lo=(floor,), hi=(int(slot),), reverse=True):
            if max_height is None or int(r.height) <= int(max_height):
                return int(r.height)
        return -1
    best = -1
    for r in index.scan_index("by_slot", lo=(floor,), hi=(int(slot),)):
        if max_height is None or int(r.height) <= int(max_height):
            best = max(best, int(r.height))
    return best


async def highest_height_before_slot(db: Any, slot: int) -> int:
    """The highest block height whose slot is < ``slot`` (-1 if none)."""
    await sync(db)
    recent = await _kept(db)
    if recent is not None:
        answered, height = recent.before_slot(int(slot))
        if answered:
            return int(
                await _checked(
                    db, height, f"before slot {slot}", lambda: _stored_before_slot(db, slot)
                )
            )
    return _stored_before_slot(db, slot)


async def slashed_before(db: Any, address: str, before_height: int) -> bool:
    """True if a canonical block below ``before_height`` carries a verified slashing proof
    against ``address``."""
    await sync(db, int(before_height) - 1)
    rows = db.store["chain_index_offenders"].scan_index("by_offender", address.lower(), limit=1)
    return bool(rows) and int(rows[0].height) < int(before_height)


async def offenders_before(db: Any, before_height: int) -> List[str]:
    """Every address a canonical block below ``before_height`` convicts (lower-cased, sorted)."""
    await sync(db, int(before_height) - 1)
    rows = db.store["chain_index_offenders"].scan(lo=(-(2**62),), hi=(int(before_height),))
    return sorted({r.offender for r in rows})


# ── Casper FFG (validator/ffg.py) ────────────────────────────────────────────────────────


async def block_hash_at(db: Any, height: int) -> Optional[str]:
    await sync(db, height)

    def stored() -> Optional[str]:
        row = db.store["chain_index"].get(int(height))
        return row.block_hash if row is not None else None

    recent = await _kept(db)
    if recent is not None:
        answered, found = recent.hash_at(int(height))
        if answered:
            return await _checked(db, found, f"hash at {height}", stored)  # type: ignore[no-any-return]
    return stored()


async def checkpoint(db: Any, epoch: int, slots_per_epoch: int) -> Optional[Tuple[int, str]]:
    """(height, hash) of epoch ``epoch``'s checkpoint on the canonical chain: the last block
    before the epoch's first slot — known by the time anyone votes in the epoch. Genesis for
    epoch 0 (and for any epoch before the first block). None while the chain is empty."""
    height = 0
    if epoch > 0:
        height = max(0, await highest_height_before_slot(db, int(epoch) * int(slots_per_epoch)))
    root = await block_hash_at(db, height)
    return (height, root) if root else None


async def ffg_votes(
    db: Any, from_target_epoch: int, up_to_height: Optional[int] = None
) -> List[Tuple[int, str, int, str, int, str]]:
    """Canonical FFG votes with target epoch ≥ ``from_target_epoch`` (carried at or below
    ``up_to_height``, default the tip), in chain order: (height, validator, source epoch,
    source root, target epoch, target root)."""
    await sync(db, up_to_height)
    return [
        (int(r.height), r.validator, r.source_epoch, r.source_root, r.target_epoch, r.target_root)
        for r in _ffg_rows(db, from_target_epoch, up_to_height)
    ]


def _ffg_rows(db: Any, from_target_epoch: int, up_to_height: Optional[int]) -> List[Any]:
    """The FFG rows with target epoch ≥ ``from_target_epoch`` carried at or below
    ``up_to_height``, in chain order (height, then the order the block carries them)."""
    rows = db.store["chain_index_ffg"].scan_index(
        "by_target", lo=(int(from_target_epoch),), hi=(_TOP,)
    )
    if up_to_height is not None:
        rows = [r for r in rows if int(r.height) <= int(up_to_height)]
    return sorted(rows, key=lambda r: (int(r.height), int(r.seq)))


async def height_before_slot_at_or_below(db: Any, slot: int, max_height: int) -> int:
    """The highest canonical height ≤ ``max_height`` whose slot is < ``slot`` (-1 if none)."""
    await sync(db, max_height)
    recent = await _kept(db)
    if recent is not None:
        answered, height = recent.before_slot(int(slot), int(max_height))
        if answered:
            return int(
                await _checked(
                    db,
                    height,
                    f"before slot {slot} at or below {max_height}",
                    lambda: _stored_before_slot(db, slot, max_height),
                )
            )
    return _stored_before_slot(db, slot, max_height)


async def voted_targets(
    db: Any, from_target_epoch: int, up_to_height: Optional[int] = None
) -> Dict[Tuple[str, int], Tuple[int, str, int, str]]:
    """{(validator, target epoch): its first canonical FFG vote} for targets ≥
    ``from_target_epoch`` carried at or below ``up_to_height`` (default: the tip)."""
    await sync(db, up_to_height)
    out: Dict[Tuple[str, int], Tuple[int, str, int, str]] = {}
    for r in _ffg_rows(db, from_target_epoch, up_to_height):
        out.setdefault(
            (r.validator, int(r.target_epoch)),
            (int(r.source_epoch), r.source_root, int(r.target_epoch), r.target_root),
        )
    return out


async def validator_public_key(db: Any, address: str, before_height: int) -> Optional[bytes]:
    """The public key of ``address`` as the canonical chain records it below ``before_height``:
    the genesis validator set, or an executed STAKE_DEPOSIT by the address (the
    ``validator_deposits`` log block application writes) — only a key that derives to the
    address counts (a deposit does not otherwise prove the key is the sender's). The same
    answer on every node holding the same chain."""
    from .crypto.pq.dilithium import PQPublicKey

    def owns(key_hex: Any) -> Optional[bytes]:
        try:
            raw = bytes.fromhex(str(key_hex))
            return raw if PQPublicKey.from_bytes(raw).to_address() == address else None
        except Exception:
            return None

    try:
        for v in await db.get_genesis_validators():
            if v.get("address") == address:
                key = owns(v.get("public_key"))
                if key:
                    return key
    except Exception:
        pass
    try:
        deposits = db.store["validator_deposits"].scan_index(
            "by_address", str(address).lower(), lo=(-(2**62),), hi=(int(before_height),)
        )
        rows = [(r.public_key,) for r in deposits if r.address == address]
    except Exception:
        return None  # no deposit log (a database without validators)
    for (key_hex,) in rows:
        key = owns(key_hex)
        if key:
            return key
    return None


async def slot_at(db: Any, height: int) -> Optional[int]:
    """The slot of the canonical block at ``height`` (None if unknown)."""
    await sync(db, height)

    def stored() -> Optional[int]:
        row = db.store["chain_index"].get(int(height))
        return int(row.slot) if row is not None and row.slot is not None else None

    recent = await _kept(db)
    if recent is not None:
        answered, found = recent.slot_at(int(height))
        if answered:
            return await _checked(db, found, f"slot at {height}", stored)  # type: ignore[no-any-return]
    return stored()
