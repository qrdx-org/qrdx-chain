"""
Incremental commitment to the in-memory exchange state (chain-spec feature
``incremental_state_root``; the database domains' counterpart is qrdx/state_commitment.py).

The exchange root used to serialize every pool, order, account, allowance and nonce on every
block. Under the feature, each keyed collection is a ``CommittedDict`` or ``CommittedSet``: it
keeps a 32-byte digest per entry and an LtHash accumulator (qrdx/crypto/lthash.py) of all of
them, and re-digests only the entries that may have changed since the last commitment.

What "may have changed" means is deliberately conservative, so that a mutation can make the
commitment slower but never wrong:

* writing, deleting or popping a key marks it;
* for collections of MUTABLE values (an account, a pool position, a proposal), handing a value
  out by any route — ``d[k]``, ``get``, ``setdefault``, iterating ``values()``/``items()`` —
  marks it, because the caller may change it in place.

Insertion order is not part of the state: the commitment is order-free, every consensus reader
iterates sorted or order-independently, and an undo scope that deletes and restores an entry
may move it (qrdx/exchange/undo.py). Keep it that way.

Read-only code that must not mark everything (the per-block liquidation scan, the invariant
sums) uses ``peek``, ``peek_values`` and ``peek_items``, which return the same objects without
marking them. Those are the only way to read a value unmarked, so a missed conversion costs
time, not correctness. ``verify`` recomputes a collection from scratch; with
``QRDX_VERIFY_STATE_COMMITMENTS=1`` every exchange root is checked against it (the test suite
runs that way).

**Proofs** (docs/STATE_PROOFS.md). Where the chain spec schedules ``provable_state``, each
collection also keeps a sparse Merkle tree of its entries (qrdx/crypto/smt.py, immutable nodes),
updated in ``commitment`` from exactly the entries whose digest changed — so it is a function of
the entries, travels with every copy and undo of the collection, and any entry can be proven.
An entry's key is ``key_of(TREE_KEY | canonical(key))``, its payload ``canonical([key,
encoded])`` (the bytes its digest hashes).
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from typing import Any, Callable, Dict, Iterable, Optional, Set, Tuple

from ..crypto import lthash, smt
from .undo import (
    active as _undo_active,
    restore_into as _undo_restore_into,
)

Encoder = Callable[[Any, Any], Any]  # (key, value) → a JSON-serializable canonical form


def verifying() -> bool:
    """Check every incremental exchange root against a from-scratch recomputation."""
    return os.environ.get("QRDX_VERIFY_STATE_COMMITMENTS", "").lower() in ("1", "true", "yes")


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def _digest(encoded: Any) -> bytes:
    return _raw_digest(canonical_bytes(encoded))


def _raw_digest(raw: bytes) -> bytes:
    return hashlib.blake2b(raw, digest_size=32, person=b"qrdx-exch-v1").digest()


TREE_KEY = b"\x20"  # an exchange entry's tree key: key_of(TREE_KEY | canonical(key))
_TREES: Optional[bool] = None


def trees_on() -> bool:
    """Do collections keep proof trees on this network (``provable_state`` scheduled)?"""
    global _TREES
    if _TREES is None:
        from ..state_proofs import scheduled

        _TREES = scheduled()
    return _TREES


def reset_trees_flag() -> None:
    """Re-read the chain spec (tests that switch networks)."""
    global _TREES
    _TREES = None


def tree_key(key: Any) -> bytes:
    return smt.key_of(TREE_KEY + canonical_bytes(key))


def _vector(tag: str, digest: bytes) -> int:
    return lthash.entry(b"qrdx/exchange/" + tag.encode(), digest)


def _apply(acc: bytes, removed: "lthash.Accumulator", added: "lthash.Accumulator") -> bytes:
    """acc − Σ removed + Σ added, each sum reduced first (one mix for any number of changes)."""
    if removed.count == 0 and added.count == 0:
        return acc
    return lthash.mix(
        acc,
        int.from_bytes(removed.digest(), "little") if removed.count else None,
        int.from_bytes(added.digest(), "little") if added.count else None,
    )


class CommitmentMismatch(AssertionError):
    """An incremental commitment disagreed with its from-scratch recomputation: some code
    changed an entry without marking it (only raised when verifying)."""


class CommittedDict(dict):
    """A dict committed entry by entry (see the module docstring).

    ``encode(key, value)`` gives an entry's canonical form; ``mutable`` says whether values are
    changed in place (then handing one out marks it)."""

    def __init__(
        self,
        tag: str,
        encode: Encoder,
        data: Any = (),
        *,
        mutable: bool = True,
    ) -> None:
        super().__init__(data)
        self._tag = tag
        self._encode = encode
        self._mutable = mutable
        self._acc = lthash.ZERO
        self._digests: Dict[Any, bytes] = {}
        self._dirty: Set[Any] = set(dict.keys(self))
        self._changes: Optional[Set[Any]] = None  # see track_changes
        self._tree: Optional[smt.MNode] = None  # the entries' proof tree (see the module doc)
        self._tree_on = False

    # ── changes, for derived indexes (the liquidation index) ─────────────

    def track_changes(self) -> None:
        """Start keeping every key marked from now on for ``take_changes``."""
        if self._changes is None:
            self._changes = set()

    def take_changes(self) -> Set[Any]:
        """Every key marked since the last call (since ``track_changes`` the first time). Each
        mark is kept as it happens, so a derived index syncing many times a block processes
        each change once (it used to get every key marked since the last commitment, each
        call)."""
        if self._changes is None:
            return set(self._dirty)
        out, self._changes = self._changes, set()
        return out

    # ── undo (qrdx/exchange/undo.py) ──────────────────────────────────────

    def _keep(self, key: Any) -> None:
        """Inside an undo scope: record this entry as it is now, the first time the scope sees
        it — before a write or delete, or before handing a mutable value out."""
        scope = _undo_active()
        if scope is None or not scope.first(self, key):
            return
        if dict.__contains__(self, key):
            original = dict.__getitem__(self, key)
            # A mutable value is restored INTO the original object, so whoever holds it (an
            # outer operation, a caller) sees it as it was — not a stale object beside a copy.
            saved = copy.deepcopy(original) if self._mutable else original

            def restore() -> None:
                value = _undo_restore_into(original, saved) if self._mutable else saved
                dict.__setitem__(self, key, value)
                self._mark(key)

        else:

            def restore() -> None:
                if dict.__contains__(self, key):
                    dict.__delitem__(self, key)
                self._mark(key)

        scope.record(self, key, restore)

    # ── marking writes ───────────────────────────────────────────────────

    def _mark(self, key: Any) -> None:
        self._dirty.add(key)
        if self._changes is not None:
            self._changes.add(key)

    def _mark_all(self, keys: Iterable[Any]) -> None:
        keys = list(keys)
        self._dirty.update(keys)
        if self._changes is not None:
            self._changes.update(keys)

    def __setitem__(self, key: Any, value: Any) -> None:
        self._keep(key)
        dict.__setitem__(self, key, value)
        self._mark(key)

    def __delitem__(self, key: Any) -> None:
        self._keep(key)
        dict.__delitem__(self, key)
        self._mark(key)

    def pop(self, key: Any, *default: Any) -> Any:
        if dict.__contains__(self, key):
            self._keep(key)
            self._mark(key)
        return dict.pop(self, key, *default)

    def popitem(self) -> Tuple[Any, Any]:
        if dict.__len__(self):
            self._keep(next(reversed(dict.keys(self))))
        key, value = dict.popitem(self)
        self._mark(key)
        return key, value

    def setdefault(self, key: Any, default: Any = None) -> Any:
        self._keep(key)
        self._mark(key)
        return dict.setdefault(self, key, default)

    def update(self, *args: Any, **kwargs: Any) -> None:
        other = dict(*args, **kwargs)
        for key in other:
            self._keep(key)
        dict.update(self, other)
        self._mark_all(other)

    def __ior__(self, other: Any) -> "CommittedDict":  # type: ignore[misc]
        self.update(other)
        return self

    def clear(self) -> None:
        for key in list(dict.keys(self)):
            self._keep(key)
        self._mark_all(dict.keys(self))
        dict.clear(self)

    # ── reads (marking when values are mutable) ──────────────────────────

    def __getitem__(self, key: Any) -> Any:
        if self._mutable and dict.__contains__(self, key):
            self._keep(key)
        value = dict.__getitem__(self, key)
        if self._mutable:
            self._mark(key)
        return value

    def get(self, key: Any, default: Any = None) -> Any:
        if self._mutable and dict.__contains__(self, key):
            self._keep(key)
            self._mark(key)
        return dict.get(self, key, default)

    def values(self):  # type: ignore[override]
        if self._mutable:
            for key in list(dict.keys(self)):
                self._keep(key)
            self._mark_all(dict.keys(self))
        return dict.values(self)

    def items(self):  # type: ignore[override]
        if self._mutable:
            for key in list(dict.keys(self)):
                self._keep(key)
            self._mark_all(dict.keys(self))
        return dict.items(self)

    # ── unmarked reads, for code that only reads ─────────────────────────

    def peek(self, key: Any, default: Any = None) -> Any:
        return dict.get(self, key, default)

    def peek_values(self) -> Iterable[Any]:
        return dict.values(self)

    def peek_items(self) -> Iterable[Tuple[Any, Any]]:
        return dict.items(self)

    # ── copying (snapshots deep-copy the exchange state every block) ─────

    def copy(self) -> "CommittedDict":
        new = type(self).__new__(type(self))
        dict.update(new, dict.items(self))
        new.__dict__.update(self.__dict__)
        new._digests = dict(self._digests)
        new._dirty = set(self._dirty)
        new._changes = None if self._changes is None else set(self._changes)
        return new

    def __copy__(self) -> "CommittedDict":
        return self.copy()

    def __deepcopy__(self, memo: Dict[int, Any]) -> "CommittedDict":
        new = type(self).__new__(type(self))
        memo[id(self)] = new
        for k, v in dict.items(self):
            dict.__setitem__(new, copy.deepcopy(k, memo), copy.deepcopy(v, memo))
        new.__dict__.update(self.__dict__)
        new._digests = dict(self._digests)  # keys and digests are immutable
        new._dirty = set(self._dirty)
        new._changes = None if self._changes is None else set(self._changes)
        # The marker tying a derived index to this dict (it is copied with it).
        if "_index_token" in self.__dict__:
            new.__dict__["_index_token"] = copy.deepcopy(self.__dict__["_index_token"], memo)
        return new

    def __reduce__(self):  # pickling: rebuild from the entries (every entry dirty)
        return (
            _rebuild_dict,
            (self._tag, self._encode, dict(dict.items(self)), self._mutable),
        )

    # ── the commitment ───────────────────────────────────────────────────

    def _entry_digest(self, key: Any, value: Any) -> bytes:
        return _digest([key, self._encode(key, value)])

    def _entry_raw(self, key: Any, value: Any) -> bytes:
        """The entry's canonical bytes: what its digest hashes and its proof leaf holds."""
        return canonical_bytes([key, self._encode(key, value)])

    def commitment(self) -> bytes:
        """The accumulator over every entry, after re-digesting the marked ones (and the proof
        tree, from the same changes)."""
        trees = trees_on()
        rebuilt = False
        if trees and not self.__dict__.get("_tree_on", False):  # (a copy from before trees)
            self._tree = smt.m_build(
                sorted((tree_key(k), self._entry_raw(k, v)) for k, v in dict.items(self))
            )
            self._tree_on = rebuilt = True
        elif not trees:
            self._tree, self._tree_on = None, False
        if self._dirty:
            removed, added = lthash.Accumulator(), lthash.Accumulator()
            tree_changes = []
            for key in self._dirty:
                old = self._digests.pop(key, None)
                new = raw = None
                if dict.__contains__(self, key):
                    raw = self._entry_raw(key, dict.__getitem__(self, key))
                    new = _raw_digest(raw)
                    self._digests[key] = new
                if old != new:
                    if old is not None:
                        removed.add(_vector(self._tag, old))
                    if new is not None:
                        added.add(_vector(self._tag, new))
                    if trees:
                        tree_changes.append((tree_key(key), raw))
            self._acc = _apply(self._acc, removed, added)
            self._dirty.clear()
            if tree_changes and not rebuilt:
                self._tree = smt.m_update(self._tree, sorted(tree_changes))
        return self._acc

    @property
    def tree(self) -> Optional[smt.MNode]:
        """The entries' proof tree, up to date (``commitment`` brings it there)."""
        self.commitment()
        return self.__dict__.get("_tree")

    def full_commitment(self) -> bytes:
        acc = lthash.Accumulator()
        for key, value in dict.items(self):
            acc.add(_vector(self._tag, self._entry_digest(key, value)))
        return acc.digest()

    def verify(self) -> None:
        got, want = self.commitment(), self.full_commitment()
        if got != want:
            stale = [
                k for k, v in dict.items(self) if self._digests.get(k) != self._entry_digest(k, v)
            ]
            raise CommitmentMismatch(
                f"{self._tag}: incremental commitment is stale for {len(stale)} entr"
                f"{'y' if len(stale) == 1 else 'ies'} (e.g. {stale[:3]!r})"
            )
        if trees_on():
            full = smt.m_build(
                sorted((tree_key(k), self._entry_raw(k, v)) for k, v in dict.items(self))
            )
            if smt.m_root(self.__dict__.get("_tree")) != smt.m_root(full):
                raise CommitmentMismatch(f"{self._tag}: the proof tree disagrees with the entries")

    @property
    def dirty_count(self) -> int:
        return len(self._dirty)


def _rebuild_dict(tag: str, encode: Encoder, data: dict, mutable: bool) -> CommittedDict:
    return CommittedDict(tag, encode, data, mutable=mutable)


class CommittedSet(set):
    """A set of immutable elements committed element by element."""

    def __init__(self, tag: str, data: Iterable[Any] = ()) -> None:
        super().__init__(data)
        self._tag = tag
        self._acc = lthash.ZERO
        self._members: Set[Any] = set()  # what the accumulator holds
        self._dirty: Set[Any] = set(set.__iter__(self))
        self._tree: Optional[smt.MNode] = None  # the members' proof tree
        self._tree_on = False

    def _keep(self, item: Any) -> None:
        """Inside an undo scope: record whether ``item`` is a member now (qrdx/exchange/undo.py)."""
        scope = _undo_active()
        if scope is None or not scope.first(self, item):
            return
        was = set.__contains__(self, item)

        def restore() -> None:
            if was:
                set.add(self, item)
            else:
                set.discard(self, item)
            self._dirty.add(item)

        scope.record(self, item, restore)

    def add(self, item: Any) -> None:
        self._keep(item)
        set.add(self, item)
        self._dirty.add(item)

    def discard(self, item: Any) -> None:
        self._keep(item)
        set.discard(self, item)
        self._dirty.add(item)

    def remove(self, item: Any) -> None:
        self._keep(item)
        set.remove(self, item)
        self._dirty.add(item)

    def pop(self) -> Any:
        if set.__len__(self):
            self._keep(next(iter(set.__iter__(self))))
        item = set.pop(self)
        self._dirty.add(item)
        return item

    def clear(self) -> None:
        for item in list(set.__iter__(self)):
            self._keep(item)
        self._dirty.update(set.__iter__(self))
        set.clear(self)

    def update(self, *others: Iterable[Any]) -> None:
        for o in others:
            o = list(o)
            for item in o:
                self._keep(item)
            set.update(self, o)
            self._dirty.update(o)

    def difference_update(self, *others: Iterable[Any]) -> None:
        for o in others:
            o = list(o)
            for item in o:
                self._keep(item)
            set.difference_update(self, o)
            self._dirty.update(o)

    def intersection_update(self, *others: Iterable[Any]) -> None:
        before = set(set.__iter__(self))
        keep = set(before)
        keep.intersection_update(*others)
        for item in before - keep:
            self._keep(item)
        set.intersection_update(self, *others)
        self._dirty.update(before - set(set.__iter__(self)))

    def symmetric_difference_update(self, other: Iterable[Any]) -> None:
        other = list(other)
        for item in other:
            self._keep(item)
        set.symmetric_difference_update(self, other)
        self._dirty.update(other)

    def __ior__(self, other: Any) -> "CommittedSet":  # type: ignore[misc]
        self.update(other)
        return self

    def __isub__(self, other: Any) -> "CommittedSet":  # type: ignore[misc]
        self.difference_update(other)
        return self

    def __iand__(self, other: Any) -> "CommittedSet":  # type: ignore[misc]
        self.intersection_update(other)
        return self

    def __ixor__(self, other: Any) -> "CommittedSet":  # type: ignore[misc]
        self.symmetric_difference_update(other)
        return self

    def copy(self) -> "CommittedSet":
        new = type(self).__new__(type(self))
        set.update(new, set.__iter__(self))
        new.__dict__.update(self.__dict__)
        new._members = set(self._members)
        new._dirty = set(self._dirty)
        return new

    def __copy__(self) -> "CommittedSet":
        return self.copy()

    def __deepcopy__(self, memo: Dict[int, Any]) -> "CommittedSet":
        new = self.copy()  # elements are immutable
        memo[id(self)] = new
        return new

    def __reduce__(self):
        return (_rebuild_set, (self._tag, list(set.__iter__(self))))

    def _entry_digest(self, item: Any) -> bytes:
        return _digest(item)

    def commitment(self) -> bytes:
        trees = trees_on()
        rebuilt = False
        if trees and not self.__dict__.get("_tree_on", False):
            self._tree = smt.m_build(
                sorted((tree_key(i), canonical_bytes(i)) for i in set.__iter__(self))
            )
            self._tree_on = rebuilt = True
        elif not trees:
            self._tree, self._tree_on = None, False
        if self._dirty:
            removed, added = lthash.Accumulator(), lthash.Accumulator()
            tree_changes = []
            for item in self._dirty:
                had, has = item in self._members, set.__contains__(self, item)
                if had == has:
                    continue
                vec = _vector(self._tag, self._entry_digest(item))
                if has:
                    added.add(vec)
                    self._members.add(item)
                else:
                    removed.add(vec)
                    self._members.discard(item)
                if trees:
                    tree_changes.append((tree_key(item), canonical_bytes(item) if has else None))
            self._acc = _apply(self._acc, removed, added)
            self._dirty.clear()
            if tree_changes and not rebuilt:
                self._tree = smt.m_update(self._tree, sorted(tree_changes))
        return self._acc

    @property
    def tree(self) -> Optional[smt.MNode]:
        self.commitment()
        return self.__dict__.get("_tree")

    def full_commitment(self) -> bytes:
        acc = lthash.Accumulator()
        for item in set.__iter__(self):
            acc.add(_vector(self._tag, self._entry_digest(item)))
        return acc.digest()

    def verify(self) -> None:
        if self.commitment() != self.full_commitment():
            raise CommitmentMismatch(f"{self._tag}: incremental set commitment is stale")
        if trees_on():
            full = smt.m_build(
                sorted((tree_key(i), canonical_bytes(i)) for i in set.__iter__(self))
            )
            if smt.m_root(self.__dict__.get("_tree")) != smt.m_root(full):
                raise CommitmentMismatch(f"{self._tag}: the proof tree disagrees with the members")


def _rebuild_set(tag: str, items: list) -> CommittedSet:
    return CommittedSet(tag, items)


def as_committed_dict(
    value: Any, tag: str, encode: Encoder, *, mutable: bool = True
) -> CommittedDict:
    """``value`` if it already is a committed dict for ``tag``, else one built from it (every
    entry digested on the next commitment)."""
    if isinstance(value, CommittedDict) and value._tag == tag:
        return value
    return CommittedDict(tag, encode, value or {}, mutable=mutable)


def as_committed_set(value: Any, tag: str) -> CommittedSet:
    if isinstance(value, CommittedSet) and value._tag == tag:
        return value
    return CommittedSet(tag, value or ())


class Section:
    """Builds one exchange-root section: a tag, then length-prefixed parts."""

    def __init__(self, tag: str) -> None:
        self._h = hashlib.blake2b(digest_size=32, person=b"qrdx-exch-sec")
        self._part(tag.encode())

    def _part(self, data: bytes) -> None:
        self._h.update(len(data).to_bytes(8, "little"))
        self._h.update(data)

    def value(self, obj: Any) -> "Section":
        self._part(canonical_bytes(obj))
        return self

    def raw(self, data: bytes) -> "Section":
        self._part(data)
        return self

    def digest(self) -> bytes:
        return self._h.digest()


class committed:
    """A class attribute holding a committed collection: whatever is assigned to it (a plain
    dict or set included) is stored as the committed kind, so no reassignment can silently
    replace the tracked container with an untracked one.

        class Clearinghouse:
            accounts = committed("ch.accounts", encode_account)              # dict, mutable
            vault_shares = committed("ch.vault_shares", encode_value, mutable=False)
            frozen = committed("tokens.frozen", kind="set")
    """

    def __init__(
        self,
        tag: str,
        encode: Optional[Encoder] = None,
        *,
        mutable: bool = True,
        kind: str = "dict",
    ) -> None:
        self.tag, self.encode, self.mutable, self.kind = tag, encode, mutable, kind
        self.name = ""

    def __set_name__(self, owner: type, name: str) -> None:
        self.name = name

    def __get__(self, obj: Any, objtype: Any = None) -> Any:
        if obj is None:
            return self
        try:
            return obj.__dict__[self.name]
        except KeyError:
            raise AttributeError(self.name) from None

    def __set__(self, obj: Any, value: Any) -> None:
        if self.kind == "set":
            obj.__dict__[self.name] = as_committed_set(value, self.tag)
        else:
            assert self.encode is not None, f"{self.tag}: a committed dict needs an encoder"
            obj.__dict__[self.name] = as_committed_dict(
                value, self.tag, self.encode, mutable=self.mutable
            )


def encode_value(_key: Any, value: Any) -> Any:
    """The entry encoding of a collection of plain values (nonces, shares, allowances)."""
    return str(value)


def tracked(value: Any) -> CommittedDict:
    """``value`` as the committed dict it must be (a dataclass field annotated as a plain dict
    and wrapped in ``__post_init__``). Raises if it is not — an untracked container would
    commit stale state silently."""
    if not isinstance(value, CommittedDict):
        raise TypeError(f"expected a committed dict, got {type(value).__name__}")
    return value
