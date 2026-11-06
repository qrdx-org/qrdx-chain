"""
All or nothing for exchange operations: undo scopes.

An operation that does several things — a batch of orders, an order that must fill whole, a
modify that cancels one order and places another, a multi-hop swap — must change nothing if
any part of it fails. Copying the state first costs the state, not the operation: a spot order
used to deep-copy its whole book (every resting order) before matching, and anything wider than
one book could not be made atomic at all.

Inside an ``atomic()`` scope each piece of exchange state records what it was the first time
the scope touches it; a failure puts back exactly those pieces, newest first. What is covered:

* every committed collection (qrdx/exchange/commitment.py): a ``CommittedDict`` entry before it
  is written, deleted or — for collections of mutable values — handed out; a ``CommittedSet``
  member before it is added or removed;
* each order book's own state (qrdx/exchange/orderbook.py): the price levels it touches, its
  order and stop-order indexes, its counters, its scalars and its display history;
* the clearinghouse's scalars and every market's own fields (qrdx/exchange/clearinghouse.py);
* whatever an operation registers with ``keep``.

Scopes nest: an inner scope that fails undoes its own changes; one that succeeds hands what it
recorded to the outer scope, which can still undo everything. Not consensus state itself —
nothing here is committed or persisted — only a record of how to go back.
"""

from __future__ import annotations

import contextlib
import contextvars
import copy
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

_ACTIVE: "contextvars.ContextVar[Optional[Scope]]" = contextvars.ContextVar(
    "qrdx_exchange_undo", default=None
)


class Scope:
    """What one atomic operation changed, as restore actions in the order they were recorded."""

    def __init__(self, parent: Optional["Scope"]) -> None:
        self.parent = parent
        self.entries: List[Tuple[Optional[Tuple[int, Any]], Callable[[], None]]] = []
        # Restores that must run after every other one: a container's key order (a key deleted
        # and put back would otherwise land at the end — and some of the exchange iterates in
        # insertion order).
        self.finals: List[Tuple[Tuple[int, Any], Callable[[], None]]] = []
        self.seen: Set[Tuple[int, Any]] = set()
        # Keeps every captured container alive for the scope (their ids key ``seen``), and is
        # the deepcopy memo: one object reached through two containers (an order in its price
        # level and in the book's order index) is copied once, as it was when first captured.
        self.memo: Dict[int, Any] = {}
        self._alive: List[Any] = []

    def first(self, container: Any, key: Any) -> bool:
        """True the first time this scope sees ``(container, key)`` — record its pre-image."""
        token = (id(container), key)
        if token in self.seen:
            return False
        self.seen.add(token)
        self._alive.append(container)
        return True

    def record(self, container: Any, key: Any, restore: Callable[[], None]) -> None:
        self.entries.append(((id(container), key), restore))

    def record_final(self, container: Any, key: Any, restore: Callable[[], None]) -> None:
        self.finals.append(((id(container), key), restore))

    def record_step(self, restore: Callable[[], None]) -> None:
        """An undo step that is not a pre-image: replayed in order with everything else."""
        self.entries.append((None, restore))

    def copy(self, value: Any) -> Any:
        return copy.deepcopy(value, self.memo)

    def rollback(self) -> None:
        for _token, restore in reversed(self.entries):
            restore()
        for _token, restore in self.finals:
            restore()
        self.entries.clear()
        self.finals.clear()

    def hand_to_parent(self) -> None:
        """This scope succeeded: the outer scope must still be able to undo it. A pre-image the
        outer scope already holds is older than ours, so ours is dropped."""
        parent = self.parent
        if parent is None:
            return
        for token, restore in self.entries:
            if token is not None:
                if token in parent.seen:
                    continue
                parent.seen.add(token)
            parent.entries.append((token, restore))
        for final_token, restore in self.finals:
            if final_token in parent.seen:
                continue
            parent.seen.add(final_token)
            parent.finals.append((final_token, restore))
        parent._alive.extend(self._alive)
        for key, value in self.memo.items():  # the outer scope's older copies win
            parent.memo.setdefault(key, value)


def active() -> Optional[Scope]:
    """The innermost open scope, if any."""
    return _ACTIVE.get()


@contextlib.contextmanager
def atomic() -> Iterator[Scope]:
    """Run the body all or nothing: if it raises, every exchange change it made is undone and
    the exception propagates."""
    scope = Scope(_ACTIVE.get())
    token = _ACTIVE.set(scope)
    try:
        yield scope
    except BaseException:
        _ACTIVE.reset(token)
        scope.rollback()
        raise
    else:
        _ACTIVE.reset(token)
        scope.hand_to_parent()


def keep(obj: Any, attrs: Tuple[str, ...], tag: str = "attrs", *, shallow: bool = False) -> None:
    """Record ``obj``'s attributes ``attrs`` (deep-copied; ``shallow``: one level, for
    containers of immutable values) the first time the open scope sees them under ``tag``; a
    rollback sets them back. No-op outside a scope."""
    scope = _ACTIVE.get()
    if scope is None or not scope.first(obj, (tag, attrs)):
        return
    take = copy.copy if shallow else scope.copy
    saved = {a: take(getattr(obj, a)) for a in attrs if hasattr(obj, a)}
    missing = [a for a in attrs if not hasattr(obj, a)]

    def restore() -> None:
        for a, v in saved.items():
            setattr(obj, a, v)
        for a in missing:
            if hasattr(obj, a):
                delattr(obj, a)

    scope.record(obj, (tag, attrs), restore)


def keep_entry(container: Dict[Any, Any], key: Any, *, mutable: bool = True) -> None:
    """Record a plain dict's entry ``key`` (deep-copied when ``mutable``) the first time the open
    scope sees it; a rollback puts it back (or removes it if it was absent)."""
    scope = _ACTIVE.get()
    if scope is None or not scope.first(container, ("entry", key)):
        return
    if key in container:
        old = container[key]
        if mutable:
            old = scope.copy(old)

        def restore() -> None:
            container[key] = old

    else:

        def restore() -> None:
            container.pop(key, None)

    scope.record(container, ("entry", key), restore)


def keep_order(container: Dict[Any, Any]) -> None:
    """Before the first deletion from a dict in the open scope: record its key order, put back
    after every other restore (so keys deleted and restored are where they were)."""
    scope = _ACTIVE.get()
    if scope is None or not scope.first(container, "__order__"):
        return
    saved = list(dict.keys(container))
    is_committed = hasattr(container, "_mark")

    def restore() -> None:
        present = dict(dict.items(container))
        dict.clear(container)
        for key in saved:
            if key in present:
                dict.__setitem__(container, key, present.pop(key))
        for key, value in present.items():  # (none, once every entry is restored)
            dict.__setitem__(container, key, value)
        if is_committed:
            container._mark_all(saved)  # type: ignore[attr-defined]

    scope.record_final(container, "__order__", restore)


def restore_into(original: Any, saved: Any) -> Any:
    """Put ``saved`` (a deep copy of ``original`` taken earlier) back into ``original`` itself,
    so that whoever holds ``original`` sees it as it was; returns the object to store. Values
    that cannot be restored in place (immutable ones) are replaced."""
    if original is saved:
        return original
    if type(original) is not type(saved):
        return saved
    if isinstance(original, list):
        original[:] = saved
        return original
    if isinstance(original, dict) and not hasattr(original, "_mark"):
        original.clear()
        original.update(saved)
        return original
    if isinstance(original, set) and not hasattr(original, "_dirty"):
        original.clear()
        original.update(saved)
        return original
    if hasattr(original, "__dict__") and not isinstance(original, type):
        original.__dict__.clear()
        original.__dict__.update(saved.__dict__)
        return original
    return saved


def keep_length(log: List[Any]) -> None:
    """An append-only list: a rollback truncates it to the length it had when the open scope
    first saw it."""
    scope = _ACTIVE.get()
    if scope is None or not scope.first(log, "__length__"):
        return
    length = len(log)

    def restore() -> None:
        del log[length:]

    scope.record(log, "__length__", restore)
